"""Outbound network connection polling.

Uses psutil.net_connections(). Visibility depends on the install type:
- HA OS / Supervised: the Core container shares the host network namespace,
  so you see host-wide sockets, but PID → process mapping is limited to the
  Core container. Add-on traffic shows up without an owner.
- Container: only what the container's network namespace sees.
- Short-lived connections between polls are missed. The HTTP tracer covers
  most of those for aiohttp traffic; for everything else pair this with a
  companion add-on (conntrack) or DNS logs from Pi-hole/AdGuard.

Each socket is labelled with the hostname and integration the HTTP tracer saw
for its peer IP, falling back to reverse DNS.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import ipaddress
import logging
import socket
from typing import TYPE_CHECKING, Any

import psutil

from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import DOMAIN, NETWORK_SCAN_INTERVAL, SIGNAL_UPDATED

if TYPE_CHECKING:
    from . import SecurityConfigEntry
    from .http_tracer import HttpTracer

_LOGGER = logging.getLogger(__name__)

# Destinations first seen during this window after monitoring started are the
# baseline; only later ones are flagged as new.
LEARNING_PERIOD = timedelta(hours=1)
HOST_RETENTION = timedelta(days=7)


@dataclass
class NetworkSnapshot:
    scanned_at: str
    connections: list[dict[str, Any]] = field(default_factory=list)
    listening: list[dict[str, Any]] = field(default_factory=list)
    destinations: list[dict[str, Any]] = field(default_factory=list)
    # Rolling 24 h view merged from HTTP tracing and the socket scan
    destinations_24h: list[dict[str, Any]] = field(default_factory=list)
    new_destinations_24h: int = 0
    monitoring_since: str | None = None
    learning_until: str | None = None

    @property
    def outbound_count(self) -> int:
        return len(self.connections)


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _process_name(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _scan(rdns_cache: dict[str, str | None]) -> NetworkSnapshot:
    """Blocking scan; runs in the executor."""
    outbound, listening = [], []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            listening.append(
                {"ip": conn.laddr.ip, "port": conn.laddr.port, "process": _process_name(conn.pid)}
            )
        elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr and _is_external(conn.raddr.ip):
            ip = conn.raddr.ip
            if ip not in rdns_cache:
                try:
                    rdns_cache[ip] = socket.gethostbyaddr(ip)[0]
                except OSError:
                    rdns_cache[ip] = None
            outbound.append(
                {
                    "remote_ip": ip,
                    "remote_port": conn.raddr.port,
                    "hostname": rdns_cache[ip],
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "process": _process_name(conn.pid),
                }
            )
    return NetworkSnapshot(scanned_at=dt_util.utcnow().isoformat(), connections=outbound, listening=listening)


def _parse(value: str | None) -> datetime | None:
    return dt_util.parse_datetime(value) if value else None


class NetworkCoordinator(DataUpdateCoordinator[NetworkSnapshot]):
    """Polls sockets and token usage on a fixed interval."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: SecurityConfigEntry,
        tracer: HttpTracer,
        restored: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}_network",
            update_interval=NETWORK_SCAN_INTERVAL,
        )
        self.tracer = tracer
        self._rdns_cache: dict[str, str | None] = {}
        restored = restored or {}
        self.monitoring_since: datetime = _parse(restored.get("monitoring_since")) or dt_util.utcnow()
        # (remote_ip, remote_port, local_port) -> (host, first seen): each socket counts once
        self._sockets: dict[tuple, tuple[str, datetime]] = {}
        for item in restored.get("sockets", []):
            if (seen := _parse(item.get("seen"))) is not None:
                self._sockets[tuple(item["key"])] = (item["host"], seen)
        # host -> {"first_seen": iso, "last_seen": iso}  (socket-observed hosts)
        self._hosts: dict[str, dict[str, str]] = dict(restored.get("hosts", {}))

    # ------------------------------------------------------------ persistence

    def as_dict(self) -> dict[str, Any]:
        return {
            "monitoring_since": self.monitoring_since.isoformat(),
            "sockets": [
                {"key": list(key), "host": host, "seen": seen.isoformat()}
                for key, (host, seen) in self._sockets.items()
            ],
            "hosts": self._hosts,
        }

    # ------------------------------------------------------------ tracking

    def _is_new(self, first_seen: str | None, day_ago: datetime) -> bool:
        first = _parse(first_seen)
        return first is not None and first > day_ago and first > self.monitoring_since + LEARNING_PERIOD

    def _track(self, snapshot: NetworkSnapshot) -> None:
        """Label sockets and fold the scan into the rolling 24 h view."""
        now = dt_util.utcnow()
        now_iso = now.isoformat()
        day_ago = now - timedelta(hours=24)
        self.tracer.prune()

        for c in snapshot.connections:
            traced = self.tracer.lookup_ip(c["remote_ip"])
            c["traced_host"] = traced["host"] if traced else None
            c["integration"] = traced["integration"] if traced else None
            host = c["traced_host"] or c["hostname"] or c["remote_ip"]
            key = (c["remote_ip"], c["remote_port"], c["local_port"])
            self._sockets.setdefault(key, (host, now))
            entry = self._hosts.setdefault(host, {"first_seen": now_iso, "last_seen": now_iso})
            entry["last_seen"] = now_iso

        self._sockets = {k: v for k, v in self._sockets.items() if v[1] > day_ago}
        cutoff = (now - HOST_RETENTION).isoformat()
        self._hosts = {h: v for h, v in self._hosts.items() if v["last_seen"] > cutoff}

        # Merge: HTTP-traced hosts (requests) + socket-observed hosts (connections)
        merged: dict[str, dict[str, Any]] = {}
        for t in self.tracer.hosts_24h():
            merged[t["host"]] = {
                "host": t["host"],
                "requests": t["requests"],
                "connections": 0,
                "integrations": t["integrations"],
                "first_seen": t["first_seen"],
                "last_seen": t["last_seen"],
            }
        sockets_per_host = Counter(host for host, _ in self._sockets.values())
        integration_per_host: dict[str, str] = {}
        for c in snapshot.connections:
            if c["integration"]:
                integration_per_host[c["traced_host"]] = c["integration"]
        for host, count in sockets_per_host.items():
            seen = self._hosts.get(host, {})
            item = merged.setdefault(
                host,
                {"host": host, "requests": 0, "connections": 0, "integrations": [],
                 "first_seen": seen.get("first_seen"), "last_seen": seen.get("last_seen")},
            )
            item["connections"] = count
            if not item["integrations"] and host in integration_per_host:
                item["integrations"] = [integration_per_host[host]]
            # Earliest first sighting / latest last sighting across both sources
            if seen.get("first_seen") and (item["first_seen"] is None or seen["first_seen"] < item["first_seen"]):
                item["first_seen"] = seen["first_seen"]
            if seen.get("last_seen") and (item["last_seen"] is None or seen["last_seen"] > item["last_seen"]):
                item["last_seen"] = seen["last_seen"]

        destinations = list(merged.values())
        for d in destinations:
            d["new"] = self._is_new(d["first_seen"], day_ago)
            d["activity"] = d["requests"] + d["connections"]
        destinations.sort(key=lambda d: d["activity"], reverse=True)

        snapshot.destinations = [
            {"host": h, "connections": n}
            for h, n in Counter(
                (c["traced_host"] or c["hostname"] or c["remote_ip"]) for c in snapshot.connections
            ).most_common()
        ]
        snapshot.destinations_24h = destinations
        snapshot.new_destinations_24h = sum(1 for d in destinations if d["new"])
        snapshot.monitoring_since = self.monitoring_since.isoformat()
        learning_until = self.monitoring_since + LEARNING_PERIOD
        snapshot.learning_until = learning_until.isoformat() if learning_until > now else None

    async def _async_update_data(self) -> NetworkSnapshot:
        snapshot = await self.hass.async_add_executor_job(_scan, self._rdns_cache)
        self._track(snapshot)
        # Piggy-back token-usage polling on the same timer
        if (data := getattr(self.config_entry, "runtime_data", None)) is not None:
            await data.auth.async_poll_token_usage()
        async_dispatcher_send(self.hass, SIGNAL_UPDATED)
        return snapshot
