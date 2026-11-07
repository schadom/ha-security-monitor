"""Outbound network connection polling.

Uses psutil.net_connections(). Visibility depends on the install type:
- HA OS / Supervised: the Core container shares the host network namespace,
  so you see host-wide sockets, but PID → process mapping is limited to the
  Core container. Add-on traffic shows up without an owner.
- Container: only what the container's network namespace sees.
- Short-lived connections between polls are missed. For full coverage pair
  this with a companion add-on (conntrack) or DNS logs from Pi-hole/AdGuard.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
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

_LOGGER = logging.getLogger(__name__)


@dataclass
class NetworkSnapshot:
    scanned_at: str
    connections: list[dict[str, Any]] = field(default_factory=list)
    listening: list[dict[str, Any]] = field(default_factory=list)
    destinations: list[dict[str, Any]] = field(default_factory=list)

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

    per_dest = Counter((c["hostname"] or c["remote_ip"]) for c in outbound)
    destinations = [{"host": h, "connections": n} for h, n in per_dest.most_common()]
    return NetworkSnapshot(
        scanned_at=dt_util.utcnow().isoformat(),
        connections=outbound,
        listening=listening,
        destinations=destinations,
    )


class NetworkCoordinator(DataUpdateCoordinator[NetworkSnapshot]):
    """Polls sockets and token usage on a fixed interval."""

    def __init__(self, hass: HomeAssistant, entry: SecurityConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}_network",
            update_interval=NETWORK_SCAN_INTERVAL,
        )
        self._rdns_cache: dict[str, str | None] = {}

    async def _async_update_data(self) -> NetworkSnapshot:
        snapshot = await self.hass.async_add_executor_job(_scan, self._rdns_cache)
        # Piggy-back token-usage polling on the same timer
        if (data := getattr(self.config_entry, "runtime_data", None)) is not None:
            await data.auth.async_poll_token_usage()
        async_dispatcher_send(self.hass, SIGNAL_UPDATED)
        return snapshot
