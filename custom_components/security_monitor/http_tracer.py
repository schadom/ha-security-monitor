"""Attribute outbound HTTP(S) traffic to the integration that made it.

aiohttp sends every request (get/post/…, `request()` and websocket connects)
through ClientSession._request. We wrap that method once at class level, so
every session is covered: HA's shared one, per-integration ones and sessions
libraries create themselves. Traffic over other stacks (requests/urllib3 in
executor threads, raw sockets, MQTT) is not seen here; those still show up in
the socket scan, just without an integration.

For each request we record the hostname, the calling integration (found by
walking the call stack) and the peer IP the connection actually went to. The
peer IP lets the socket scan label long-lived connections with the hostname
and integration instead of a cloud provider's reverse DNS name.

Privacy: only hostnames, IPs, integration names and counts are kept, never
URLs, paths, query strings, headers or bodies.

The peer IP is taken where aiohttp opens the TCP connection
(TCPConnector._create_direct_connection); the caller is handed over through a
context variable, since connection setup runs inside the request.

Note: both hooks are private aiohttp API.
"""

from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
import functools
import ipaddress
import logging
import re
import sys
import time
from typing import Any

import aiohttp
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_loaded_integration
from homeassistant.util import dt as dt_util

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

_MARK = "_security_monitor_tracer"
_CURRENT_CALLER: ContextVar[str | None] = ContextVar("security_monitor_caller", default=None)
_COMPONENT_RE = re.compile(r"[/\\](?:homeassistant[/\\]components|custom_components)[/\\]([a-z0-9_]+)[/\\]")
_PACKAGE_RE = re.compile(r"[/\\](?:site|dist)-packages[/\\]([A-Za-z0-9_]+)")
_IGNORED_PACKAGES = {
    "aiohttp", "yarl", "multidict", "async_timeout", "homeassistant", "aiohttp_retry",
    "backoff", "tenacity", "asyncio", "concurrent", "propcache", "sentry_sdk",
}
_MAX_FRAMES = 80
_MAX_HOSTS = 500
_IP_TTL = 24 * 3600


def _caller() -> str | None:
    """Integration domain on the call stack, else "lib:<package>", else None."""
    frame = sys._getframe(2)  # skip _caller and the wrapper
    library = None
    depth = 0
    while frame is not None and depth < _MAX_FRAMES:
        filename = frame.f_code.co_filename
        if (m := _COMPONENT_RE.search(filename)) and m.group(1) != DOMAIN:
            return m.group(1)
        if library is None and (p := _PACKAGE_RE.search(filename)):
            if p.group(1) not in _IGNORED_PACKAGES:
                library = p.group(1)
        frame = frame.f_back
        depth += 1
    return f"lib:{library}" if library else None


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _hour() -> int:
    return int(time.time() // 3600)


class HttpTracer:
    """Collects per-host request stats and a peer-IP → host/integration map."""

    def __init__(self, hass: HomeAssistant, restored: dict[str, Any] | None = None) -> None:
        self.hass = hass
        # host -> {"integrations": {name: count}, "first_seen": iso, "last_seen": iso,
        #          "hourly": {epoch_hour: count}}
        self.hosts: dict[str, dict[str, Any]] = {}
        # peer ip -> {"host": str, "integration": str|None, "ts": epoch seconds}
        self.ip_map: dict[str, dict[str, Any]] = {}
        self._lib_to_domain: dict[str, str] = {}
        self._originals: tuple[Callable[..., Any], Callable[..., Any]] | None = None
        self._wrappers: tuple[Callable[..., Any], Callable[..., Any]] | None = None
        # False after stop(): a wrapper that can't be unhooked becomes a pass-through
        self._active = False
        # Hostnames whose connections went to a LAN/loopback address (e.g. shelly.local)
        self._local_hosts: set[str] = set()
        # Only outbound (internet) traffic matters here; LAN devices are skipped
        self.include_local = False
        if restored:
            self.hosts = {
                h: {**v, "hourly": {int(k): n for k, n in v.get("hourly", {}).items()}}
                for h, v in restored.get("hosts", {}).items()
            }
            self.ip_map = restored.get("ip_map", {})

    # ---------------------------------------------------------------- hooking

    def start(self) -> None:
        if getattr(aiohttp.ClientSession._request, _MARK, False):
            _LOGGER.debug("aiohttp is already traced; not wrapping twice")
            return
        tracer = self
        orig_request = aiohttp.ClientSession._request
        orig_connect = aiohttp.TCPConnector._create_direct_connection
        self._originals = (orig_request, orig_connect)

        @functools.wraps(orig_request)
        async def _traced_request(session: aiohttp.ClientSession, method: str, str_or_url: Any, *args: Any, **kwargs: Any):
            host = caller = None
            try:
                host = URL(str_or_url).host
                if host is None and (base := getattr(session, "_base_url", None)) is not None:
                    host = base.host
                caller = _caller()
            except Exception:  # noqa: BLE001 - tracing must never break a request
                pass
            # Connection setup runs inside this await, so it can read the caller
            token = _CURRENT_CALLER.set(caller)
            try:
                return await orig_request(session, method, str_or_url, *args, **kwargs)
            finally:
                _CURRENT_CALLER.reset(token)
                if host and tracer._active:
                    try:
                        tracer._record(host.lower(), caller)
                    except Exception:  # noqa: BLE001
                        pass

        @functools.wraps(orig_connect)
        async def _traced_connect(connector: aiohttp.TCPConnector, req: Any, *args: Any, **kwargs: Any):
            result = await orig_connect(connector, req, *args, **kwargs)
            try:
                if tracer._active and (peername := result[0].get_extra_info("peername")):
                    tracer._record_peer((req.url.raw_host or "").lower(), peername[0], _CURRENT_CALLER.get())
            except Exception:  # noqa: BLE001
                pass
            return result

        setattr(_traced_request, _MARK, True)
        aiohttp.ClientSession._request = _traced_request
        aiohttp.TCPConnector._create_direct_connection = _traced_connect
        self._wrappers = (_traced_request, _traced_connect)
        self._active = True

    def stop(self) -> None:
        self._active = False
        if self._originals is None or self._wrappers is None:
            return
        # Only unhook what is still ours on top. If something wrapped aiohttp after
        # us (e.g. the old security_dashboard during an upgrade), restoring would
        # remove its hook too, so our wrapper stays in place as a pass-through.
        if aiohttp.ClientSession._request is self._wrappers[0]:
            aiohttp.ClientSession._request = self._originals[0]
        if aiohttp.TCPConnector._create_direct_connection is self._wrappers[1]:
            aiohttp.TCPConnector._create_direct_connection = self._originals[1]
        self._originals = self._wrappers = None

    def _record_peer(self, host: str, peer: str, caller: str | None) -> None:
        """A new TCP connection: remember which host/integration an IP belongs to."""
        if _is_local(peer):
            self._local_hosts.add(host)
            if not self.include_local:
                return
        if host and peer != host:
            self.ip_map[peer] = {"host": host, "integration": caller, "ts": time.time()}

    def _record(self, host: str, caller: str | None) -> None:
        """One request. Called on the request's loop; plain dict updates only."""
        if not self.include_local and (host in self._local_hosts or _is_local(host)):
            return
        now_iso = dt_util.utcnow().isoformat()
        entry = self.hosts.get(host)
        if entry is None:
            if len(self.hosts) >= _MAX_HOSTS:
                return
            entry = self.hosts[host] = {"integrations": {}, "first_seen": now_iso, "last_seen": now_iso, "hourly": {}}
        entry["last_seen"] = now_iso
        hour = _hour()
        entry["hourly"][hour] = entry["hourly"].get(hour, 0) + 1
        label = caller or "unknown"
        entry["integrations"][label] = entry["integrations"].get(label, 0) + 1

    # ---------------------------------------------------------------- library → integration

    async def async_build_library_map(self) -> None:
        """Map import packages to the integrations that require them.

        Lets "lib:pyfoo" (a request from a library's own background task, with no
        integration frame on the stack) be shown as the integration that installed
        that library.
        """
        import importlib.metadata  # noqa: PLC0415

        pkg_to_dists = await self.hass.async_add_executor_job(importlib.metadata.packages_distributions)
        dist_to_domain: dict[str, str] = {}
        for domain in list(self.hass.config.components):
            if "." in domain:
                continue
            try:
                integration = async_get_loaded_integration(self.hass, domain)
            except Exception:  # noqa: BLE001
                continue
            for req in integration.requirements:
                name = re.split(r"[<>=!~\[; ]", req, maxsplit=1)[0]
                dist_to_domain.setdefault(_normalize(name), domain)
        mapping = {}
        for pkg, dists in pkg_to_dists.items():
            for dist in dists:
                if (domain := dist_to_domain.get(_normalize(dist))) is not None:
                    mapping[pkg] = domain
                    break
        self._lib_to_domain = mapping

    def display_integration(self, label: str | None) -> str | None:
        if label and label.startswith("lib:"):
            return self._lib_to_domain.get(label[4:], label)
        return label

    # ---------------------------------------------------------------- queries

    def prune(self) -> None:
        cutoff_hour = _hour() - 24
        week_ago = (dt_util.utcnow().timestamp()) - 7 * 86400
        for host in list(self.hosts):
            entry = self.hosts[host]
            entry["hourly"] = {h: n for h, n in list(entry["hourly"].items()) if h > cutoff_hour}
            last = dt_util.parse_datetime(entry["last_seen"])
            if last is None or last.timestamp() < week_ago:
                del self.hosts[host]
        ip_cutoff = time.time() - _IP_TTL
        self.ip_map = {ip: v for ip, v in list(self.ip_map.items()) if v["ts"] > ip_cutoff}

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        hit = self.ip_map.get(ip)
        if hit is None:
            return None
        return {"host": hit["host"], "integration": self.display_integration(hit["integration"])}

    def hosts_24h(self) -> list[dict[str, Any]]:
        out = []
        cutoff_hour = _hour() - 24
        for host, entry in list(self.hosts.items()):
            requests = sum(n for h, n in list(entry["hourly"].items()) if h > cutoff_hour)
            if not requests:
                continue
            integrations: dict[str, int] = {}
            for label, n in list(entry["integrations"].items()):
                name = self.display_integration(label) or "unknown"
                integrations[name] = integrations.get(name, 0) + n
            out.append(
                {
                    "host": host,
                    "requests": requests,
                    "integrations": sorted(integrations, key=integrations.get, reverse=True),
                    "first_seen": entry["first_seen"],
                    "last_seen": entry["last_seen"],
                }
            )
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "hosts": {
                h: {**v, "integrations": dict(v["integrations"]), "hourly": {str(k): n for k, n in list(v["hourly"].items())}}
                for h, v in list(self.hosts.items())
            },
            "ip_map": dict(self.ip_map),
        }


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
