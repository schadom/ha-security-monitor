"""Attribute outbound connections to the integration that made them.

Two layers:

1. Python audit hook (attribution, every library).
   `sys.addaudithook` reports every `socket.connect` and `socket.getaddrinfo`
   in the process: aiohttp, httpx, requests/urllib3, websockets, MQTT, raw
   sockets, in asyncio tasks and executor threads alike. This is a documented
   Python feature, so it does not depend on any library's internals. For each
   outbound TCP connection we record the peer IP and the integration, found by:
     a. walking the call stack to the first frame of an integration,
     b. the caller handed down by the aiohttp layer (context variable),
     c. Home Assistant's `current_entry` context: it is set while a config
        entry sets up and is inherited by the tasks and timers created then,
        so background polling is attributed even with no integration code on
        the stack,
     d. a library frame on the stack, mapped to the integration that requires
        that library.

2. aiohttp layer (exact hostnames, optional).
   The audit hook sees the IP a connection goes to, but HA's HTTP client
   resolves names with its own DNS library, so the hostname is not visible
   there. Wrapping aiohttp (ClientSession._request and
   TCPConnector._create_direct_connection, private API) records the hostname
   of each request. If a future aiohttp version changes these, this layer
   switches itself off and attribution keeps working; only those hostnames are
   lost. For connections made by other libraries, hostnames come from their
   DNS lookups (getaddrinfo), which are resolved again in the background and
   matched against the connected IPs, with reverse DNS as the last resort.

Privacy: only hostnames, IPs, integration names, counts and timestamps are
kept, never URLs, paths, query strings, headers or bodies. LAN and loopback
traffic is ignored.

An audit hook can't be removed once added. It is installed once per process
and becomes a no-op while no tracer is active.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from contextvars import ContextVar
import functools
import ipaddress
import logging
import re
import socket
import sys
import threading
import time
import types
from typing import Any

import aiohttp
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_loaded_integration
from homeassistant.util import dt as dt_util

from .const import DOMAIN

try:  # HA internal; attribution falls back to the stack if it ever moves
    from homeassistant.config_entries import current_entry as _CURRENT_ENTRY
except ImportError:  # pragma: no cover
    _CURRENT_ENTRY = None

_LOGGER = logging.getLogger(__name__)

_MARK = "_security_monitor_tracer"
_CURRENT_CALLER: ContextVar[str | None] = ContextVar("security_monitor_caller", default=None)
_COMPONENT_RE = re.compile(r"[/\\](?:homeassistant[/\\]components|custom_components)[/\\]([a-z0-9_]+)[/\\]")
_PACKAGE_RE = re.compile(r"[/\\](?:site|dist)-packages[/\\]([A-Za-z0-9_]+)")
_IGNORED_PACKAGES = {
    "aiohttp", "yarl", "multidict", "async_timeout", "homeassistant", "aiohttp_retry",
    "backoff", "tenacity", "asyncio", "concurrent", "propcache", "sentry_sdk",
    "aiohappyeyeballs", "urllib3", "requests", "httpx", "httpcore", "anyio", "h11",
    "certifi", "socket", "ssl", "selectors", "threading",
}
_MAX_FRAMES = 80
_MAX_HOSTS = 500
_IP_TTL = 24 * 3600
_LOOKUP_TTL = 15 * 60          # how long a DNS lookup is used to name connections
_RESOLVE_INTERVAL = 10 * 60    # re-resolve a hostname at most this often
_MAX_RESOLVE_PER_RUN = 20
_PENDING_MAX = 5000

_INET = (socket.AF_INET, socket.AF_INET6)
_AUDIT_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo"})
_REGISTRY_KEY = "_security_monitor_audit_registry"


# ------------------------------------------------------------------ helpers


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _hour() -> int:
    return int(time.time() // 3600)


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _stack_caller(frame: types.FrameType | None) -> tuple[str | None, str | None]:
    """(integration domain, library package) found on the stack, each or None."""
    library = None
    depth = 0
    while frame is not None and depth < _MAX_FRAMES:
        filename = frame.f_code.co_filename
        if (m := _COMPONENT_RE.search(filename)) and m.group(1) != DOMAIN:
            return m.group(1), library
        if library is None and (p := _PACKAGE_RE.search(filename)):
            if p.group(1) not in _IGNORED_PACKAGES:
                library = p.group(1)
        frame = frame.f_back
        depth += 1
    return None, library


def _attribute(frame: types.FrameType | None) -> str | None:
    """Best attribution for the current call: integration, else "lib:<pkg>"."""
    integration, library = _stack_caller(frame)
    if integration:
        return integration
    if (handed_down := _CURRENT_CALLER.get()) and not handed_down.startswith("lib:"):
        return handed_down
    if _CURRENT_ENTRY is not None:
        entry = _CURRENT_ENTRY.get()
        if entry is not None and entry.domain != DOMAIN:
            return entry.domain
    if handed_down:
        return handed_down
    return f"lib:{library}" if library else None


# ------------------------------------------------------------------ audit hook


def _registry() -> types.ModuleType:
    """Process-wide state, kept in sys.modules so it survives module reloads."""
    reg = sys.modules.get(_REGISTRY_KEY)
    if reg is None:
        reg = types.ModuleType(_REGISTRY_KEY)
        reg.tracer = None
        reg.installed = False
        reg.guard = threading.local()
        sys.modules[_REGISTRY_KEY] = reg
    return reg


def _install_audit_hook(reg: types.ModuleType) -> bool:
    if reg.installed:
        return True
    events = _AUDIT_EVENTS
    guard = reg.guard

    def _hook(event: str, args: tuple[Any, ...]) -> None:
        # Called for every audit event in the process: keep the fast path tiny
        if event not in events:
            return
        tracer = reg.tracer
        if tracer is None or getattr(guard, "active", False):
            return
        try:
            tracer._on_audit(event, args, sys._getframe(1))
        except Exception:  # noqa: BLE001 - must never break a connection
            pass

    try:
        sys.addaudithook(_hook)
    except Exception:  # noqa: BLE001 - e.g. blocked by another hook
        _LOGGER.warning("Could not install the Python audit hook; connection attribution is limited")
        return False
    reg.installed = True
    return True


# ------------------------------------------------------------------ tracer


class ConnectionTracer:
    """Per-host request/connection stats and a peer-IP → host/integration map."""

    def __init__(self, hass: HomeAssistant, restored: dict[str, Any] | None = None) -> None:
        self.hass = hass
        # host -> {"integrations": {name: n}, "first_seen", "last_seen", "hourly": {hour: n}}
        self.hosts: dict[str, dict[str, Any]] = {}      # HTTP requests (aiohttp layer)
        self.connects: dict[str, dict[str, Any]] = {}   # TCP connects (audit hook), keyed by host or IP
        # peer ip -> {"host": str | None, "integration": str | None, "ts": epoch seconds}
        self.ip_map: dict[str, dict[str, Any]] = {}
        self.capabilities = {"audit_hook": False, "aiohttp": False}
        # Only outbound (internet) traffic matters here; LAN devices are skipped
        self.include_local = False
        self._lib_to_domain: dict[str, str] = {}
        self._originals: tuple[Callable[..., Any], Callable[..., Any]] | None = None
        self._wrappers: tuple[Callable[..., Any], Callable[..., Any]] | None = None
        self._active = False
        self._local_hosts: set[str] = set()
        self._pending: deque[tuple[str, str, str | None]] = deque(maxlen=_PENDING_MAX)
        self._lookups: dict[str, tuple[str | None, float]] = {}   # host -> (caller, ts)
        self._resolved_at: dict[str, float] = {}
        if restored:
            self.hosts = self._restore_stats(restored.get("hosts", {}))
            self.connects = self._restore_stats(restored.get("connects", {}))
            self.ip_map = restored.get("ip_map", {})

    @staticmethod
    def _restore_stats(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {h: {**v, "hourly": {int(k): n for k, n in v.get("hourly", {}).items()}} for h, v in data.items()}

    # ---------------------------------------------------------------- start / stop

    def start(self) -> None:
        reg = _registry()
        self.capabilities["audit_hook"] = _install_audit_hook(reg)
        reg.tracer = self
        self._active = True
        try:
            self._start_aiohttp_layer()
        except Exception as err:  # noqa: BLE001 - private aiohttp API moved
            _LOGGER.warning("aiohttp hostname tracing is unavailable (%s); attribution still works", err)
            self.capabilities["aiohttp"] = False

    def stop(self) -> None:
        self._active = False
        reg = _registry()
        if reg.tracer is self:
            reg.tracer = None
        self._stop_aiohttp_layer()

    def _start_aiohttp_layer(self) -> None:
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
                caller = _attribute(sys._getframe(1))
            except Exception:  # noqa: BLE001 - tracing must never break a request
                pass
            # Connection setup (and the audit hook) run inside this await
            token = _CURRENT_CALLER.set(caller)
            try:
                return await orig_request(session, method, str_or_url, *args, **kwargs)
            finally:
                _CURRENT_CALLER.reset(token)
                if host and tracer._active:
                    try:
                        tracer._record_request(host.lower(), caller)
                    except Exception:  # noqa: BLE001
                        pass

        @functools.wraps(orig_connect)
        async def _traced_connect(connector: aiohttp.TCPConnector, req: Any, *args: Any, **kwargs: Any):
            result = await orig_connect(connector, req, *args, **kwargs)
            try:
                if tracer._active and (peername := result[0].get_extra_info("peername")):
                    tracer._record_peer_host((req.url.raw_host or "").lower(), peername[0], _CURRENT_CALLER.get())
            except Exception:  # noqa: BLE001
                pass
            return result

        setattr(_traced_request, _MARK, True)
        aiohttp.ClientSession._request = _traced_request
        aiohttp.TCPConnector._create_direct_connection = _traced_connect
        self._wrappers = (_traced_request, _traced_connect)
        self.capabilities["aiohttp"] = True

    def _stop_aiohttp_layer(self) -> None:
        if self._originals is None or self._wrappers is None:
            return
        # Only unhook what is still ours on top. If something wrapped aiohttp after
        # us, restoring would remove its hook too, so ours stays as a pass-through.
        if aiohttp.ClientSession._request is self._wrappers[0]:
            aiohttp.ClientSession._request = self._originals[0]
        if aiohttp.TCPConnector._create_direct_connection is self._wrappers[1]:
            aiohttp.TCPConnector._create_direct_connection = self._originals[1]
        self._originals = self._wrappers = None

    # ---------------------------------------------------------------- audit events (any thread)

    def _on_audit(self, event: str, args: tuple[Any, ...], frame: types.FrameType | None) -> None:
        """Runs in whatever thread connects: only a deque append, processed later."""
        if not self._active:
            return
        if event == "socket.connect":
            sock, address = args
            if sock.family not in _INET or sock.type != socket.SOCK_STREAM:
                return
            if not isinstance(address, tuple) or not address or not isinstance(address[0], str):
                return
            self._pending.append(("connect", address[0], _attribute(frame)))
        else:  # socket.getaddrinfo
            host = args[0]
            if isinstance(host, bytes):
                host = host.decode(errors="ignore")
            if not isinstance(host, str) or not host or _is_ip(host) or host == "localhost":
                return
            self._pending.append(("lookup", host.lower().rstrip("."), _attribute(frame)))

    def process_pending(self) -> None:
        """Fold queued audit events into the stats. Call on the event loop."""
        while self._pending:
            try:
                kind, target, caller = self._pending.popleft()
            except IndexError:
                break
            if kind == "lookup":
                if len(self._lookups) < _MAX_HOSTS or target in self._lookups:
                    self._lookups[target] = (caller, time.time())
                continue
            if _is_ip(target):
                if _is_local(target) and not self.include_local:
                    continue
                known = self.ip_map.get(target, {})
                host = known.get("host")
                self.ip_map[target] = {
                    "host": host,
                    "integration": caller or known.get("integration"),
                    "ts": time.time(),
                }
                self._bump(self.connects, host or target, caller)
            else:
                # Blocking connect((hostname, port)): name known, IP resolved inside Python
                if target in self._local_hosts and not self.include_local:
                    continue
                self._bump(self.connects, target.lower(), caller)

    async def async_enrich(self) -> None:
        """Name IPs that only the audit hook saw, using recent DNS lookups."""
        unnamed = {ip for ip, v in list(self.ip_map.items()) if not v.get("host")}
        if not unnamed:
            return
        now = time.time()
        candidates = [
            host for host, (_caller, ts) in list(self._lookups.items())
            if now - ts < _LOOKUP_TTL and now - self._resolved_at.get(host, 0) > _RESOLVE_INTERVAL
        ][:_MAX_RESOLVE_PER_RUN]
        if not candidates:
            return
        resolved = await self.hass.async_add_executor_job(self._resolve_all, candidates)
        for host, ips in resolved.items():
            self._resolved_at[host] = now
            if ips and all(_is_local(ip) for ip in ips):
                self._local_hosts.add(host)
            for ip in ips:
                if ip in unnamed:
                    self._name_ip(ip, host)

    @staticmethod
    def _resolve_all(hosts: list[str]) -> dict[str, set[str]]:
        """Executor: resolve without our own lookups showing up as traffic."""
        guard = _registry().guard
        guard.active = True
        out: dict[str, set[str]] = {}
        try:
            for host in hosts:
                try:
                    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                except OSError:
                    continue
                out[host] = {info[4][0] for info in infos}
        finally:
            guard.active = False
        return out

    def _name_ip(self, ip: str, host: str) -> None:
        entry = self.ip_map.get(ip)
        if entry is None:
            return
        entry["host"] = host
        # Connections counted under the bare IP move to the hostname
        if (stats := self.connects.pop(ip, None)) is not None:
            target = self.connects.get(host)
            if target is None:
                self.connects[host] = stats
            else:
                for label, n in stats["integrations"].items():
                    target["integrations"][label] = target["integrations"].get(label, 0) + n
                for hour, n in stats["hourly"].items():
                    target["hourly"][hour] = target["hourly"].get(hour, 0) + n
                target["first_seen"] = min(target["first_seen"], stats["first_seen"])
                target["last_seen"] = max(target["last_seen"], stats["last_seen"])

    # ---------------------------------------------------------------- aiohttp layer records

    def _record_peer_host(self, host: str, peer: str, caller: str | None) -> None:
        """aiohttp opened a TCP connection: we know the IP's hostname exactly."""
        if _is_local(peer):
            self._local_hosts.add(host)
            if not self.include_local:
                return
        if host and peer != host:
            known = self.ip_map.get(peer, {})
            self.ip_map[peer] = {"host": host, "integration": caller or known.get("integration"), "ts": time.time()}
            if peer in self.connects:
                self._name_ip(peer, host)

    def _record_request(self, host: str, caller: str | None) -> None:
        if not self.include_local and (host in self._local_hosts or _is_local(host)):
            return
        self._bump(self.hosts, host, caller)

    @staticmethod
    def _bump(table: dict[str, dict[str, Any]], key: str, caller: str | None) -> None:
        now_iso = dt_util.utcnow().isoformat()
        entry = table.get(key)
        if entry is None:
            if len(table) >= _MAX_HOSTS:
                return
            entry = table[key] = {"integrations": {}, "first_seen": now_iso, "last_seen": now_iso, "hourly": {}}
        entry["last_seen"] = now_iso
        hour = _hour()
        entry["hourly"][hour] = entry["hourly"].get(hour, 0) + 1
        label = caller or "unknown"
        entry["integrations"][label] = entry["integrations"].get(label, 0) + 1

    # ---------------------------------------------------------------- library → integration

    async def async_build_library_map(self) -> None:
        """Map import packages to the integrations that require them."""
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
        week_ago = dt_util.utcnow().timestamp() - 7 * 86400
        for table in (self.hosts, self.connects):
            for key in list(table):
                entry = table[key]
                entry["hourly"] = {h: n for h, n in list(entry["hourly"].items()) if h > cutoff_hour}
                last = dt_util.parse_datetime(entry["last_seen"])
                if last is None or last.timestamp() < week_ago:
                    del table[key]
        ip_cutoff = time.time() - _IP_TTL
        self.ip_map = {ip: v for ip, v in list(self.ip_map.items()) if v["ts"] > ip_cutoff}
        lookup_cutoff = time.time() - _LOOKUP_TTL
        self._lookups = {h: v for h, v in list(self._lookups.items()) if v[1] > lookup_cutoff}

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        hit = self.ip_map.get(ip)
        if hit is None:
            return None
        return {"host": hit.get("host"), "integration": self.display_integration(hit.get("integration"))}

    def hosts_24h(self) -> list[dict[str, Any]]:
        """Destinations with requests and/or connections in the last 24 h."""
        cutoff_hour = _hour() - 24
        merged: dict[str, dict[str, Any]] = {}
        for table, field in ((self.hosts, "requests"), (self.connects, "connections")):
            for key, entry in list(table.items()):
                count = sum(n for h, n in list(entry["hourly"].items()) if h > cutoff_hour)
                if not count:
                    continue
                item = merged.setdefault(
                    key,
                    {"host": key, "requests": 0, "connections": 0, "_integrations": {},
                     "first_seen": entry["first_seen"], "last_seen": entry["last_seen"]},
                )
                item[field] += count
                for label, n in list(entry["integrations"].items()):
                    name = self.display_integration(label)
                    if name and name != "unknown":
                        item["_integrations"][name] = item["_integrations"].get(name, 0) + n
                item["first_seen"] = min(item["first_seen"], entry["first_seen"])
                item["last_seen"] = max(item["last_seen"], entry["last_seen"])
        out = []
        for item in merged.values():
            counts = item.pop("_integrations")
            item["integrations"] = sorted(counts, key=counts.get, reverse=True)
            out.append(item)
        return out

    def as_dict(self) -> dict[str, Any]:
        def dump(table: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return {
                h: {**v, "integrations": dict(v["integrations"]), "hourly": {str(k): n for k, n in list(v["hourly"].items())}}
                for h, v in list(table.items())
            }

        return {"hosts": dump(self.hosts), "connects": dump(self.connects), "ip_map": dict(self.ip_map)}
