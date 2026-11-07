"""Access / authentication monitoring.

Two sources:
1. A logging handler on HA's http ban logger, which catches every failed
   login or request with invalid auth (HA has no dedicated event for this).
2. hass.auth: users, refresh tokens (incl. long-lived access tokens), their
   last-used time/IP, and MFA status. Note: hass.auth is semi-internal API.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import timedelta
import logging
import re
from typing import Any

from homeassistant.auth.models import TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.util import dt as dt_util

from .const import AUTH_EVENT_BUFFER, BAN_LOGGER, SIGNAL_UPDATED, STALE_TOKEN_DAYS

# HA logs either:
#   "Login attempt or request with invalid authentication from <host> (<ip>). Requested URL: '...'. (<user agent>)"
#   "Banned IP <ip> for too many login attempts"
# <host> is a reverse-DNS name when one resolves, so take the IP from the parentheses.
_LOGGER = logging.getLogger(__name__)

_FAILED_IP_RE = re.compile(r"invalid authentication from \S+ \(([0-9a-fA-F:.]+)\)")
_BANNED_IP_RE = re.compile(r"Banned IP ([0-9a-fA-F:.]+)")
# Keep the line up to the requested URL; the trailing "(<user agent>)" is unsanitized client input
_UP_TO_URL_RE = re.compile(r"^.*?Requested URL: '[^']*'\.")


@dataclass(slots=True)
class AuthEvent:
    """One entry in the access log."""

    timestamp: str
    kind: str  # "failed_login" | "banned" | "token_used"
    ip: str | None
    user: str | None
    detail: str


class _BanLogHandler(logging.Handler):
    """Turns http.ban log records into AuthEvents."""

    def __init__(self, monitor: AuthMonitor) -> None:
        super().__init__(level=logging.WARNING)
        self._monitor = monitor

    def emit(self, record: logging.LogRecord) -> None:
        msg = record.getMessage().splitlines()[0]
        if match := _BANNED_IP_RE.search(msg):
            kind = "banned"
        elif match := _FAILED_IP_RE.search(msg):
            kind = "failed_login"
        else:
            return  # some other warning from this logger
        event = AuthEvent(
            timestamp=dt_util.utcnow().isoformat(),
            kind=kind,
            ip=match.group(1),
            user=None,
            detail=(m.group(0) if (m := _UP_TO_URL_RE.match(msg)) else msg)[:300],
        )
        # Log records may come from any thread: hop back onto the event loop
        self._monitor.hass.loop.call_soon_threadsafe(self._monitor.add_event, event)


class AuthMonitor:
    """Keeps a rolling access log and answers auth-hygiene questions."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.events: deque[AuthEvent] = deque(maxlen=AUTH_EVENT_BUFFER)
        self._handler = _BanLogHandler(self)
        self._seen_token_use: dict[str, str] = {}

    async def async_start(self) -> None:
        ban_logger = logging.getLogger(BAN_LOGGER)
        # With e.g. `logger: default: error` the failed-login warnings are dropped
        # before any handler runs. Lower just this logger so we still see them.
        if ban_logger.getEffectiveLevel() > logging.WARNING:
            ban_logger.setLevel(logging.WARNING)
            _LOGGER.info("Set %s to WARNING so failed logins can be recorded", BAN_LOGGER)
        ban_logger.addHandler(self._handler)
        # Seed "last used" so we only log *new* token usage from here on
        for token in await self._all_tokens():
            if token["last_used_at"]:
                self._seen_token_use[token["id"]] = token["last_used_at"]

    @callback
    def async_stop(self) -> None:
        logging.getLogger(BAN_LOGGER).removeHandler(self._handler)

    @callback
    def add_event(self, event: AuthEvent) -> None:
        self.events.appendleft(event)
        async_dispatcher_send(self.hass, SIGNAL_UPDATED)

    # ------------------------------------------------------------------ tokens

    async def _all_tokens(self) -> list[dict[str, Any]]:
        tokens = []
        for user in await self.hass.auth.async_get_users():
            if user.system_generated:
                continue
            for tok in user.refresh_tokens.values():
                tokens.append(
                    {
                        "id": tok.id,
                        "user": user.name,
                        "client_name": tok.client_name or tok.client_id,
                        "type": tok.token_type,
                        "created_at": tok.created_at.isoformat(),
                        "last_used_at": tok.last_used_at.isoformat()
                        if tok.last_used_at
                        else None,
                        "last_used_ip": tok.last_used_ip,
                    }
                )
        return tokens

    async def async_poll_token_usage(self) -> None:
        """Turn changes in token last_used_at into 'token_used' log entries."""
        for token in await self._all_tokens():
            last = token["last_used_at"]
            if last and self._seen_token_use.get(token["id"]) != last:
                self._seen_token_use[token["id"]] = last
                self.add_event(
                    AuthEvent(
                        timestamp=last,
                        kind="token_used",
                        ip=token["last_used_ip"],
                        user=token["user"],
                        detail=f"{token['client_name']} ({token['type']})",
                    )
                )

    async def async_snapshot(self) -> dict[str, Any]:
        """Everything the panel needs about users and tokens."""
        now = dt_util.utcnow()
        stale_cutoff = now - timedelta(days=STALE_TOKEN_DAYS)
        users = []
        for user in await self.hass.auth.async_get_users():
            if user.system_generated:
                continue
            mfa = await self.hass.auth.async_get_enabled_mfa(user)
            users.append(
                {
                    "name": user.name,
                    "is_owner": user.is_owner,
                    "is_admin": user.is_admin,
                    "is_active": user.is_active,
                    "mfa_enabled": bool(mfa),
                }
            )

        tokens = await self._all_tokens()
        for tok in tokens:
            last = dt_util.parse_datetime(tok["last_used_at"] or "") or None
            tok["stale"] = (
                tok["type"] == TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN
                and (last is None or last < stale_cutoff)
            )

        # Failed logins: last 24 h plus 24 hourly buckets aligned to clock hours
        # (bucket 23 = the current, partial hour) for the chart.
        day_ago = now - timedelta(hours=24)
        hourly_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
        hourly = [0] * 24
        failed_24h = 0
        sources: Counter[str] = Counter()
        banned_ips: set[str] = set()
        for e in self.events:
            ts = dt_util.parse_datetime(e.timestamp)
            if ts is None:
                continue
            if e.kind == "banned" and ts > day_ago and e.ip:
                banned_ips.add(e.ip)
            if e.kind != "failed_login":
                continue
            if ts > day_ago:
                failed_24h += 1
                if e.ip:
                    sources[e.ip] += 1
            if ts >= hourly_start:
                hourly[min(23, int((ts - hourly_start).total_seconds() // 3600))] += 1

        top = sources.most_common(1)
        return {
            "users": users,
            "tokens": tokens,
            "failed_logins_24h": failed_24h,
            "failed_sources_24h": len(sources),
            "banned_24h": len(banned_ips),
            "top_source_24h": {"ip": top[0][0], "count": top[0][1]} if top else None,
            "failed_hourly": hourly,
            "failed_hourly_start": hourly_start.isoformat(),
            "events": [asdict(e) for e in list(self.events)[:200]],
        }
