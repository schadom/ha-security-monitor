"""Configuration hygiene checks → findings with a severity."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_custom_components

SEVERITY_WEIGHT = {"high": 20, "medium": 8, "low": 3}


def _finding(
    fid: str, severity: str, title: str, detail: str, key: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A finding. `key` and `params` let the panel show it in the user's language;
    `title` and `detail` are the English fallback."""
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "key": key, "params": params or {}}


def _ip_ban_enabled(hass: HomeAssistant) -> bool | None:
    """True/False if detectable, None if the internal API moved."""
    try:
        from homeassistant.components.http.ban import KEY_BAN_MANAGER  # noqa: PLC0415

        return hass.http.app.get(KEY_BAN_MANAGER) is not None
    except (ImportError, AttributeError):
        return None


async def async_run_checks(hass: HomeAssistant, auth: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for user in auth["users"]:
        if user["is_active"] and not user["mfa_enabled"]:
            sev = "high" if user["is_admin"] else "medium"
            findings.append(
                _finding(f"no_mfa_{user['name']}", sev, f"{user['name']} has no MFA",
                         "Enable TOTP under the user's profile → Security.",
                         "no_mfa", {"user": user["name"]})
            )

    stale = [t for t in auth["tokens"] if t["stale"]]
    if stale:
        findings.append(
            _finding("stale_tokens", "medium", f"{len(stale)} unused long-lived token(s)",
                     "Long-lived tokens not used in 90 days. Revoke the ones you don't need.",
                     "stale_tokens", {"count": len(stale)})
        )

    if _ip_ban_enabled(hass) is False:
        findings.append(
            _finding("ip_ban_disabled", "high", "IP banning is off",
                     "Set http: ip_ban_enabled: true and login_attempts_threshold.",
                     "ip_ban_disabled")
        )

    if (url := hass.config.external_url) and url.startswith("http://"):
        findings.append(
            _finding("external_http", "high", "External URL is plain HTTP",
                     "Remote access without TLS exposes credentials and tokens.",
                     "external_http")
        )

    if auth["failed_logins_24h"] >= 10:
        findings.append(
            _finding("login_burst", "medium", f"{auth['failed_logins_24h']} failed logins in 24h",
                     "Check the access log for repeated source IPs.",
                     "login_burst", {"count": auth["failed_logins_24h"]})
        )

    custom = await async_get_custom_components(hass)
    if custom:
        findings.append(
            _finding("custom_components", "low", f"{len(custom)} custom integrations installed",
                     "Custom code runs with full access to Home Assistant. Keep it updated.",
                     "custom_components", {"count": len(custom)})
        )

    return findings


def score_from_findings(findings: list[dict[str, Any]]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
