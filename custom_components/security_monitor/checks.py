"""Configuration hygiene checks → findings with a severity."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_custom_components

SEVERITY_WEIGHT = {"high": 20, "medium": 8, "low": 3}


def _finding(fid: str, severity: str, title: str, detail: str) -> dict[str, str]:
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


def _ip_ban_enabled(hass: HomeAssistant) -> bool | None:
    """True/False if detectable, None if the internal API moved."""
    try:
        from homeassistant.components.http.ban import KEY_BAN_MANAGER  # noqa: PLC0415

        return hass.http.app.get(KEY_BAN_MANAGER) is not None
    except (ImportError, AttributeError):
        return None


async def async_run_checks(hass: HomeAssistant, auth: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    for user in auth["users"]:
        if user["is_active"] and not user["mfa_enabled"]:
            sev = "high" if user["is_admin"] else "medium"
            findings.append(
                _finding(f"no_mfa_{user['name']}", sev, f"{user['name']} has no MFA",
                         "Enable TOTP under the user's profile → Security.")
            )

    stale = [t for t in auth["tokens"] if t["stale"]]
    if stale:
        findings.append(
            _finding("stale_tokens", "medium", f"{len(stale)} unused long-lived token(s)",
                     "Long-lived tokens not used in 90 days. Revoke the ones you don't need.")
        )

    if _ip_ban_enabled(hass) is False:
        findings.append(
            _finding("ip_ban_disabled", "high", "IP banning is off",
                     "Set http: ip_ban_enabled: true and login_attempts_threshold.")
        )

    if (url := hass.config.external_url) and url.startswith("http://"):
        findings.append(
            _finding("external_http", "high", "External URL is plain HTTP",
                     "Remote access without TLS exposes credentials and tokens.")
        )

    if auth["failed_logins_24h"] >= 10:
        findings.append(
            _finding("login_burst", "medium", f"{auth['failed_logins_24h']} failed logins in 24h",
                     "Check the access log for repeated source IPs.")
        )

    custom = await async_get_custom_components(hass)
    if custom:
        findings.append(
            _finding("custom_components", "low", f"{len(custom)} custom integrations installed",
                     "Custom code runs with full access to Home Assistant. Keep it updated.")
        )

    return findings


def score_from_findings(findings: list[dict[str, str]]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
