"""Configuration hygiene checks → findings with a severity."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_custom_components

SEVERITY_WEIGHT = {"high": 20, "medium": 8, "low": 3}

# Every finding `key`; the panel has a translated title and detail for each
FINDING_KEYS = frozenset({
    "no_mfa",
    "service_account",
    "service_account_admin",
    "service_account_admin_local",
    "stale_tokens",
    "ip_ban_disabled",
    "external_http",
    "login_burst",
    "custom_components",
})


def _finding(
    fid: str,
    severity: str,
    title: str,
    detail: str,
    key: str,
    params: dict[str, Any] | None = None,
    *,
    dismissible: bool = True,
) -> dict[str, Any]:
    """A finding. `key` and `params` let the panel show it in the user's language;
    `title` and `detail` are the English fallback."""
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "key": key,
        "params": params or {},
        "dismissible": dismissible,
    }


def _user_finding(user: dict[str, Any]) -> dict[str, Any] | None:
    """MFA finding for one user, or None when MFA wouldn't help.

    Service accounts (only long-lived tokens) never log in interactively, so
    "enable TOTP" is the wrong advice: the risk is their password login.
    """
    if not user["is_active"] or user["mfa_enabled"] or not user["mfa_applies"]:
        return None
    name = user["name"]
    if user["service_account"] and user["is_admin"]:
        key = "service_account_admin_local" if user["local_only"] else "service_account_admin"
        detail = "Remove admin rights if the tool using it doesn't need them"
        detail += "." if user["local_only"] else ", and make it local-only."
        return _finding(f"service_account_{user['id']}", "medium",
                        f"Admin service account {name} can log in with a password", detail,
                        key, {"user": name})
    if user["service_account"]:
        return _finding(f"service_account_{user['id']}", "low",
                        f"Service account {name} can log in with a password",
                        "It only uses long-lived tokens. Make it local-only or set a long random password.",
                        "service_account", {"user": name})
    return _finding(f"no_mfa_{user['id']}", "high" if user["is_admin"] else "medium",
                    f"{name} has no MFA", "Enable TOTP under the user's profile → Security.",
                    "no_mfa", {"user": name})


def is_dismissed(finding: dict[str, Any], dismissed: dict[str, dict[str, Any]]) -> bool:
    """A dismissal covers the finding as it was when dismissed.

    It lapses when the finding changes: another user name, or a higher count
    (e.g. one more stale token or custom integration than before).
    """
    entry = dismissed.get(finding["id"])
    if entry is None or not finding["dismissible"]:
        return False
    before = entry.get("params", {})
    for name, value in finding["params"].items():
        if name == "count":
            if value > before.get("count", value - 1):
                return False
        elif before.get(name) != value:
            return False
    return True


def split_dismissed(
    findings: list[dict[str, Any]], dismissed: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(open findings, dismissed findings)."""
    open_, hidden = [], []
    for f in findings:
        (hidden if is_dismissed(f, dismissed) else open_).append(f)
    return open_, hidden


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
        if (finding := _user_finding(user)) is not None:
            findings.append(finding)

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
                     "login_burst", {"count": auth["failed_logins_24h"]},
                     dismissible=False)  # clears by itself; a dismissal would hide future bursts
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
