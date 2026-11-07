"""Mirror high-severity findings into Settings → Repairs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from .checks import async_run_checks
from .const import DOMAIN

if TYPE_CHECKING:
    from . import SecurityConfigEntry

# Findings that get a native Repairs issue (translation keys in strings.json)
REPAIRABLE = {"ip_ban_disabled", "external_http", "stale_tokens"}


async def async_check_issues(hass: HomeAssistant, entry: SecurityConfigEntry) -> None:
    auth = await entry.runtime_data.auth.async_snapshot()
    findings = {f["id"]: f for f in await async_run_checks(hass, auth)}

    for issue_id in REPAIRABLE:
        if issue_id in findings:
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.WARNING,
                translation_key=issue_id,
            )
        else:
            ir.async_delete_issue(hass, DOMAIN, issue_id)
