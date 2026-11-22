"""Websocket commands consumed by the bundled panel (admin only)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect, async_dispatcher_send
from homeassistant.util import dt as dt_util

from .checks import async_run_checks, score_from_findings, split_dismissed
from .const import (
    DOMAIN,
    SIGNAL_UPDATED,
    WS_DISMISS_FINDING,
    WS_OVERVIEW,
    WS_RESTORE_FINDING,
    WS_RUN_CHECKS,
    WS_SUBSCRIBE,
)
from .repairs import async_check_issues


@callback
def async_register(hass: HomeAssistant) -> None:
    websocket_api.async_register_command(hass, ws_overview)
    websocket_api.async_register_command(hass, ws_subscribe)
    websocket_api.async_register_command(hass, ws_run_checks)
    websocket_api.async_register_command(hass, ws_dismiss_finding)
    websocket_api.async_register_command(hass, ws_restore_finding)


def _loaded_entry(hass: HomeAssistant):
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is ConfigEntryState.LOADED:
            return entry
    return None


def _runtime(hass: HomeAssistant):
    entry = _loaded_entry(hass)
    return entry.runtime_data if entry else None


async def _build_overview(hass: HomeAssistant) -> dict[str, Any] | None:
    data = _runtime(hass)
    if data is None:
        return None
    auth = await data.auth.async_snapshot()
    network = data.network.data
    current = await async_run_checks(hass, auth)
    # Forget dismissals of findings that went away (e.g. MFA got enabled), so
    # they don't silently hide the finding if it ever comes back
    if gone := data.dismissed.keys() - {f["id"] for f in current}:
        for fid in gone:
            del data.dismissed[fid]
        data.store.async_save_soon()
    findings, dismissed = split_dismissed(current, data.dismissed)
    return {
        # Dismissed findings don't count toward the score
        "score": score_from_findings(findings),
        "findings": findings,
        "dismissed_findings": dismissed,
        "auth": auth,
        "network": asdict(network) if network else None,
    }


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): WS_OVERVIEW})
@websocket_api.async_response
async def ws_overview(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """One-shot fetch of everything the dashboard shows."""
    overview = await _build_overview(hass)
    if overview is None:
        connection.send_error(msg["id"], "not_loaded", "Security Monitor is not set up")
        return
    connection.send_result(msg["id"], overview)


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): WS_SUBSCRIBE})
@callback
def ws_subscribe(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Push a fresh overview whenever new auth events or scan results arrive."""

    async def _push() -> None:
        if (overview := await _build_overview(hass)) is not None:
            connection.send_message(websocket_api.event_message(msg["id"], overview))

    @callback
    def _on_update() -> None:
        hass.async_create_task(_push())

    connection.subscriptions[msg["id"]] = async_dispatcher_connect(
        hass, SIGNAL_UPDATED, _on_update
    )
    connection.send_result(msg["id"])
    hass.async_create_task(_push())


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): WS_RUN_CHECKS})
@websocket_api.async_response
async def ws_run_checks(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Rescan connections, re-run checks and refresh Repairs now."""
    entry = _loaded_entry(hass)
    if entry is None:
        connection.send_error(msg["id"], "not_loaded", "Security Monitor is not set up")
        return
    await entry.runtime_data.network.async_refresh()  # fires SIGNAL_UPDATED → subscribers get fresh data
    await async_check_issues(hass, entry)
    connection.send_result(msg["id"], await _build_overview(hass))


async def _after_dismissal_change(hass: HomeAssistant, entry) -> None:
    """Save, update Repairs and push the new overview to open panels."""
    entry.runtime_data.store.async_save_soon()
    await async_check_issues(hass, entry)
    async_dispatcher_send(hass, SIGNAL_UPDATED)


@websocket_api.require_admin
@websocket_api.websocket_command(
    {vol.Required("type"): WS_DISMISS_FINDING, vol.Required("finding_id"): str}
)
@websocket_api.async_response
async def ws_dismiss_finding(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Accept a finding on purpose: hide it and leave it out of the score."""
    entry = _loaded_entry(hass)
    if entry is None:
        connection.send_error(msg["id"], "not_loaded", "Security Monitor is not set up")
        return
    data = entry.runtime_data
    findings = await async_run_checks(hass, await data.auth.async_snapshot())
    finding = next((f for f in findings if f["id"] == msg["finding_id"]), None)
    if finding is None or not finding["dismissible"]:
        connection.send_error(msg["id"], "not_found", "No such finding, or it can't be dismissed")
        return
    # Remember the parameters: the dismissal lapses when the finding changes
    data.dismissed[finding["id"]] = {
        "params": finding["params"],
        "dismissed_at": dt_util.utcnow().isoformat(),
    }
    await _after_dismissal_change(hass, entry)
    connection.send_result(msg["id"], await _build_overview(hass))


@websocket_api.require_admin
@websocket_api.websocket_command(
    {vol.Required("type"): WS_RESTORE_FINDING, vol.Required("finding_id"): str}
)
@websocket_api.async_response
async def ws_restore_finding(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Undo a dismissal."""
    entry = _loaded_entry(hass)
    if entry is None:
        connection.send_error(msg["id"], "not_loaded", "Security Monitor is not set up")
        return
    entry.runtime_data.dismissed.pop(msg["finding_id"], None)
    await _after_dismissal_change(hass, entry)
    connection.send_result(msg["id"], await _build_overview(hass))
