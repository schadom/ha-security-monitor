"""Websocket commands consumed by the bundled panel (admin only)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .checks import async_run_checks, score_from_findings
from .const import DOMAIN, SIGNAL_UPDATED, WS_OVERVIEW, WS_SUBSCRIBE


@callback
def async_register(hass: HomeAssistant) -> None:
    websocket_api.async_register_command(hass, ws_overview)
    websocket_api.async_register_command(hass, ws_subscribe)


def _runtime(hass: HomeAssistant):
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is ConfigEntryState.LOADED:
            return entry.runtime_data
    return None


async def _build_overview(hass: HomeAssistant) -> dict[str, Any] | None:
    data = _runtime(hass)
    if data is None:
        return None
    auth = await data.auth.async_snapshot()
    network = data.network.data
    findings = await async_run_checks(hass, auth)
    return {
        "score": score_from_findings(findings),
        "findings": findings,
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
        connection.send_error(msg["id"], "not_loaded", "Security Dashboard is not set up")
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
