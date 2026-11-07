"""Security Dashboard for Home Assistant.

Collects access/auth events, token hygiene and outbound network connections,
exposes them over the websocket API and as entities, and bundles a sidebar
panel that renders the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from . import websocket_api
from .auth_monitor import AuthMonitor
from .const import (
    DOMAIN,
    PANEL_ICON,
    PANEL_JS,
    PANEL_TITLE,
    PANEL_URL_PATH,
    PANEL_WEBCOMPONENT,
    STATIC_URL,
)
from .coordinator import NetworkCoordinator
from .repairs import async_check_issues

PLATFORMS: list[Platform] = [Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass
class SecurityData:
    """Runtime data stored on the config entry."""

    auth: AuthMonitor
    network: NetworkCoordinator


type SecurityConfigEntry = ConfigEntry[SecurityData]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register things that live for the whole HA run (once, not per entry)."""
    websocket_api.async_register(hass)

    # Serve the bundled frontend: /security_dashboard_static/<file>
    frontend_dir = Path(__file__).parent / "frontend"
    await hass.http.async_register_static_paths(
        [StaticPathConfig(STATIC_URL, str(frontend_dir), cache_headers=False)]
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: SecurityConfigEntry) -> bool:
    """Set up the integration from a config entry."""
    auth = AuthMonitor(hass)
    await auth.async_start()

    network = NetworkCoordinator(hass, entry)
    await network.async_config_entry_first_refresh()

    entry.runtime_data = SecurityData(auth=auth, network=network)
    entry.async_on_unload(auth.async_stop)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Bundled dashboard: an admin-only sidebar panel backed by our web component
    await panel_custom.async_register_panel(
        hass,
        frontend_url_path=PANEL_URL_PATH,
        webcomponent_name=PANEL_WEBCOMPONENT,
        sidebar_title=PANEL_TITLE,
        sidebar_icon=PANEL_ICON,
        module_url=f"{STATIC_URL}/{PANEL_JS}?v={entry.entry_id[:8]}",
        require_admin=True,
        config={"entry_id": entry.entry_id},
    )

    # Surface findings (no MFA, stale tokens, ip_ban disabled…) in Settings → Repairs
    await async_check_issues(hass, entry)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SecurityConfigEntry) -> bool:
    """Unload a config entry."""
    frontend.async_remove_panel(hass, PANEL_URL_PATH)
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
