"""Constants for the Security Dashboard integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "security_dashboard"

# Frontend panel
PANEL_URL_PATH: Final = "security-dashboard"
PANEL_TITLE: Final = "Security Monitor"
PANEL_ICON: Final = "mdi:shield-lock-outline"
PANEL_WEBCOMPONENT: Final = "security-dashboard-panel"
STATIC_URL: Final = f"/{DOMAIN}_static"
PANEL_JS: Final = "security-dashboard-panel.js"

# Collection
NETWORK_SCAN_INTERVAL: Final = timedelta(seconds=30)
AUTH_EVENT_BUFFER: Final = 500  # max auth events kept in memory
STALE_TOKEN_DAYS: Final = 90

# Logger that HA's http ban middleware writes failed-login warnings to
BAN_LOGGER: Final = "homeassistant.components.http.ban"

# Websocket command types
WS_OVERVIEW: Final = f"{DOMAIN}/overview"
WS_AUTH_LOG: Final = f"{DOMAIN}/auth_log"
WS_CONNECTIONS: Final = f"{DOMAIN}/connections"
WS_SUBSCRIBE: Final = f"{DOMAIN}/subscribe"
WS_RUN_CHECKS: Final = f"{DOMAIN}/run_checks"

# Dispatcher signal fired whenever new auth events or scan results arrive
SIGNAL_UPDATED: Final = f"{DOMAIN}_updated"
