# Security Dashboard for Home Assistant

A HACS integration that adds an admin-only **Security** panel to the sidebar:

- **Access log**: failed logins, IP bans and token usage (who, from which IP, when)
- **Tokens**: every refresh / long-lived token, last use, stale-token detection
- **Connections**: established connections to external hosts, with reverse DNS
- **Findings + score**: MFA coverage, IP banning, HTTPS on the external URL, custom integrations
- **Repairs**: important findings also appear under Settings → Repairs
- **Sensors**: `sensor.security_dashboard_failed_logins_24h` and `sensor.security_dashboard_outbound_connections` for automations

## Layout

```
custom_components/security_dashboard/
├── __init__.py          # setup, static path + sidebar panel registration
├── manifest.json
├── const.py
├── config_flow.py       # single-instance, zero-config
├── auth_monitor.py      # ban-logger handler + hass.auth token/MFA snapshot
├── coordinator.py       # psutil connection scan (executor) every 30 s
├── checks.py            # hygiene findings + score
├── repairs.py           # mirrors findings into the Repairs UI
├── websocket_api.py     # security_dashboard/overview and /subscribe (admin only)
├── sensor.py
├── strings.json / translations/en.json
└── frontend/
    └── security-dashboard-panel.js   # the bundled dashboard (no build step)
```

## How the bundled dashboard works

1. `async_setup` serves `frontend/` at `/security_dashboard_static/`.
2. `async_setup_entry` calls `panel_custom.async_register_panel(...)` with
   `require_admin=True`, pointing at the JS module. HA adds a sidebar item.
3. The web component subscribes to `security_dashboard/subscribe` and re-renders
   whenever the integration dispatches `SIGNAL_UPDATED` (new auth event or scan).

## Known limits

- `hass.auth` and the http ban internals are not public API. Pin a minimum HA
  version and test against betas.
- Failed logins are captured by attaching a handler to the
  `homeassistant.components.http.ban` logger. If that log message changes, the
  parser needs updating.
- Connection visibility depends on the install type. On HA OS you see host-wide
  sockets but cannot attribute add-on traffic. Short-lived connections between
  polls are missed. For full coverage, add a companion add-on (conntrack) or
  pull DNS logs from Pi-hole / AdGuard Home.
- Reverse DNS lookups run in the executor and are cached. Slow resolvers can
  delay a scan.

## Ideas for next steps

- Persist the access log with `homeassistant.helpers.storage.Store` so it survives restarts
- GeoIP lookup (offline MaxMind DB) for access-log IPs
- Options flow: scan interval, stale-token threshold, allowlist of known destinations
- Alert on first-seen destinations or a new IP using a token
- Companion add-on that streams conntrack events to the integration
