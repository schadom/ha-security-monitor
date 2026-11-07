# Security Dashboard for Home Assistant

A HACS integration that adds an admin-only **Security** panel to the sidebar:

- **Access log**: failed logins, IP bans and token usage (who, from which IP, when)
- **Tokens**: every refresh / long-lived token, last use, stale-token detection
- **Connections**: what's open now, plus a "last 24 h" view with first/last seen
  dates. Each destination shows the integration that talks to it.
- **History**: the access log and destination history persist across restarts
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
├── coordinator.py       # psutil connection scan every 30 s + rolling 24 h view
├── http_tracer.py       # attributes outbound HTTP traffic to integrations
├── storage.py           # persists access log + destination history
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

## Which integration talks to which host

The integration wraps aiohttp's `ClientSession._request` and
`TCPConnector._create_direct_connection` (both private aiohttp API) at class level, so
every aiohttp session is covered. For each request it records:

- the **hostname** (e.g. `openapi.tuyaeu.com` rather than an `ec2-…amazonaws.com`
  reverse-DNS name),
- the **calling integration**, found by walking the call stack to the first frame
  under `homeassistant/components/<domain>/` or `custom_components/<domain>/`.
  Requests from a library's own background task are mapped to the integration
  that requires that library.
- the **peer IP** of each new TCP connection, so the socket scan can label
  long-lived connections too.

Only hostnames, IPs, integration names, counts and timestamps are kept, never
URLs, paths, query strings, headers or bodies. LAN and loopback traffic is
ignored. Traffic that doesn't use aiohttp (`requests` in executor threads, MQTT,
raw sockets, add-ons, the host OS) still appears in the socket scan, as
"unattributed".

## History and "new" destinations

History is stored in `.storage/security_dashboard.history`. It is saved every
5 minutes and on shutdown, and deleted when you remove the integration.
Destinations first seen during the first hour of monitoring form the baseline.
Only later ones are flagged as new.

## Known limits

- `hass.auth` and the http ban internals are not public API. Pin a minimum HA
  version and test against betas.
- Failed logins are captured by attaching a handler to the
  `homeassistant.components.http.ban` logger. If that log message changes, the
  parser needs updating. If your `logger:` config sets a level above WARNING,
  the integration lowers that one logger to WARNING, so failed logins also
  appear in the HA log.
- Connection visibility depends on the install type. On HA OS you see host-wide
  sockets but cannot attribute add-on traffic. Short-lived connections between
  polls are missed. For full coverage, add a companion add-on (conntrack) or
  pull DNS logs from Pi-hole / AdGuard Home.
- Reverse DNS lookups run in the executor and are cached. Slow resolvers can
  delay a scan.

## Ideas for next steps

- GeoIP lookup (offline MaxMind DB) for access-log IPs
- Options flow: scan interval, stale-token threshold, allowlist of known destinations
- Alert on first-seen destinations or a new IP using a token
- Companion add-on that streams conntrack events to the integration
- Notify when an integration contacts a host for the first time
