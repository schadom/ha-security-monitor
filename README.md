# Security Dashboard integration

[![GitHub Release][releases-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![License][license-shield]](LICENSE)
[![hacs][hacsbadge]][hacs]

> [!IMPORTANT]
> This integration is not affiliated with the Home Assistant project or Nabu Casa and is provided as-is and without warranty. It helps you spot problems; it does not make your installation secure on its own.

Adds an admin-only **Security** panel to the Home Assistant sidebar. It shows who
accessed your instance, which tokens are in use, which internet hosts Home
Assistant talks to and which integration is behind each connection, together
with a security score and concrete findings.

## What it shows

| Area | Source | Details |
| --- | --- | --- |
| Access log | HA's login and ban handling | Failed logins, IP bans and token use, with source IP and user |
| Failed logins chart | Access log | Failed logins per hour for the last 24 hours, peak hour and top source IP |
| Tokens | HA's auth system | Every session and long-lived token, last use and last IP; long-lived tokens unused for 90 days are marked stale |
| Connections | Socket scan + HTTP tracing | Open connections to internet hosts and a 24-hour history with first and last seen, labelled with the integration that made them |
| Findings | Configuration checks | Users without MFA, stale tokens, IP banning disabled, plain-HTTP external URL, failed-login bursts, custom integrations |
| Repairs | Findings | Important findings also appear in **Settings > Repairs** |

The access log and the connection history are stored on disk, so they survive
restarts.

## Screenshot

![demo]

The **Connections** tab, **Last 24 h** view:

![connections]

## Installation with HACS

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=schadom&repository=hacs_security_dashboard&category=integration)

1. Add this repository as a custom repository of category **Integration**.
2. Install **Security Dashboard** and restart Home Assistant.
3. In **Settings > Devices & services > Add integration**, add **Security Dashboard**.
   There is nothing to configure.
4. Open **Security** in the sidebar. The panel is only visible to administrators.

To install manually, copy `custom_components/security_dashboard` into the
`custom_components` folder of your Home Assistant configuration and restart.

Requires Home Assistant **2026.2.0** or newer.

### Entities

The integration adds a **Security Dashboard** service device with two sensors
for use in automations:

- `sensor.security_dashboard_failed_logins_24h`: failed logins in the last 24 hours
- `sensor.security_dashboard_outbound_connections`: connections to internet hosts
  open right now. The attribute `top_destinations` lists the busiest hosts.

## Removal

1. In **Settings > Devices & services**, open **Security Dashboard**, open the
   entry's menu and choose **Delete**. This removes the panel, the sensors and the
   stored history.
2. To remove the integration completely, uninstall **Security Dashboard** in HACS
   (or delete `custom_components/security_dashboard`) and restart Home Assistant.

## How it works

**Access log.** Home Assistant logs every failed login and IP ban as a warning.
The integration reads those log records and records the source IP. Token use
comes from the `last_used_at` and `last_used_ip` fields of each token. If your
`logger:` configuration hides warnings, the integration sets only the
`homeassistant.components.http.ban` logger back to warning, so failed logins
also appear in your Home Assistant log.

**Connections.** Every 30 seconds the integration lists established connections
to internet addresses. LAN and loopback addresses are ignored. On its own, a
socket scan only shows an IP address and a reverse-DNS name, which for cloud
services is usually a hosting provider such as `ec2-…amazonaws.com`.

**Which integration talks to which host.** The integration also traces Home
Assistant's HTTP client (aiohttp). For each request it records the hostname,
the integration that made the request and the IP address the connection went
to. That lets the panel show `openapi.tuyaeu.com` and **Tuya** instead of an
Amazon hostname. Requests made by a library on its own are assigned to the
integration that requires that library.

**New destinations.** Hosts first seen during the first hour of monitoring are
the baseline. Hosts that appear later are marked **New** for 24 hours.

**Storage.** History is kept in `.storage/security_dashboard.history`. It is
saved every 5 minutes and when Home Assistant stops, and deleted when you
remove the integration.

**Privacy.** Everything stays on your Home Assistant instance. Only hostnames,
IP addresses, integration names, counts and timestamps are stored, never URLs,
paths, query strings, headers or request bodies.

## Local Docker testing

Install and start Docker Desktop on macOS, or Docker Engine with Compose on Linux.
From this repository, start the pinned Home Assistant **2026.10.3** image:

```sh
docker compose up -d
```

Open <http://localhost:8123>, complete Home Assistant onboarding, then add
**Security Dashboard**. The test configuration enables IP banning after five
failed attempts and debug logging for the integration.

To produce access-log entries, log out and sign in with a wrong password a few
times, or call the API with an invalid token:

```sh
curl -s -H "Authorization: Bearer invalid" http://localhost:8123/api/states
```

Inside the container, the socket scan only sees the container's own network.
Integrations that reach the internet, such as **Met.no**, produce traced
connections in the **Connections** tab.

The UI binds only to `127.0.0.1`. If port 8123 is occupied, use
`HA_PORT=8124 docker compose up -d` and open port 8124. HA state is retained in a
Docker volume; the integration source is mounted read-only from this checkout.
No HACS installation is needed inside this test HA.

```sh
docker compose logs --tail=100 homeassistant
docker compose restart homeassistant
docker compose down
```

Restart Home Assistant after Python changes. Reload the browser after changes
to the panel. `down` retains your test configuration; adding `--volumes`
permanently deletes it.

## Development checks

Use Python 3.13. The test dependencies pin Home Assistant to the version the
tests were run against.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check custom_components tests
docker compose config --quiet
```

The **Validate** workflow runs these checks on every push and pull request,
weekly, and on demand, together with the HACS and hassfest validations.
Coverage must stay at 90% or higher.

Tests exercise the config flow, panel registration, static files, sensors, the
websocket API and live subscription, unload and reload, log parsing for real
Home Assistant log formats, the 24-hour destination history, HTTP tracing and
attribution against a local server, and persistence across a reload.

## Known limitations

- **Private APIs.** The integration relies on parts of Home Assistant and
  aiohttp that are not public API: the auth system, the ban logger's message
  format, `ClientSession._request` and `TCPConnector._create_direct_connection`.
  A Home Assistant or aiohttp update can break these. Test against beta
  releases before updating production systems.
- **Only aiohttp traffic is attributed.** Connections from libraries that use
  `requests`, MQTT, raw sockets, add-ons and the host system show as
  **Unattributed**.
- **Connections opened before the integration starts** stay unattributed until
  they reconnect. Integrations that open a long-lived connection during startup
  are labelled after the next reconnect or restart.
- **Short-lived connections between scans** are missed by the socket scan.
  aiohttp requests are still counted by the tracing.
- **Visibility depends on the installation type.** On Home Assistant OS the
  scan sees the whole host network but cannot attribute add-on traffic. In
  Container installations it sees only the container's network.
- **Reverse DNS lookups** run in the background and are cached. A slow DNS
  server delays scans.

## Troubleshooting

- **The Security panel does not appear.** The panel is only shown to
  administrators. Check that the integration is set up under **Settings >
  Devices & services**.
- **The panel shows an old version after an update.** Restart Home Assistant,
  then reload the browser page.
- **No failed logins are recorded.** Check that the `homeassistant.components.http.ban`
  logger is not set to `error` or higher in an automation or in the
  **logger.set_level** action; the integration only adjusts it at startup.
- **Many connections are unattributed.** See [Known limitations](#known-limitations).
  Restart Home Assistant once after installing so that long-lived connections are
  traced from the start.
- **Enable debug logging** to see what the integration records:

  ```yaml
  logger:
    logs:
      custom_components.security_dashboard: debug
  ```

[hacs_security_dashboard]: https://github.com/schadom/hacs_security_dashboard
[commits-shield]: https://img.shields.io/github/commit-activity/y/schadom/hacs_security_dashboard.svg?style=for-the-badge
[commits]: https://github.com/schadom/hacs_security_dashboard/commits/main
[hacs]: https://github.com/hacs/integration
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/schadom/hacs_security_dashboard.svg?style=for-the-badge
[demo]: https://raw.githubusercontent.com/schadom/hacs_security_dashboard/refs/heads/main/demo.png
[connections]: https://raw.githubusercontent.com/schadom/hacs_security_dashboard/refs/heads/main/connections.png
[releases-shield]: https://img.shields.io/github/release/schadom/hacs_security_dashboard.svg?style=for-the-badge
[releases]: https://github.com/schadom/hacs_security_dashboard/releases
