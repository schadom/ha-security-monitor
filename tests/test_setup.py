"""Smoke test: load the integration in a real HA core and exercise it."""

import logging


from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

DOMAIN = "security_monitor"


async def test_full_flow(hass: HomeAssistant, hass_ws_client, hass_client, hass_admin_user):
    assert await async_setup_component(hass, "http", {})
    # Simulate `logger: default: error`
    logging.getLogger("homeassistant.components.http.ban").setLevel(logging.ERROR)

    # Config flow
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    assert result["type"] == "form", result
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == "create_entry", result
    await hass.async_block_till_done()

    entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert entry.state is ConfigEntryState.LOADED

    # Panel registered
    panels = hass.data["frontend_panels"]
    assert "security-monitor" in panels
    print("panel:", panels["security-monitor"].to_response())

    # Sensors
    states = sorted(s.entity_id for s in hass.states.async_all("sensor"))
    print("sensors:", states)
    assert states == [
        "sensor.security_monitor_failed_logins_24h",
        "sensor.security_monitor_outbound_connections",
    ]

    # Panel JS is served
    http = await hass_client()
    resp = await http.get("/security_monitor_static/security-monitor-panel.js")
    assert resp.status == 200
    assert "customElements.define" in await resp.text()

    # Real HA log formats: hostname resolved, IP only, and a ban
    ban = logging.getLogger("homeassistant.components.http.ban")
    ban.warning("Login attempt or request with invalid authentication from scanner.example.net (203.0.113.47). Requested URL: '/auth/login_flow'. (curl/8.0)")
    ban.warning("Login attempt or request with invalid authentication from 198.51.100.9 (198.51.100.9). Requested URL: '/api/states'. (Mozilla/5.0 (X11))")
    ban.warning("Banned IP %s for too many login attempts", "203.0.113.47")
    await hass.async_block_till_done()
    await hass.async_block_till_done()

    # Websocket overview
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "security_monitor/overview"})
    msg = await client.receive_json()
    assert msg["success"], msg
    res = msg["result"]
    print("score:", res["score"], "findings:", [f["id"] for f in res["findings"]])
    # Each finding carries a translation key and its parameters for the panel
    assert all(f["key"] and isinstance(f["params"], dict) for f in res["findings"])
    print("events:", res["auth"]["events"])
    print("users:", res["auth"]["users"])
    ev = res["auth"]["events"]
    a = res["auth"]
    assert a["failed_logins_24h"] == 2  # bans are counted separately
    assert a["failed_sources_24h"] == 2 and a["banned_24h"] == 1
    assert sum(a["failed_hourly"]) == 2 and len(a["failed_hourly"]) == 24
    assert a["failed_hourly"][23] == 2
    assert [(e["kind"], e["ip"]) for e in ev] == [
        ("banned", "203.0.113.47"),
        ("failed_login", "198.51.100.9"),
        ("failed_login", "203.0.113.47"),
    ]
    assert all("curl" not in e["detail"] and "Mozilla" not in e["detail"] for e in ev)
    assert hass.states.get("sensor.security_monitor_failed_logins_24h").state == "2"

    # Run checks
    await client.send_json({"id": 2, "type": "security_monitor/run_checks"})
    msg = await client.receive_json()
    assert msg["success"], msg
    assert msg["result"]["network"]["scanned_at"]

    # 24 h destination tracking: baseline host, then a new one
    from custom_components.security_monitor.coordinator import NetworkSnapshot
    coord = entry.runtime_data.network

    def conn(host, ip, lport):
        return {"remote_ip": ip, "remote_port": 443, "hostname": host, "local_port": lport, "process": "python3"}

    from datetime import timedelta
    from homeassistant.util import dt as dt_util
    now = dt_util.utcnow()
    coord.tracer.hosts = {}
    coord._sockets, coord._hosts = {}, {}

    # During the learning period nothing is flagged as new
    coord.monitoring_since = now
    s1 = NetworkSnapshot(scanned_at="x", connections=[conn("a.example", "192.0.2.1", 1000)])
    coord._track(s1)
    assert s1.learning_until and s1.new_destinations_24h == 0

    # After it: a.example is old, 192.0.2.88 appears → new
    coord.monitoring_since = now - timedelta(days=2)
    coord._hosts["a.example"]["first_seen"] = (now - timedelta(days=3)).isoformat()
    s2 = NetworkSnapshot(scanned_at="x", connections=[
        conn("a.example", "192.0.2.1", 1000),   # same socket, not recounted
        conn("a.example", "192.0.2.1", 1001),   # new socket to a known host
        conn(None, "192.0.2.88", 1002),         # new host without rDNS
    ])
    coord._track(s2)
    print("destinations_24h:", s2.destinations_24h)
    by_host = {x["host"]: x for x in s2.destinations_24h}
    assert by_host["a.example"]["connections"] == 2 and not by_host["a.example"]["new"]
    assert by_host["192.0.2.88"]["new"] and s2.new_destinations_24h == 1
    assert s2.learning_until is None

    # Traced peer IP labels the socket with hostname + integration
    coord.tracer.ip_map["192.0.2.1"] = {"host": "api.vendor.example", "integration": "vendor", "ts": 9e12}
    s3 = NetworkSnapshot(scanned_at="x", connections=[conn("ec2-192-0-2-1.compute.example", "192.0.2.1", 1003)])
    coord._track(s3)
    assert s3.connections[0]["traced_host"] == "api.vendor.example"
    assert s3.connections[0]["integration"] == "vendor"

    # Subscription pushes data
    await client.send_json({"id": 3, "type": "security_monitor/subscribe"})
    msg = await client.receive_json()
    assert msg["success"], msg
    msg = await client.receive_json()
    assert msg["type"] == "event" and "score" in msg["event"]

    # Unload + reload
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert "security-monitor" not in hass.data["frontend_panels"]
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
