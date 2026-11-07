"""HTTP tracing attribution and persistence across a reload."""

import importlib.util
import logging
from pathlib import Path

import aiohttp
from aiohttp import web
from pytest_homeassistant_custom_component.common import MockConfigEntry

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

DOMAIN = "security_monitor"


def _load_fake_integration():
    # Lives under .../custom_components/fake_cloud/ so the tracer sees an integration
    path = Path(__file__).parent / "fixtures/custom_components/fake_cloud/api.py"
    spec = importlib.util.spec_from_file_location("fake_cloud_api", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def test_tracer_and_persistence(hass: HomeAssistant, hass_storage, socket_enabled):
    assert await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(domain=DOMAIN, data={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    data = entry.runtime_data

    # Local HTTP server standing in for a cloud API
    async def _ok(request):
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/v1/status", _ok)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    # The test server is on loopback, which the tracer skips by default
    data.tracer.include_local = True
    fake = _load_fake_integration()
    async with aiohttp.ClientSession() as session:  # a session HA doesn't know about
        assert await fake.fetch(session, f"http://localhost:{port}/v1/status?token=SECRET") == "ok"
        assert await fake.fetch(session, f"http://localhost:{port}/v1/status") == "ok"
    await runner.cleanup()

    host = data.tracer.hosts["localhost"]
    print("traced:", host)
    assert host["integrations"] == {"fake_cloud": 2}
    assert data.tracer.lookup_ip("127.0.0.1") == {"host": "localhost", "integration": "fake_cloud"}
    stored = repr(data.tracer.as_dict())
    assert "SECRET" not in stored and "/v1/status" not in stored  # no URLs persisted

    h24 = data.tracer.hosts_24h()
    assert h24[0]["host"] == "localhost" and h24[0]["requests"] == 2

    # Library label → integration via requirements
    data.tracer._lib_to_domain = {"pyfakecloud": "fake_cloud"}
    assert data.tracer.display_integration("lib:pyfakecloud") == "fake_cloud"
    assert data.tracer.display_integration("lib:unknownlib") == "lib:unknownlib"

    # An access-log event, then unload (saves) and reload (restores)
    logging.getLogger("homeassistant.components.http.ban").warning(
        "Login attempt or request with invalid authentication from 198.51.100.9 (198.51.100.9). Requested URL: '/api/states'. (x)"
    )
    await hass.async_block_till_done()
    since = data.network.monitoring_since
    data.tracer.include_local = False

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    import aiohttp as _a
    assert not getattr(_a.ClientSession._request, "_security_monitor_tracer", False), "tracer not removed"

    saved = hass_storage[f"{DOMAIN}.history"]["data"]
    assert saved["auth"]["events"][0]["ip"] == "198.51.100.9"
    assert "localhost" in saved["http"]["hosts"]

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    data = entry.runtime_data
    assert data.auth.events[0].ip == "198.51.100.9"
    assert data.tracer.hosts["localhost"]["integrations"] == {"fake_cloud": 2}
    assert data.network.monitoring_since == since
    snap = await data.auth.async_snapshot()
    assert snap["failed_logins_24h"] == 1  # chart and counters survive the restart

    # Removing the integration deletes the history
    assert await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert f"{DOMAIN}.history" not in hass_storage


async def test_imports_history_from_security_dashboard(hass: HomeAssistant, hass_storage):
    """First start after the rename takes over the old integration's history."""
    hass_storage["security_dashboard.history"] = {
        "version": 1,
        "minor_version": 1,
        "key": "security_dashboard.history",
        "data": {
            "auth": {"events": [{"timestamp": "2026-11-07T01:00:00+00:00", "kind": "failed_login",
                                 "ip": "203.0.113.47", "user": None, "detail": "Invalid"}]},
            "network": {"monitoring_since": "2026-11-01T00:00:00+00:00", "sockets": [], "hosts": {}},
            "http": {"hosts": {"api.github.com": {"integrations": {"hacs": 3}, "first_seen": "2026-11-01T00:00:00+00:00",
                                                  "last_seen": "2026-11-07T01:00:00+00:00", "hourly": {}}},
                     "ip_map": {}},
        },
    }
    assert await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(domain=DOMAIN, data={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    data = entry.runtime_data
    assert data.auth.events[0].ip == "203.0.113.47"
    assert data.network.monitoring_since.isoformat() == "2026-11-01T00:00:00+00:00"
    assert "api.github.com" in data.tracer.hosts
    assert f"{DOMAIN}.history" in hass_storage
    assert "security_dashboard.history" not in hass_storage  # old integration isn't loaded

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()


async def test_tracer_unhooks_without_removing_later_wrappers(hass: HomeAssistant):
    """If something wrapped aiohttp after us, stop() must not remove it."""
    from custom_components.security_monitor.connection_tracer import ConnectionTracer

    original = aiohttp.ClientSession._request
    tracer = ConnectionTracer(hass)
    tracer.start()
    ours = aiohttp.ClientSession._request

    async def later_wrapper(*args, **kwargs):
        return await ours(*args, **kwargs)

    aiohttp.ClientSession._request = later_wrapper
    try:
        tracer.stop()
        assert aiohttp.ClientSession._request is later_wrapper  # left alone
        assert tracer._active is False  # ours is now a pass-through
    finally:
        aiohttp.ClientSession._request = original

    # Normal case: nothing on top → original methods are restored
    tracer2 = ConnectionTracer(hass)
    tracer2.start()
    tracer2.stop()
    assert aiohttp.ClientSession._request is original
