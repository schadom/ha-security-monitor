"""Connection attribution through the Python audit hook (not only aiohttp)."""

import asyncio
import importlib.util
from pathlib import Path

import aiohttp
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.security_monitor.connection_tracer import ConnectionTracer
from homeassistant.config_entries import current_entry
from homeassistant.core import HomeAssistant


def _load_fake_integration():
    # Lives under .../custom_components/fake_cloud/ so the tracer sees an integration
    path = Path(__file__).parent / "fixtures/custom_components/fake_cloud/api.py"
    spec = importlib.util.spec_from_file_location("fake_cloud_api_attr", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _start_server():
    handlers: set[asyncio.Task] = set()

    async def _handle(reader, writer):
        handlers.add(asyncio.current_task())
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    server.handlers = handlers
    return server, server.sockets[0].getsockname()[1]


async def _stop_server(server) -> None:
    # Let accepted connections finish before closing, or asyncio warns on cleanup
    for _ in range(20):
        await asyncio.sleep(0)
    if server.handlers:
        await asyncio.gather(*server.handlers, return_exceptions=True)
    server.close()
    await server.wait_closed()


def _connects(tracer: ConnectionTracer) -> dict[str, int]:
    tracer.process_pending()
    stats = tracer.connects.get("127.0.0.1", {"integrations": {}})
    return dict(stats["integrations"])


async def test_plain_socket_in_executor_thread(hass: HomeAssistant, socket_enabled):
    """requests/urllib3-style traffic: attributed via the integration frame on the stack."""
    tracer = ConnectionTracer(hass)
    tracer.include_local = True
    tracer.start()
    server, port = await _start_server()
    try:
        assert tracer.capabilities["audit_hook"] is True
        fake = _load_fake_integration()
        await hass.async_add_executor_job(fake.blocking_connect, "127.0.0.1", port)
        assert _connects(tracer) == {"fake_cloud": 1}
        assert tracer.lookup_ip("127.0.0.1") == {"host": None, "integration": "fake_cloud"}
    finally:
        await _stop_server(server)
        tracer.stop()


async def test_raw_asyncio_connection(hass: HomeAssistant, socket_enabled):
    """MQTT/websocket-style traffic over raw asyncio streams."""
    tracer = ConnectionTracer(hass)
    tracer.include_local = True
    tracer.start()
    server, port = await _start_server()
    try:
        fake = _load_fake_integration()
        await fake.asyncio_connect("127.0.0.1", port)
        assert _connects(tracer) == {"fake_cloud": 1}
    finally:
        await _stop_server(server)
        tracer.stop()


async def test_background_task_attributed_by_config_entry(hass: HomeAssistant, socket_enabled):
    """No integration code on the stack: the task inherited HA's current_entry."""
    tracer = ConnectionTracer(hass)
    tracer.include_local = True
    tracer.start()
    server, port = await _start_server()

    async def _poll():  # defined in the test file, so no integration frame
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()

    try:
        token = current_entry.set(MockConfigEntry(domain="vendor_cloud"))
        task = asyncio.ensure_future(_poll())  # copies the context, like setup-time tasks
        current_entry.reset(token)
        await task
        assert _connects(tracer) == {"vendor_cloud": 1}
    finally:
        await _stop_server(server)
        tracer.stop()


async def test_hostname_from_dns_lookup(hass: HomeAssistant, socket_enabled):
    """An IP seen only by the audit hook gets its name from a recent DNS lookup."""
    tracer = ConnectionTracer(hass)
    tracer.include_local = True  # Python counts documentation IPs (192.0.2.0/24) as private
    tracer.start()
    try:
        fake = _load_fake_integration()
        await hass.async_add_executor_job(fake.lookup, "security-monitor-test.invalid")
        tracer.process_pending()
        assert tracer._lookups["security-monitor-test.invalid"][0] == "fake_cloud"

        # A connection to a public IP, as the audit hook would queue it
        tracer._pending.append(("connect", "192.0.2.10", "fake_cloud"))
        tracer._pending.append(("lookup", "api.vendor.example", "fake_cloud"))
        tracer.process_pending()
        assert "192.0.2.10" in tracer.connects

        tracer._resolve_all = lambda hosts: {"api.vendor.example": {"192.0.2.10"}}
        await tracer.async_enrich()
        assert tracer.lookup_ip("192.0.2.10") == {"host": "api.vendor.example", "integration": "fake_cloud"}
        assert "192.0.2.10" not in tracer.connects  # moved to the hostname
        h24 = {d["host"]: d for d in tracer.hosts_24h()}
        assert h24["api.vendor.example"]["connections"] == 1
        assert h24["api.vendor.example"]["integrations"] == ["fake_cloud"]
    finally:
        tracer.stop()


async def test_own_lookups_and_stopped_tracer_are_ignored(hass: HomeAssistant, socket_enabled):
    tracer = ConnectionTracer(hass)
    tracer.include_local = True
    tracer.start()
    server, port = await _start_server()
    try:
        # Lookups made by the tracer itself don't count as traffic
        await hass.async_add_executor_job(ConnectionTracer._resolve_all, ["security-monitor-test.invalid"])
        tracer.process_pending()
        assert "security-monitor-test.invalid" not in tracer._lookups

        # After stop the hook stays installed but records nothing
        tracer.stop()
        fake = _load_fake_integration()
        await fake.asyncio_connect("127.0.0.1", port)
        assert not tracer._pending
    finally:
        await _stop_server(server)
        tracer.stop()


async def test_attribution_survives_missing_aiohttp_internals(hass: HomeAssistant, monkeypatch, socket_enabled):
    """If aiohttp's private API moves, only the hostname layer switches off."""
    monkeypatch.delattr(aiohttp.TCPConnector, "_create_direct_connection")
    tracer = ConnectionTracer(hass)
    tracer.include_local = True
    tracer.start()
    server, port = await _start_server()
    try:
        assert tracer.capabilities == {"audit_hook": True, "aiohttp": False}
        fake = _load_fake_integration()
        await fake.asyncio_connect("127.0.0.1", port)
        assert _connects(tracer) == {"fake_cloud": 1}
    finally:
        await _stop_server(server)
        tracer.stop()
