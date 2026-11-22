"""MFA findings for service accounts, and dismissing findings."""

from datetime import timedelta

import pytest
from pytest_homeassistant_custom_component.common import register_auth_provider

from homeassistant.auth.models import TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN, Credentials
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component

from custom_components.security_monitor.checks import (
    FINDING_KEYS,
    _finding,
    _user_finding,
    is_dismissed,
    score_from_findings,
    split_dismissed,
)

DOMAIN = "security_monitor"


def _user(**overrides):
    user = {
        "id": "u1", "name": "claude", "is_active": True, "is_admin": False, "local_only": False,
        "mfa_enabled": False, "password_login": True, "service_account": False, "mfa_applies": True,
    }
    user.update(overrides)
    return user


# ---------------------------------------------------------------- user findings


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, ("no_mfa", "medium")),
        ({"is_admin": True}, ("no_mfa", "high")),
        ({"service_account": True}, ("service_account", "low")),
        ({"service_account": True, "is_admin": True}, ("service_account_admin", "medium")),
        ({"service_account": True, "is_admin": True, "local_only": True},
         ("service_account_admin_local", "medium")),
        ({"mfa_enabled": True}, None),
        ({"is_active": False}, None),
        ({"mfa_applies": False}, None),  # no password login, trusted networks, local-only non-admin
    ],
)
def test_user_finding(overrides, expected):
    finding = _user_finding(_user(**overrides))
    if expected is None:
        assert finding is None
        return
    assert (finding["key"], finding["severity"]) == expected
    assert finding["key"] in FINDING_KEYS
    assert finding["params"] == {"user": "claude"}
    assert finding["dismissible"]
    # Stable across renames: the ID uses the user ID, not the name
    assert finding["id"].endswith("_u1")


def test_service_accounts_get_other_advice_than_totp():
    finding = _user_finding(_user(service_account=True, is_admin=True))
    assert "TOTP" not in finding["detail"]
    assert "admin rights" in finding["detail"] and "local-only" in finding["detail"]
    local = _user_finding(_user(service_account=True, is_admin=True, local_only=True))
    assert "local-only" not in local["detail"]  # already is


# ---------------------------------------------------------------- dismissing


def test_dismissal_covers_the_finding_as_it_was():
    custom = _finding("custom_components", "low", "t", "d", "custom_components", {"count": 14})
    dismissed = {"custom_components": {"params": {"count": 14}}}
    assert is_dismissed(custom, dismissed)
    # Fewer is still covered; one more brings it back
    assert is_dismissed({**custom, "params": {"count": 12}}, dismissed)
    assert not is_dismissed({**custom, "params": {"count": 15}}, dismissed)

    mfa = _user_finding(_user(name="ipad"))
    assert is_dismissed(mfa, {mfa["id"]: {"params": {"user": "ipad"}}})
    assert not is_dismissed(mfa, {mfa["id"]: {"params": {"user": "old name"}}})
    assert not is_dismissed(mfa, {})


def test_login_bursts_cannot_be_dismissed():
    burst = _finding("login_burst", "medium", "t", "d", "login_burst", {"count": 12}, dismissible=False)
    assert not is_dismissed(burst, {"login_burst": {"params": {"count": 99}}})


def test_dismissed_findings_leave_the_score():
    high = _user_finding(_user(is_admin=True))
    low = _finding("custom_components", "low", "t", "d", "custom_components", {"count": 3})
    open_, hidden = split_dismissed([high, low], {high["id"]: {"params": high["params"]}})
    assert open_ == [low] and hidden == [high]
    assert score_from_findings(open_) == 97


# ---------------------------------------------------------------- with Home Assistant


async def _add_user(hass, name, *, admin=False, local_only=False, provider=None, tokens=()):
    user = await hass.auth.async_create_user(
        name, group_ids=["system-admin" if admin else "system-users"], local_only=local_only
    )
    if provider is not None:
        cred = Credentials(auth_provider_type=provider.type, auth_provider_id=provider.id,
                           data={"username": name}, is_new=False)
        await hass.auth.async_link_user(user, cred)
    for kind in tokens:
        if kind == "long_lived":
            await hass.auth.async_create_refresh_token(
                user, client_name=f"{name} token", token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
                access_token_expiration=timedelta(days=3650),
            )
        else:
            await hass.auth.async_create_refresh_token(user, client_id="http://example.local/")
    return user


async def test_users_and_dismissing(hass: HomeAssistant, hass_ws_client, hass_admin_user):
    assert await async_setup_component(hass, "http", {})
    password = await register_auth_provider(hass, {"type": "insecure_example", "users": []})
    trusted = await register_auth_provider(
        hass, {"type": "trusted_networks", "trusted_networks": ["192.168.0.0/24"]}
    )
    await _add_user(hass, "person", provider=password, tokens=["session"])
    await _add_user(hass, "TRMNL feeder", provider=password, tokens=["long_lived"])
    claude = await _add_user(hass, "claude", admin=True, provider=password, tokens=["long_lived"])
    await _add_user(hass, "wall ipad", local_only=True, provider=password, tokens=["session"])
    await _add_user(hass, "kiosk", provider=trusted, tokens=["session"])
    await _add_user(hass, "mcp", tokens=["long_lived"])  # created without a login

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    await hass.config_entries.flow.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries(DOMAIN)[0]

    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "security_monitor/overview"})
    res = (await client.receive_json())["result"]
    users = {u["name"]: u for u in res["auth"]["users"]}
    assert users["TRMNL feeder"]["service_account"] and users["claude"]["service_account"]
    assert not users["person"]["service_account"]
    assert not users["wall ipad"]["mfa_applies"]
    assert not users["kiosk"]["password_login"] and not users["kiosk"]["mfa_applies"]
    assert not users["mcp"]["password_login"] and not users["mcp"]["mfa_applies"]

    by_user = {f["params"].get("user"): f for f in res["findings"] if "user" in f["params"]}
    assert by_user["person"]["key"] == "no_mfa"
    assert by_user["TRMNL feeder"]["key"] == "service_account"
    assert (by_user["claude"]["key"], by_user["claude"]["severity"]) == ("service_account_admin", "medium")
    assert {"wall ipad", "kiosk", "mcp"}.isdisjoint(by_user)
    assert res["dismissed_findings"] == []
    assert all(f["key"] in FINDING_KEYS for f in res["findings"])

    # Dismiss claude's finding: it moves to the dismissed list and the score goes up
    fid = by_user["claude"]["id"]
    assert fid == f"service_account_{claude.id}"
    await client.send_json({"id": 2, "type": "security_monitor/dismiss_finding", "finding_id": fid})
    msg = await client.receive_json()
    assert msg["success"], msg
    after = msg["result"]
    assert fid not in {f["id"] for f in after["findings"]}
    assert [f["id"] for f in after["dismissed_findings"]] == [fid]
    assert after["score"] == res["score"] + 8
    assert fid in entry.runtime_data.dismissed

    # Unknown or non-dismissible findings are refused
    await client.send_json({"id": 3, "type": "security_monitor/dismiss_finding", "finding_id": "nope"})
    msg = await client.receive_json()
    assert not msg["success"] and msg["error"]["code"] == "not_found"

    # The dismissal survives a reload
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert fid in entry.runtime_data.dismissed

    # Restore brings it back
    await client.send_json({"id": 4, "type": "security_monitor/restore_finding", "finding_id": fid})
    msg = await client.receive_json()
    assert msg["success"], msg
    assert fid in {f["id"] for f in msg["result"]["findings"]}
    assert msg["result"]["dismissed_findings"] == []


async def test_dismissed_findings_leave_repairs(hass: HomeAssistant, hass_ws_client, hass_admin_user):
    assert await async_setup_component(hass, "http", {})
    password = await register_auth_provider(hass, {"type": "insecure_example", "users": []})
    user = await _add_user(hass, "old", provider=password, tokens=["long_lived"])
    token = next(iter(user.refresh_tokens.values()))
    token.last_used_at = None  # never used → stale

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    await hass.config_entries.flow.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()
    issues = ir.async_get(hass)
    assert issues.async_get_issue(DOMAIN, "stale_tokens")

    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "security_monitor/dismiss_finding", "finding_id": "stale_tokens"})
    assert (await client.receive_json())["success"]
    assert issues.async_get_issue(DOMAIN, "stale_tokens") is None

    # Once the finding goes away, the dismissal is forgotten
    removed = hass.auth.async_remove_refresh_token(token)
    if removed is not None:  # a coroutine on older Home Assistant versions
        await removed
    await client.send_json({"id": 2, "type": "security_monitor/overview"})
    assert (await client.receive_json())["success"]
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert "stale_tokens" not in entry.runtime_data.dismissed


async def test_mfa_support_without_support_mfa_property(hass: HomeAssistant, monkeypatch):
    """HA 2026.11 removed AuthProvider.support_mfa; setup must not depend on it."""
    from types import SimpleNamespace

    from custom_components.security_monitor.auth_monitor import AuthMonitor

    monitor = AuthMonitor(hass)
    password = Credentials(auth_provider_type="homeassistant", auth_provider_id=None, data={})
    trusted = Credentials(auth_provider_type="trusted_networks", auth_provider_id=None, data={})

    # 2026.11+: providers without the property → decided by provider type
    monkeypatch.setattr(hass.auth, "get_auth_provider", lambda *_: SimpleNamespace(type="x"))
    assert monitor._supports_mfa(password)
    assert not monitor._supports_mfa(trusted)

    # Up to 2026.10: the property wins
    monkeypatch.setattr(hass.auth, "get_auth_provider", lambda *_: SimpleNamespace(support_mfa=False))
    assert not monitor._supports_mfa(password)

    # A broken lookup never raises
    def boom(*_):
        raise RuntimeError("internal API moved")

    monkeypatch.setattr(hass.auth, "get_auth_provider", boom)
    assert monitor._supports_mfa(password)
    assert not monitor._supports_mfa(trusted)
