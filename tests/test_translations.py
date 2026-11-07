"""Translations stay complete and are picked up by Home Assistant."""

import json
import re
from pathlib import Path

from homeassistant.core import HomeAssistant
from homeassistant.helpers.translation import async_get_translations

DOMAIN = "security_monitor"
INTEGRATION = Path(__file__).parent.parent / "custom_components" / DOMAIN


def _keys(data: dict, prefix: str = "") -> set[str]:
    keys = set()
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        keys |= _keys(value, path) if isinstance(value, dict) else {path}
    return keys


def test_every_language_has_exactly_the_english_keys():
    source = _keys(json.loads((INTEGRATION / "strings.json").read_text(encoding="utf-8")))
    files = sorted((INTEGRATION / "translations").glob("*.json"))
    assert {f.stem for f in files} >= {"en", "de"}
    for file in files:
        keys = _keys(json.loads(file.read_text(encoding="utf-8")))
        assert keys == source, f"{file.name}: missing {sorted(source - keys)}, extra {sorted(keys - source)}"


async def test_home_assistant_loads_german_texts(hass: HomeAssistant):
    entity = await async_get_translations(hass, "de", "entity", {DOMAIN})
    assert entity[f"component.{DOMAIN}.entity.sensor.outbound_connections.name"] == "Ausgehende Verbindungen"
    issues = await async_get_translations(hass, "de", "issues", {DOMAIN})
    assert issues[f"component.{DOMAIN}.issues.stale_tokens.title"] == "Ungenutzte langlebige Zugriffstoken"


# ---------------------------------------------------------------- panel

PANEL = INTEGRATION / "frontend" / "security-monitor-panel.js"


def _panel_translations() -> tuple[dict, str]:
    source = PANEL.read_text(encoding="utf-8")
    start = source.index("/* translations:start */") + len("/* translations:start */")
    end = source.index("/* translations:end */")
    return json.loads(source[start:end]), source[end:]


def _placeholders(value) -> set[str]:
    texts = value.values() if isinstance(value, dict) else [value]
    return {name for text in texts for name in re.findall(r"\{(\w+)\}", text)}


def test_panel_languages_match():
    translations, _code = _panel_translations()
    english = translations["en"]
    assert set(translations) >= {"en", "de"}
    for lang, table in translations.items():
        assert set(table) == set(english), f"{lang}: missing {sorted(set(english) - set(table))}, extra {sorted(set(table) - set(english))}"
        for key, value in table.items():
            assert type(value) is type(english[key]), f"{lang}.{key}: plural form differs from English"
            if isinstance(value, dict):
                assert set(value) == {"one", "other"}, f"{lang}.{key}: plurals need 'one' and 'other'"
            assert _placeholders(value) == _placeholders(english[key]), f"{lang}.{key}: placeholders differ"


def test_panel_uses_only_known_keys():
    translations, code = _panel_translations()
    used = set(re.findall(r'\bt\("([a-z0-9_.]+)"', code))
    used |= set(re.findall(r'"(client\.app_[a-z]+)"', code))
    assert used, "no translation calls found"
    assert used <= set(translations["en"]), f"unknown keys: {sorted(used - set(translations['en']))}"


def test_every_finding_has_panel_texts():
    translations, _code = _panel_translations()
    checks = (INTEGRATION / "checks.py").read_text(encoding="utf-8")
    keys = set(re.findall(r'^\s+"([a-z_]+)"(?:,\s*\{.*\})?\)\s*$', checks, re.MULTILINE))
    assert keys >= {"no_mfa", "stale_tokens", "ip_ban_disabled", "external_http", "login_burst", "custom_components"}
    for key in keys:
        for part in ("title", "detail"):
            assert f"finding.{key}.{part}" in translations["en"], f"finding.{key}.{part} missing"
    for kind in ("failed_login", "banned", "token_used"):
        assert f"kind.{kind}" in translations["en"]
    for severity in ("high", "medium", "low"):
        assert f"sev.{severity}" in translations["en"]
