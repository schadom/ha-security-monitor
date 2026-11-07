"""Translations stay complete and are picked up by Home Assistant."""

import json
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
