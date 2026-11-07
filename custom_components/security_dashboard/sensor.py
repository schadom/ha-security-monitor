"""Sensors so findings can drive automations (e.g. notify on failed logins)."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SecurityConfigEntry
from .const import SIGNAL_UPDATED
from .coordinator import NetworkCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SecurityConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    data = entry.runtime_data
    async_add_entities(
        [
            OutboundConnectionsSensor(data.network, entry.entry_id),
            FailedLoginsSensor(entry),
        ]
    )


class OutboundConnectionsSensor(CoordinatorEntity[NetworkCoordinator], SensorEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "outbound_connections"
    _attr_icon = "mdi:lan-connect"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: NetworkCoordinator, entry_id: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry_id}_outbound_connections"

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.outbound_count if self.coordinator.data else None

    @property
    def extra_state_attributes(self):
        if not self.coordinator.data:
            return None
        return {"top_destinations": self.coordinator.data.destinations[:10]}


class FailedLoginsSensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "failed_logins_24h"
    _attr_icon = "mdi:account-alert"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_should_poll = False

    def __init__(self, entry: SecurityConfigEntry) -> None:
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_failed_logins_24h"
        self._attr_native_value = 0

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(self.hass, SIGNAL_UPDATED, self._schedule_refresh)
        )
        await self._refresh()

    @callback
    def _schedule_refresh(self) -> None:
        self.hass.async_create_task(self._refresh())

    async def _refresh(self) -> None:
        snap = await self._entry.runtime_data.auth.async_snapshot()
        self._attr_native_value = snap["failed_logins_24h"]
        self.async_write_ha_state()
