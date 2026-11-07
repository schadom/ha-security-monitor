"""Persist the access log and destination history across restarts.

Stored in <config>/.storage/security_monitor.history. Only hostnames, IPs,
integration names, counts and timestamps are kept, never URLs, paths or
payloads.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
import logging
from typing import Any

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.history"
# Until v0.3.1 this integration was called "Security Dashboard" (domain security_dashboard)
LEGACY_DOMAIN = "security_dashboard"
LEGACY_STORAGE_KEY = f"{LEGACY_DOMAIN}.history"
SAVE_INTERVAL = timedelta(minutes=5)


class HistoryStore:
    """Periodic save plus a final write when Home Assistant stops.

    Store.async_delay_save debounces: with a coordinator updating every 30 s a
    delayed save would keep being pushed back and never run, so we save on a
    fixed timer instead.
    """

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._data_func: Callable[[], dict[str, Any]] | None = None
        self._unsubs: list[Callable[[], None]] = []

    async def async_load(self) -> dict[str, Any]:
        if data := await self._store.async_load():
            return data
        return await self._async_import_legacy()

    async def _async_import_legacy(self) -> dict[str, Any]:
        """First start after the rename: take over the old integration's history."""
        legacy: Store[dict[str, Any]] = Store(self.hass, STORAGE_VERSION, LEGACY_STORAGE_KEY)
        data = await legacy.async_load()
        if not data:
            return {}
        await self._store.async_save(data)
        _LOGGER.info("Imported access log and connection history from %s", LEGACY_STORAGE_KEY)
        # While the old integration is still loaded it owns its file (and deletes it
        # when removed); otherwise nothing else will clean it up.
        if LEGACY_DOMAIN not in self.hass.config.components:
            await legacy.async_remove()
        return data

    @callback
    def async_start(self, data_func: Callable[[], dict[str, Any]]) -> None:
        self._data_func = data_func

        @callback
        def _save(_now: Any = None) -> None:
            self._store.async_delay_save(data_func, 0)

        @callback
        def _on_stop(_event: Event) -> None:
            # While stopping, this queues the data for the Store's final write
            self._store.async_delay_save(data_func, 0)

        self._unsubs = [
            async_track_time_interval(self.hass, _save, SAVE_INTERVAL),
            self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_stop),
        ]

    async def async_stop(self) -> None:
        """Unload: stop the timer and save once more."""
        for unsub in self._unsubs:
            try:
                unsub()
            except Exception:  # noqa: BLE001 - the stop listener may have fired already
                pass
        self._unsubs = []
        if self._data_func is not None:
            await self._store.async_save(self._data_func())

    async def async_remove(self) -> None:
        await self._store.async_remove()
