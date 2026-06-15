"""Events API — governance event outbox, replay, stats."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import Event, EventStats

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class EventsAPI:
    """Synchronous event operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    def list(
        self,
        *,
        status: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
        **filters: Any,
    ) -> list[Event]:
        """List governance events with optional filtering."""
        params: dict[str, Any] = {"limit": limit, **filters}
        if status:
            params["status"] = status
        if event_type:
            params["event_type"] = event_type
        resp = self._c._get("/api/v1/events", params=params)
        items = resp.get("data", resp.get("events", []))
        return [Event(**e) for e in items]

    def get(self, event_id: str) -> Event:
        """Get a single event by ID."""
        return Event(**self._c._get(f"/api/v1/events/{event_id}"))

    def get_stats(self) -> EventStats:
        """Get event delivery statistics."""
        return EventStats(**self._c._get("/api/v1/events/stats"))

    def replay(self, event_id: str) -> dict[str, Any]:
        """Replay a single event."""
        return self._c._post(f"/api/v1/events/{event_id}/replay")

    def replay_dead_letters(self) -> dict[str, Any]:
        """Replay all dead-letter events."""
        return self._c._post("/api/v1/events/replay-dead-letters")

    # -- Fleet Events ---------------------------------------------------

    def emit_fleet_event(self, **kwargs: Any) -> dict[str, Any]:
        """Emit a fleet event."""
        return self._c._post("/api/v1/fleet/events", json=kwargs)

    def list_fleet_events(self, **params: Any) -> dict[str, Any]:
        """List fleet events."""
        return self._c._get("/api/v1/fleet/events", params=params)

    def get_fleet_event_stats(self) -> dict[str, Any]:
        """Get fleet event statistics."""
        return self._c._get("/api/v1/fleet/events/stats")

    def export_fleet_events(self, **params: Any) -> dict[str, Any]:
        """Export fleet events."""
        return self._c._get("/api/v1/fleet/events/export", params=params)

    # -- Webhooks -------------------------------------------------------

    def get_webhook_config(self) -> dict[str, Any]:
        """Get webhook configuration."""
        return self._c._get("/api/v1/webhooks/config")

    def test_webhook(self, **kwargs: Any) -> dict[str, Any]:
        """Test webhook delivery."""
        return self._c._post("/api/v1/webhooks/test", json=kwargs)

    # -- Maintenance ----------------------------------------------------

    def cleanup(self, **kwargs: Any) -> dict[str, Any]:
        """Run maintenance cleanup of old events and evaluations."""
        return self._c._post("/api/v1/maintenance/cleanup", json=kwargs)


class EventsAsyncAPI:
    """Asynchronous event operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def list(self, *, status: str | None = None, event_type: str | None = None, limit: int = 50, **filters: Any) -> list[Event]:
        params: dict[str, Any] = {"limit": limit, **filters}
        if status:
            params["status"] = status
        if event_type:
            params["event_type"] = event_type
        resp = await self._c._get("/api/v1/events", params=params)
        items = resp.get("data", resp.get("events", []))
        return [Event(**e) for e in items]

    async def get(self, event_id: str) -> Event:
        return Event(**await self._c._get(f"/api/v1/events/{event_id}"))

    async def get_stats(self) -> EventStats:
        return EventStats(**await self._c._get("/api/v1/events/stats"))

    async def replay(self, event_id: str) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/events/{event_id}/replay")

    async def replay_dead_letters(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/events/replay-dead-letters")

    async def emit_fleet_event(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/fleet/events", json=kwargs)

    async def list_fleet_events(self, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/fleet/events", params=params)

    async def get_fleet_event_stats(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/fleet/events/stats")

    async def export_fleet_events(self, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/fleet/events/export", params=params)

    async def get_webhook_config(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/webhooks/config")

    async def test_webhook(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/webhooks/test", json=kwargs)

    async def cleanup(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/maintenance/cleanup", json=kwargs)
