"""Kill Switch API — targeted, blanket, and auto kill switch operations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    AutoKillConfig,
    BlanketKillRequest,
    KillSwitchHistory,
    KillSwitchResult,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class KillSwitchAPI:
    """Synchronous kill switch operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- Targeted -------------------------------------------------------

    def targeted(
        self,
        *,
        agent_ids: list[str],
        reason: str,
        initiated_by: str | None = None,
        **kwargs: Any,
    ) -> KillSwitchResult:
        """Execute targeted kill switch on specific agents."""
        payload: dict[str, Any] = {"agent_ids": agent_ids, "reason": reason, **kwargs}
        if initiated_by:
            payload["initiated_by"] = initiated_by
        return KillSwitchResult(**self._c._post("/api/v1/kill-switch", json=payload))

    # -- Blanket --------------------------------------------------------

    def blanket_initiate(
        self,
        *,
        reason: str,
        scope: str | None = None,
        initiated_by: str | None = None,
        **kwargs: Any,
    ) -> BlanketKillRequest:
        """Initiate a blanket kill switch (requires 2 approvals)."""
        payload: dict[str, Any] = {"reason": reason, **kwargs}
        if scope:
            payload["scope"] = scope
        if initiated_by:
            payload["initiated_by"] = initiated_by
        return BlanketKillRequest(**self._c._post("/api/v1/kill-switch/blanket/initiate", json=payload))

    def blanket_approve(self, blanket_id: str, **kwargs: Any) -> dict[str, Any]:
        """Approve a pending blanket kill switch request."""
        return self._c._post(f"/api/v1/kill-switch/blanket/{blanket_id}/approve", json=kwargs)

    def blanket_cancel(self, blanket_id: str, **kwargs: Any) -> dict[str, Any]:
        """Cancel a pending blanket kill switch request."""
        return self._c._post(f"/api/v1/kill-switch/blanket/{blanket_id}/cancel", json=kwargs)

    def list_pending_blanket(self) -> list[BlanketKillRequest]:
        """List pending blanket kill switch requests."""
        resp = self._c._get("/api/v1/kill-switch/blanket")
        items = resp.get("data", resp.get("requests", []))
        return [BlanketKillRequest(**r) for r in items]

    # -- Auto Kill Switch -----------------------------------------------

    def auto_evaluate(self, **kwargs: Any) -> dict[str, Any]:
        """Trigger auto kill switch evaluation."""
        return self._c._post("/api/v1/kill-switch/auto/evaluate", json=kwargs)

    def get_auto_config(self) -> AutoKillConfig:
        """Get auto kill switch configuration."""
        return AutoKillConfig(**self._c._get("/api/v1/kill-switch/auto/config"))

    def update_auto_config(self, **kwargs: Any) -> AutoKillConfig:
        """Update auto kill switch configuration."""
        return AutoKillConfig(**self._c._patch("/api/v1/kill-switch/auto/config", json=kwargs))

    def list_auto_pending(self) -> dict[str, Any]:
        """List pending auto kill switch requests."""
        return self._c._get("/api/v1/kill-switch/auto/pending")

    def approve_auto_request(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        """Approve a pending auto kill switch request."""
        return self._c._post(f"/api/v1/kill-switch/auto/approve/{request_id}", json=kwargs)

    def reject_auto_request(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        """Reject a pending auto kill switch request."""
        return self._c._post(f"/api/v1/kill-switch/auto/reject/{request_id}", json=kwargs)

    # -- History & Violations -------------------------------------------

    def get_history(self) -> list[KillSwitchHistory]:
        """Get kill switch activation history."""
        resp = self._c._get("/api/v1/kill-switch/history")
        items = resp.get("data", resp.get("history", []))
        return [KillSwitchHistory(**h) for h in items]

    def get_violations(self) -> dict[str, Any]:
        """Get kill switch violation records."""
        return self._c._get("/api/v1/kill-switch/violations")

    # -- Webhook --------------------------------------------------------

    def webhook_snow(self, **kwargs: Any) -> dict[str, Any]:
        """ServiceNow webhook for kill switch events."""
        return self._c._post("/api/v1/kill-switch/webhook/snow", json=kwargs)


class KillSwitchAsyncAPI:
    """Asynchronous kill switch operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def targeted(self, *, agent_ids: list[str], reason: str, initiated_by: str | None = None, **kwargs: Any) -> KillSwitchResult:
        payload: dict[str, Any] = {"agent_ids": agent_ids, "reason": reason, **kwargs}
        if initiated_by:
            payload["initiated_by"] = initiated_by
        return KillSwitchResult(**await self._c._post("/api/v1/kill-switch", json=payload))

    async def blanket_initiate(self, *, reason: str, scope: str | None = None, initiated_by: str | None = None, **kwargs: Any) -> BlanketKillRequest:
        payload: dict[str, Any] = {"reason": reason, **kwargs}
        if scope:
            payload["scope"] = scope
        if initiated_by:
            payload["initiated_by"] = initiated_by
        return BlanketKillRequest(**await self._c._post("/api/v1/kill-switch/blanket/initiate", json=payload))

    async def blanket_approve(self, blanket_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/kill-switch/blanket/{blanket_id}/approve", json=kwargs)

    async def blanket_cancel(self, blanket_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/kill-switch/blanket/{blanket_id}/cancel", json=kwargs)

    async def list_pending_blanket(self) -> list[BlanketKillRequest]:
        resp = await self._c._get("/api/v1/kill-switch/blanket")
        items = resp.get("data", resp.get("requests", []))
        return [BlanketKillRequest(**r) for r in items]

    async def auto_evaluate(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/kill-switch/auto/evaluate", json=kwargs)

    async def get_auto_config(self) -> AutoKillConfig:
        return AutoKillConfig(**await self._c._get("/api/v1/kill-switch/auto/config"))

    async def update_auto_config(self, **kwargs: Any) -> AutoKillConfig:
        return AutoKillConfig(**await self._c._patch("/api/v1/kill-switch/auto/config", json=kwargs))

    async def list_auto_pending(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/kill-switch/auto/pending")

    async def approve_auto_request(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/kill-switch/auto/approve/{request_id}", json=kwargs)

    async def reject_auto_request(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/kill-switch/auto/reject/{request_id}", json=kwargs)

    async def get_history(self) -> list[KillSwitchHistory]:
        resp = await self._c._get("/api/v1/kill-switch/history")
        items = resp.get("data", resp.get("history", []))
        return [KillSwitchHistory(**h) for h in items]

    async def get_violations(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/kill-switch/violations")

    async def webhook_snow(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/kill-switch/webhook/snow", json=kwargs)
