"""B005.2 governed service API wrappers.

These SDK methods mirror the `kswitch_service` MCP surface. They are transport
wrappers only; policy, identity binding, audit persistence, and provider
dispatch remain server-side responsibilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


SERVICE_BASE = "/api/v1/b005/service"


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


class ServiceAPI:
    """Synchronous B005.2 governed service operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    def fetch(self, *, url: str, purpose: str, task_id: str, max_bytes: int = 1048576) -> dict[str, Any]:
        return self._c._post(f"{SERVICE_BASE}/fetch", json={
            "url": url,
            "purpose": purpose,
            "task_id": task_id,
            "max_bytes": max_bytes,
        })

    def search(
        self,
        *,
        query: str,
        purpose: str,
        task_id: str,
        provider_id: str = "customer_search_default",
        max_results: int = 10,
    ) -> dict[str, Any]:
        return self._c._post(f"{SERVICE_BASE}/search", json={
            "query": query,
            "purpose": purpose,
            "task_id": task_id,
            "provider_id": provider_id,
            "max_results": max_results,
        })

    def policy_check(
        self,
        *,
        action: str,
        target: dict[str, Any],
        purpose: str,
        task_id: str,
        service_class: str | None = None,
    ) -> dict[str, Any]:
        return self._c._post(f"{SERVICE_BASE}/policy_check", json=_compact({
            "action": action,
            "target": target,
            "purpose": purpose,
            "task_id": task_id,
            "service_class": service_class,
        }))

    def get_policy(self) -> dict[str, Any]:
        return self._c._get(f"{SERVICE_BASE}/policy")

    def health(self) -> dict[str, Any]:
        return self._c._get(f"{SERVICE_BASE}/health")


class ServiceAsyncAPI:
    """Asynchronous B005.2 governed service operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def fetch(self, *, url: str, purpose: str, task_id: str, max_bytes: int = 1048576) -> dict[str, Any]:
        return await self._c._post(f"{SERVICE_BASE}/fetch", json={
            "url": url,
            "purpose": purpose,
            "task_id": task_id,
            "max_bytes": max_bytes,
        })

    async def search(
        self,
        *,
        query: str,
        purpose: str,
        task_id: str,
        provider_id: str = "customer_search_default",
        max_results: int = 10,
    ) -> dict[str, Any]:
        return await self._c._post(f"{SERVICE_BASE}/search", json={
            "query": query,
            "purpose": purpose,
            "task_id": task_id,
            "provider_id": provider_id,
            "max_results": max_results,
        })

    async def policy_check(
        self,
        *,
        action: str,
        target: dict[str, Any],
        purpose: str,
        task_id: str,
        service_class: str | None = None,
    ) -> dict[str, Any]:
        return await self._c._post(f"{SERVICE_BASE}/policy_check", json=_compact({
            "action": action,
            "target": target,
            "purpose": purpose,
            "task_id": task_id,
            "service_class": service_class,
        }))

    async def get_policy(self) -> dict[str, Any]:
        return await self._c._get(f"{SERVICE_BASE}/policy")

    async def health(self) -> dict[str, Any]:
        return await self._c._get(f"{SERVICE_BASE}/health")
