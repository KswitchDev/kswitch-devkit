from __future__ import annotations

import asyncio

from kswitch.service import SERVICE_BASE, ServiceAPI, ServiceAsyncAPI


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []

    def _post(self, path: str, *, json: dict) -> dict:
        self.calls.append(("POST", path, json))
        return {"ok": True, "path": path, "json": json}

    def _get(self, path: str) -> dict:
        self.calls.append(("GET", path, None))
        return {"ok": True, "path": path}


class FakeAsyncClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []

    async def _post(self, path: str, *, json: dict) -> dict:
        self.calls.append(("POST", path, json))
        return {"ok": True, "path": path, "json": json}

    async def _get(self, path: str) -> dict:
        self.calls.append(("GET", path, None))
        return {"ok": True, "path": path}


def test_service_api_exposes_b005_tool_contract_paths() -> None:
    fake = FakeClient()
    service = ServiceAPI(fake)  # type: ignore[arg-type]

    service.fetch(url="https://example.com/docs", purpose="docs", task_id="task-1")
    service.search(query="vendor docs", purpose="docs", task_id="task-1")
    service.policy_check(action="fetch", target={"host": "example.com"}, purpose="docs", task_id="task-1")
    service.get_policy()
    service.health()

    assert fake.calls == [
        ("POST", f"{SERVICE_BASE}/fetch", {
            "url": "https://example.com/docs",
            "purpose": "docs",
            "task_id": "task-1",
            "max_bytes": 1048576,
        }),
        ("POST", f"{SERVICE_BASE}/search", {
            "query": "vendor docs",
            "purpose": "docs",
            "task_id": "task-1",
            "provider_id": "customer_search_default",
            "max_results": 10,
        }),
        ("POST", f"{SERVICE_BASE}/policy_check", {
            "action": "fetch",
            "target": {"host": "example.com"},
            "purpose": "docs",
            "task_id": "task-1",
        }),
        ("GET", f"{SERVICE_BASE}/policy", None),
        ("GET", f"{SERVICE_BASE}/health", None),
    ]


def test_async_service_api_exposes_same_paths() -> None:
    async def run() -> list[tuple[str, str, dict | None]]:
        fake = FakeAsyncClient()
        service = ServiceAsyncAPI(fake)  # type: ignore[arg-type]
        await service.fetch(url="https://example.com/docs", purpose="docs", task_id="task-1", max_bytes=64)
        await service.health()
        return fake.calls

    assert asyncio.run(run()) == [
        ("POST", f"{SERVICE_BASE}/fetch", {
            "url": "https://example.com/docs",
            "purpose": "docs",
            "task_id": "task-1",
            "max_bytes": 64,
        }),
        ("GET", f"{SERVICE_BASE}/health", None),
    ]
