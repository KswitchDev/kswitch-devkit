"""EP-011 T3 SDK context invalidation sync tests."""
from __future__ import annotations

import json
import os

from kswitch.context.invalidation_sync import ContextInvalidationSyncWorker
from kswitch.context.local_cache import LocalContextCache, _sanitize_agent_id


class _Resp:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Http:
    def __init__(self, responses: list[_Resp]):
        self.responses = responses
        self.urls: list[str] = []
        self.kwargs: list[dict] = []

    def get(self, url: str, **kwargs):
        self.urls.append(url)
        self.kwargs.append(kwargs)
        return self.responses.pop(0)


def _write_context(path, agent_id: str) -> str:
    os.makedirs(path, exist_ok=True)
    filename = os.path.join(path, f"{_sanitize_agent_id(agent_id)}.contextpack")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({"agent_id": agent_id, "status": "active", "risk_tier": "low", "pack_version": 1}, f)
    return filename


def test_context_invalidation_sync_evicts_memory_and_disk(tmp_path):
    agent_id = "agent:ep011@bank"
    context_file = _write_context(str(tmp_path), agent_id)
    cache = LocalContextCache(context_dir=str(tmp_path))
    assert cache.get_or_load(agent_id) is not None

    http = _Http([
        _Resp(200, {"version": 1}),
        _Resp(200, {
            "version": 1,
            "compacted": False,
            "events": [{"version": 1, "subject_id": agent_id, "reason": "kill_switch"}],
        }),
    ])
    worker = ContextInvalidationSyncWorker(http, "https://kswitch.internal", context_cache=cache)

    assert worker.sync_once() == 1
    assert not os.path.exists(context_file)
    assert cache.get_or_load(agent_id) is None
    assert worker.diagnostics()["last_version"] == 1


def test_context_invalidation_sync_compaction_flushes_all_context(tmp_path):
    context_a = _write_context(str(tmp_path), "agent:a")
    context_b = _write_context(str(tmp_path), "agent:b")
    cache = LocalContextCache(context_dir=str(tmp_path))
    assert cache.get_or_load("agent:a") is not None
    assert cache.get_or_load("agent:b") is not None

    http = _Http([
        _Resp(200, {"version": 9}),
        _Resp(200, {"version": 9, "compacted": True, "events": []}),
    ])
    worker = ContextInvalidationSyncWorker(http, "https://kswitch.internal", context_cache=cache)

    assert worker.sync_once() == 0
    assert not os.path.exists(context_a)
    assert not os.path.exists(context_b)
    assert worker.diagnostics()["last_compacted"] is True


def test_context_invalidation_sync_sends_auth_header():
    http = _Http([
        _Resp(200, {"version": 1}),
        _Resp(200, {"version": 1, "compacted": False, "events": []}),
    ])
    worker = ContextInvalidationSyncWorker(
        http,
        "https://kswitch.internal",
        context_cache=LocalContextCache(),
        auth_header="Bearer token",
    )

    worker.sync_once()

    assert http.kwargs[0]["headers"] == {"Authorization": "Bearer token"}
    assert http.kwargs[1]["headers"] == {"Authorization": "Bearer token"}


def test_context_invalidation_sync_advances_to_returned_version_not_global_latest(tmp_path):
    _write_context(str(tmp_path), "agent:a")
    cache = LocalContextCache(context_dir=str(tmp_path))
    http = _Http([
        _Resp(200, {"version": 5}),
        _Resp(200, {
            "version": 5,
            "returned_version": 2,
            "has_more": True,
            "compacted": False,
            "events": [{"version": 2, "subject_id": "agent:a", "reason": "status_change"}],
        }),
    ])
    worker = ContextInvalidationSyncWorker(http, "https://kswitch.internal", context_cache=cache)

    assert worker.sync_once() == 1
    assert worker.diagnostics()["last_version"] == 2


def test_context_invalidation_sync_auth_failure_preserves_local_cache(tmp_path):
    agent_id = "agent:auth@bank"
    context_file = _write_context(str(tmp_path), agent_id)
    cache = LocalContextCache(context_dir=str(tmp_path))
    http = _Http([_Resp(401, {"error": "nope"})])
    worker = ContextInvalidationSyncWorker(http, "https://kswitch.internal", context_cache=cache)

    assert worker.sync_once() == 0
    assert os.path.exists(context_file)
    assert worker.diagnostics()["last_error"] == "context_invalidation_version_auth_failed"


def test_context_invalidation_sync_version_regression_flushes_cache(tmp_path):
    context_a = _write_context(str(tmp_path), "agent:a")
    context_b = _write_context(str(tmp_path), "agent:b")
    cache = LocalContextCache(context_dir=str(tmp_path))
    http = _Http([_Resp(200, {"version": 2})])
    worker = ContextInvalidationSyncWorker(http, "https://kswitch.internal", context_cache=cache)
    worker._last_version = 7

    assert worker.sync_once() == 0
    assert not os.path.exists(context_a)
    assert not os.path.exists(context_b)
    assert worker.diagnostics()["last_version"] == 2
    assert worker.diagnostics()["last_compacted"] is True
