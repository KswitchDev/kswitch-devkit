"""Tests for the KSwitch AI Brain MCP stdio bridge."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MCP_SERVER = os.path.join(REPO_ROOT, "mcp-server")
for path in (REPO_ROOT, MCP_SERVER):
    if path not in sys.path:
        sys.path.insert(0, path)

from kswitch_brain_mcp import server
from kswitch_brain_mcp.client import BrainUnavailable


class FakeBrainClient:
    def __init__(self, *, unavailable: bool = False) -> None:
        self.unavailable = unavailable
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _maybe_raise(self) -> None:
        if self.unavailable:
            raise BrainUnavailable("sidecar unavailable")

    def health(self) -> dict[str, Any]:
        self.calls.append(("health", {}))
        self._maybe_raise()
        return {"ok": True, "services": {"memory": True, "graph": True}}

    def time_context(
        self,
        *,
        task: str = "",
        timezone: str = "Europe/London",
        max_age_seconds: int = 1800,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "time_context",
                {
                    "task": task,
                    "timezone": timezone,
                    "max_age_seconds": max_age_seconds,
                },
            )
        )
        self._maybe_raise()
        return {
            "schema_version": "kswitch.agent_time.v1",
            "task": task,
            "timezone": timezone,
        }

    def recall(
        self,
        query: str,
        *,
        limit: int = 8,
        include_unconfirmed: bool = False,
        workspace: str = "kswitch-dev",
        project: str = "kswitch",
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "recall",
                {
                    "query": query,
                    "limit": limit,
                    "include_unconfirmed": include_unconfirmed,
                    "workspace": workspace,
                    "project": project,
                },
            )
        )
        self._maybe_raise()
        return {
            "memories": [
                {
                    "id": "memory-1",
                    "memory_type": "constraint",
                    "review_status": "confirmed",
                    "summary": "Use the agent-onboarding bundle.",
                }
            ],
            "policy": {"project_only": True},
            "request_id": "req-1",
        }

    def graph_context(
        self,
        *,
        query: str = "",
        bundle: str = "agent-onboarding",
        limit: int = 8,
        memory_id: str = "",
        worker_role: str = "",
        workspace: str = "kswitch-dev",
        project: str = "kswitch",
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "graph_context",
                {
                    "query": query,
                    "bundle": bundle,
                    "limit": limit,
                    "memory_id": memory_id,
                    "worker_role": worker_role,
                    "workspace": workspace,
                    "project": project,
                },
            )
        )
        self._maybe_raise()
        return {
            "ok": True,
            "bundle": {"name": bundle},
            "seed": {"id": "seed-1"},
            "groups": {"confirmed_instructions": []},
        }

    def writeback(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("writeback", payload))
        self._maybe_raise()
        return {
            "ok": True,
            "blocked": False,
            "warnings": [],
            "written": [
                {
                    "id": "memory-written-1",
                    "memory_type": "work_log",
                    "review_status": "pending",
                    "source_ref_count": len(payload.get("source_refs", [])),
                }
            ],
        }

    def review_queue(
        self,
        *,
        limit: int = 10,
        include_evidence_only: bool = False,
        workspace: str = "kswitch-dev",
        project: str = "kswitch",
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "review_queue",
                {
                    "limit": limit,
                    "include_evidence_only": include_evidence_only,
                    "workspace": workspace,
                    "project": project,
                },
            )
        )
        self._maybe_raise()
        return {
            "ok": True,
            "queue": [
                {
                    "memory": {"id": "memory-pending-1", "review_status": "pending"},
                    "authority_class": "candidate_memory",
                    "candidate_flags": [
                        {
                            "flag_type": "missing_source_refs",
                            "severity": "blocker",
                            "evidence": {"field": "source_refs"},
                        }
                    ],
                }
            ],
            "policy": {"pending_is_not_instruction": True},
            "count": 1,
            "total": 1,
            "has_more": False,
        }

    def compile_context_pack(
        self,
        *,
        target: str = "agent-onboarding",
        query: str = "",
        task_id: str = "",
        limit: int = 8,
        workspace: str = "kswitch-dev",
        project: str = "kswitch",
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "compile_context_pack",
                {
                    "target": target,
                    "query": query,
                    "task_id": task_id,
                    "limit": limit,
                    "workspace": workspace,
                    "project": project,
                },
            )
        )
        self._maybe_raise()
        return {
            "ok": True,
            "cache_hit": True,
            "cache_key": "cpc-test",
            "dependency_hash": "dep-test",
            "contract_hash": "contract-test",
            "pack": {
                "schema_version": "kswitch.ai_brain.compiled_context_pack.v1",
                "target": target,
                "bundle": {"name": target},
                "degraded": {"active": False},
                "included": {"confirmed_instructions": []},
            },
        }



def test_brain_status_returns_live_sidecar_status(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_status())

    assert result["ok"] is True
    assert result["degraded"] is False
    assert result["status"]["services"]["memory"] is True
    assert fake.calls == [("health", {})]


def test_brain_status_degrades_without_crashing(monkeypatch) -> None:
    fake = FakeBrainClient(unavailable=True)
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_status())

    assert result == {
        "ok": False,
        "degraded": True,
        "tool": "brain_status",
        "reason": "sidecar unavailable",
    }


def test_brain_time_context_degrades_when_local_fallback_rejects_timezone(monkeypatch) -> None:
    fake = FakeBrainClient(unavailable=True)
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_time_context(task="KSwitch onboarding", timezone="Not/AZone"))

    assert result["ok"] is False
    assert result["degraded"] is True
    assert result["time_context"]["schema_version"] == "kswitch.agent_time.v1"
    assert result["time_context"]["degraded"] is True
    assert result["time_context"]["timezone"] == "Not/AZone"
    assert "unknown timezone" in result["time_context"]["error"]


def test_brain_recall_rejects_unsafe_query_before_sidecar(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_recall("Authorization: Bearer secret-token"))

    assert result["ok"] is False
    assert result["reason"] == "unsafe_input"
    assert fake.calls == []


def test_brain_graph_context_defaults_to_agent_onboarding(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_graph_context(query="KSwitch agent onboarding", limit=5))

    assert result["ok"] is True
    assert result["context"]["bundle"]["name"] == "agent-onboarding"
    assert fake.calls == [
        (
            "graph_context",
            {
                "query": "KSwitch agent onboarding",
                "bundle": "agent-onboarding",
                "limit": 5,
                "memory_id": "",
                "worker_role": "",
                "workspace": "kswitch-dev",
                "project": "kswitch",
            },
        )
    ]


def test_brain_bootstrap_returns_required_context_pack(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_bootstrap("KSwitch agent onboarding", runtime="gemini", limit=3))

    assert result["schema_version"] == "kswitch.ai_brain.bootstrap.v1"
    assert result["runtime"] == "gemini"
    assert result["brain"]["available"] is True
    assert result["time_context"]["schema_version"] == "kswitch.agent_time.v1"
    assert result["authority_rules"]
    assert [memory["id"] for memory in result["memories"]] == ["memory-1"]
    assert result["graph_context"]["bundle"]["name"] == "agent-onboarding"
    assert result["compiled_context"]["cache_hit"] is True
    assert (
        "compile_context_pack",
        {
            "target": "agent-onboarding",
            "query": "KSwitch agent onboarding",
            "task_id": "KSwitch agent onboarding",
            "limit": 3,
            "workspace": "kswitch-dev",
            "project": "kswitch",
        },
    ) in fake.calls


def test_worker_role_bootstrap_uses_worker_context_bundle(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(
        server.brain_bootstrap(
            "KSwitch worker onboarding",
            runtime="codex",
            worker_role="security_reviewer",
            limit=4,
        )
    )

    assert result["worker_role"] == "security_reviewer"
    assert result["graph_context"]["bundle"]["name"] == "worker-role-onboarding"
    assert (
        "graph_context",
        {
            "query": "KSwitch worker onboarding",
            "bundle": "worker-role-onboarding",
            "limit": 4,
            "memory_id": "",
            "worker_role": "security_reviewer",
            "workspace": "kswitch-dev",
            "project": "kswitch",
        },
    ) in fake.calls


def test_brain_bootstrap_falls_back_when_compiled_pack_unavailable(monkeypatch) -> None:
    fake = FakeBrainClient()

    def unavailable_compile(**_: Any) -> dict[str, Any]:
        fake.calls.append(("compile_context_pack", {"forced": "unavailable"}))
        raise BrainUnavailable("compiled cache unavailable")

    fake.compile_context_pack = unavailable_compile  # type: ignore[method-assign]
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_bootstrap("KSwitch agent onboarding", runtime="codex", limit=3))

    assert result["graph_context"]["bundle"]["name"] == "agent-onboarding"
    assert result["compiled_context"] == {}
    assert any("compiled_context_unavailable" in error for error in result["recall_errors"])
    assert any(call[0] == "graph_context" for call in fake.calls)


def test_brain_write_candidate_requires_source_refs_before_sidecar(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(
        server.brain_write_candidate(
            task="KS-EP-212",
            content="Worker found a source-backed handoff note.",
            source_refs=[],
        )
    )

    assert result["ok"] is False
    assert result["reason"] == "unsafe_input"
    assert "source_refs_required" in result["detail"]
    assert fake.calls == []


def test_brain_write_candidate_writes_pending_sourced_memory(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(
        server.brain_write_candidate(
            task="KS-EP-212",
            content="Security reviewer should record bypass findings as pending memory only.",
            memory_type="work_log",
            runtime="codex",
            worker_role="security_reviewer",
            source_refs=[{"kind": "repo", "uri": "docs/execution-packs/KS-EP-212.md:1"}],
            idempotency_key="ep212-security-reviewer-1",
        )
    )

    assert result["ok"] is True
    assert result["review_status"] == "pending"
    assert result["written"][0]["id"] == "memory-written-1"
    call_name, payload = fake.calls[-1]
    assert call_name == "writeback"
    assert payload["task_id"] == "KS-EP-212"
    assert payload["visibility"]["worker_role"] == "security_reviewer"
    assert payload["memory_payload"]["next_steps"] == [
        "Security reviewer should record bypass findings as pending memory only."
    ]


def test_brain_write_candidate_rejects_unsafe_idempotency_key(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(
        server.brain_write_candidate(
            task="KS-EP-212",
            content="Worker found a source-backed handoff note.",
            source_refs=[{"kind": "repo", "uri": "docs/execution-packs/KS-EP-212.md:1"}],
            idempotency_key="Authorization: Bearer secret-token",
        )
    )

    assert result["ok"] is False
    assert result["reason"] == "unsafe_input"
    assert fake.calls == []


def test_brain_write_candidate_rejects_unknown_worker_role(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(
        server.brain_write_candidate(
            task="KS-EP-212",
            content="Worker found a source-backed handoff note.",
            worker_role="root_admin",
            source_refs=[{"kind": "repo", "uri": "docs/execution-packs/KS-EP-212.md:1"}],
        )
    )

    assert result["ok"] is False
    assert result["reason"] == "unsupported_worker_role"
    assert fake.calls == []


def test_brain_review_queue_returns_pending_flags(monkeypatch) -> None:
    fake = FakeBrainClient()
    monkeypatch.setattr(server, "_client", fake)

    result = asyncio.run(server.brain_review_queue(limit=7, include_evidence_only=True))

    assert result["ok"] is True
    assert result["queue"][0]["authority_class"] == "candidate_memory"
    assert result["queue"][0]["candidate_flags"][0]["flag_type"] == "missing_source_refs"
    assert result["policy"]["pending_is_not_instruction"] is True
    assert fake.calls == [
        (
            "review_queue",
            {
                "limit": 7,
                "include_evidence_only": True,
                "workspace": "kswitch-dev",
                "project": "kswitch",
            },
        )
    ]
