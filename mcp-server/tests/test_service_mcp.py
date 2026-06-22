"""Tests for the B005.2 KSwitch service MCP entrypoint."""

from __future__ import annotations

import asyncio
import json
import os
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 test host
    tomllib = None

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MCP_SERVER = os.path.join(REPO_ROOT, "mcp-server")
for path in (REPO_ROOT, MCP_SERVER):
    if path not in sys.path:
        sys.path.insert(0, path)


from kswitch_mcp import service_server

pytest.importorskip("app.b005_kswitch_service")
pytest.importorskip("app.b005_service_governance")


def _runtime_context():
    from app.b005_kswitch_service import B005TrustedContext

    return B005TrustedContext(
        tenant_id="tenant-alpha",
        customer_id="customer-bank-a",
        mode="managed",
        service_registry_id="registry-b005-demo",
        service_registry_version="2026-05-28.1",
        governance_profile_id="governance-profile-managed",
        policy_scope="tenant",
        policy_bundle="sha256:" + "1" * 64,
        identity={
            "agent_wlid": "spiffe://bank.internal/agent/researcher",
            "wlid_attestation_method": "spiffe_svid_jwt",
            "wlid_validated_at": "2026-05-28T00:00:00Z",
            "agent_operational_id": "agent-researcher-001",
        },
        device_trust_level="managed",
        user="service-agent@bank.internal",
        device_id="device-managed-001",
        agent_runtime="claude-code",
        agent_session_id="agent-session-001",
        workspace_id="workspace-prod-001",
        compliance_frameworks=["soc_2"],
        search_provider_registry={
            "customer_search_default": {
                "service_provider": "customer_search",
                "service_id": "customer_search_default",
                "owner": "customer-bank-a",
                "retention_class": "metadata_only",
                "evidence_policy": "b005-search-default",
                "health": "available",
                "enabled": True,
            }
        },
    )


@pytest.fixture(autouse=True)
def _clear_b005_service_runtime():
    service_server.clear_runtime()
    yield
    service_server.clear_runtime()


def test_service_mcp_is_dedicated_fastmcp_entrypoint() -> None:
    from mcp.server.fastmcp import FastMCP

    assert isinstance(service_server.mcp, FastMCP)
    assert service_server.SERVICE_NAME == "kswitch_service"
    assert service_server.TOOL_NAMES == ("fetch", "search", "policy_check", "get_policy", "health")


def test_service_mcp_script_entry_is_registered() -> None:
    pyproject = os.path.join(MCP_SERVER, "pyproject.toml")

    if tomllib is not None:
        with open(pyproject, "rb") as fh:
            config = tomllib.load(fh)
        assert config["project"]["scripts"]["kswitch-service-mcp"] == "kswitch_mcp.service_server:main"
    else:
        with open(pyproject, encoding="utf-8") as fh:
            pyproject_text = fh.read()
        assert 'kswitch-service-mcp = "kswitch_mcp.service_server:main"' in pyproject_text


def test_health_reports_fail_closed_dependency_posture() -> None:
    result = asyncio.run(service_server.health())

    assert result["ok"] is False
    assert result["fail_closed"] is True
    assert result["status"] == "fail_closed"
    for dependency in ("identity", "policy", "registry", "audit", "fetch_broker", "search_adapter"):
        assert result["dependencies"][dependency] == "unavailable"


def test_fetch_fails_closed_without_trusted_context_and_redacts_url() -> None:
    result = asyncio.run(
        service_server.fetch(
            url="https://example.com/docs?token=secret",
            purpose="technical docs",
            task_id="task-1",
        )
    )

    rendered = json.dumps(result, sort_keys=True)
    assert result["allowed"] is False
    assert result["reason"] == "identity_context_unavailable"
    assert result["dispatch_attempted"] is False
    assert "target_hash" in result
    assert "example.com" not in rendered
    assert "secret" not in rendered
    assert "token" not in rendered


def test_fetch_missing_purpose_denies_without_target_hash() -> None:
    result = asyncio.run(
        service_server.fetch(
            url="https://example.com/docs",
            purpose="",
            task_id="task-1",
        )
    )

    assert result["allowed"] is False
    assert result["reason"] == "missing_purpose"
    assert "target_hash" not in result


def test_search_is_discoverable_but_fails_closed_until_b005_3() -> None:
    result = asyncio.run(
        service_server.search(
            query="vendor docs",
            purpose="technical docs",
            task_id="task-1",
            provider_id="customer_search_default",
        )
    )

    rendered = json.dumps(result, sort_keys=True)
    assert result["allowed"] is False
    assert result["reason"] == "search_adapter_unavailable"
    assert result["provider_id"] == "customer_search_default"
    assert "query_hash" in result
    assert "vendor docs" not in rendered


def test_search_runtime_calls_registered_adapter_without_raw_query() -> None:
    from app.b005_service_governance import canonical_json_hash, validate_governance_event

    events: list[dict] = []
    adapter_requests: list[dict] = []

    def audit_sink(event: dict) -> dict:
        validate_governance_event(event)
        events.append(event)
        return event

    def adapter(request: dict) -> dict:
        adapter_requests.append(request)
        return {
            "provider_id": "customer_search_default",
            "result_set_hash": canonical_json_hash({"results": ["r1"]}),
            "results": [
                {
                    "result_id": "result-1",
                    "rank": 1,
                    "title": "Vendor documentation",
                    "url_hash": canonical_json_hash({"url": "https://docs.example.com/guide"}),
                    "display_url_redacted": "docs.example.com/guide",
                    "snippet_hash": canonical_json_hash({"snippet": "redacted"}),
                }
            ],
        }

    service_server.configure_runtime(
        context=_runtime_context(),
        audit_sink=audit_sink,
        search_adapter=adapter,
        search_classifier=lambda _request: {"classification": "default"},
    )

    result = asyncio.run(
        service_server.search(
            query="vendor docs",
            purpose="technical docs",
            task_id="task-1",
            provider_id="customer_search_default",
        )
    )

    rendered = json.dumps(result, sort_keys=True)
    assert result["allowed"] is True
    assert "query_hash" in adapter_requests[0]
    assert "query" not in adapter_requests[0]
    assert "vendor docs" not in rendered
    assert [event["event_type"] for event in events] == ["agent.service.decision", "agent.service.completed"]


def test_fetch_runtime_accepts_search_handoff_and_records_linkage() -> None:
    from app.b005_service_governance import canonical_json_hash, validate_governance_event

    events: list[dict] = []

    def audit_sink(event: dict) -> dict:
        validate_governance_event(event)
        events.append(event)
        return event

    def adapter(_request: dict) -> dict:
        return {
            "provider_id": "customer_search_default",
            "result_set_hash": canonical_json_hash({"results": ["r1"]}),
            "results": [
                {
                    "result_id": "result-1",
                    "rank": 1,
                    "title": "Vendor documentation",
                    "url_hash": canonical_json_hash({"url": "https://docs.example.com/guide"}),
                    "display_url_redacted": "docs.example.com/guide",
                    "snippet_hash": canonical_json_hash({"snippet": "redacted"}),
                }
            ],
        }

    service_server.configure_runtime(
        context=_runtime_context(),
        audit_sink=audit_sink,
        fetch_dispatcher=lambda _url, _max_bytes: {"status": 200, "content": "linked mcp content"},
        fetch_resolver=lambda _host: ["93.184.216.34"],
        search_adapter=adapter,
        search_classifier=lambda _request: {"classification": "default"},
    )

    search_result = asyncio.run(
        service_server.search(
            query="vendor docs",
            purpose="technical docs",
            task_id="task-1",
            provider_id="customer_search_default",
        )
    )
    handoff = search_result["results"][0]["fetch_handoff"]
    fetch_result = asyncio.run(
        service_server.fetch(
            url="https://docs.example.com/guide",
            purpose="technical docs",
            task_id="task-1",
            **handoff,
        )
    )

    assert fetch_result["allowed"] is True
    assert events[2]["tool"] == "fetch"
    assert events[2]["source_search_decision_id"] == search_result["decision_id"]
    assert fetch_result["citations"][0]["source_search_url_hash"] == handoff["source_url_hash"]


def test_search_runtime_denies_without_classifier_before_adapter() -> None:
    from app.b005_service_governance import validate_governance_event

    events: list[dict] = []
    called = []

    def audit_sink(event: dict) -> dict:
        validate_governance_event(event)
        events.append(event)
        return event

    service_server.configure_runtime(
        context=_runtime_context(),
        audit_sink=audit_sink,
        search_adapter=lambda _request: called.append(True),
    )

    result = asyncio.run(
        service_server.search(
            query="vendor docs",
            purpose="technical docs",
            task_id="task-1",
            provider_id="customer_search_default",
        )
    )

    assert result["allowed"] is False
    assert result["reason"] == "classifier_unavailable"
    assert called == []
    assert events[0]["decision"] == "deny"


def test_policy_check_fails_closed_with_redacted_target() -> None:
    result = asyncio.run(
        service_server.policy_check(
            action="fetch",
            target={"url": "https://example.com/docs?token=secret"},
            purpose="technical docs",
            task_id="task-1",
            service_class="broker.webfetch",
        )
    )

    rendered = json.dumps(result, sort_keys=True)
    assert result["allowed"] is False
    assert result["reason"] == "identity_context_unavailable"
    assert result["action"] == "fetch"
    assert result["service_class"] == "broker.webfetch"
    assert "target_hash" in result
    assert "example.com" not in rendered
    assert "secret" not in rendered


def test_policy_check_runtime_uses_injected_rate_limiter() -> None:
    from app.b005_service_governance import validate_governance_event

    events: list[dict] = []

    def audit_sink(event: dict) -> dict:
        validate_governance_event(event)
        events.append(event)
        return event

    service_server.configure_runtime(
        context=_runtime_context(),
        audit_sink=audit_sink,
        policy_check_rate_limiter=lambda _payload: {
            "allowed": False,
            "limit": 1,
            "remaining": 0,
            "window_seconds": 60,
        },
    )

    result = asyncio.run(
        service_server.policy_check(
            action="fetch",
            target={"url": "https://example.com/docs?token=secret"},
            purpose="technical docs",
            task_id="task-1",
            service_class="broker.webfetch",
        )
    )

    rendered = json.dumps(result, sort_keys=True)
    assert result["allowed"] is False
    assert result["reason"] == "policy_check_rate_limited"
    assert events[0]["matched_rule_id"] == "b005.policy_check.rate_limited"
    assert "token=secret" not in rendered
    assert "token=secret" not in json.dumps(events)


def test_get_policy_is_redacted() -> None:
    result = asyncio.run(service_server.get_policy())
    rendered = json.dumps(result, sort_keys=True)

    assert result["ok"] is True
    assert result["policy_view"] == "redacted_w1"
    assert "broker.webfetch" in result["supported_service_classes"]
    assert "example.com" not in rendered
    assert "secret" not in rendered
    assert "signing" not in rendered.lower()
