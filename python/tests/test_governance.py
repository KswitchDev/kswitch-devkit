"""Tests for GovernanceAPI methods."""

from __future__ import annotations

import pytest
import httpx

# `respx` is an optional test-only dependency for HTTP mocking. Skip the
# whole module cleanly if it isn't installed rather than failing collection
# at the repo root — keeps `pytest` at root green for the bank dev review.
respx = pytest.importorskip("respx")

from kswitch import KSwitchClient, Agent, PaginatedResponse
from kswitch.models import ApprovalCriteria, GateStatus, MCPServer, DelegationChain


BASE = "http://localhost:5001"


@pytest.fixture
def client():
    c = KSwitchClient(base_url=BASE, verify_ssl=False)
    yield c
    c.close()


class TestRegisterAgent:
    @respx.mock
    def test_register_returns_agent(self, client):
        respx.post(f"{BASE}/api/v1/agents").mock(
            return_value=httpx.Response(201, json={
                "id": "agent-001",
                "display_name": "test-agent",
                "record_type": "AGENT",
                "status": "pending_review",
                "risk_tier": "tier_2",
            })
        )
        agent = client.governance.register_agent(
            display_name="test-agent",
            risk_tier="tier_2",
        )
        assert isinstance(agent, Agent)
        assert agent.id == "agent-001"
        assert agent.display_name == "test-agent"
        assert agent.risk_tier == "tier_2"


class TestListAgents:
    @respx.mock
    def test_list_returns_paginated(self, client):
        respx.get(f"{BASE}/api/v1/agents").mock(
            return_value=httpx.Response(200, json={
                "data": [
                    {"id": "a1", "display_name": "Agent 1", "record_type": "AGENT", "status": "active"},
                    {"id": "a2", "display_name": "Agent 2", "record_type": "AGENT", "status": "pending_review"},
                ],
                "total": 2,
                "page": 1,
                "page_size": 50,
            })
        )
        result = client.governance.list_agents()
        assert isinstance(result, PaginatedResponse)
        assert len(result.data) == 2
        assert result.total == 2
        assert all(isinstance(a, Agent) for a in result.data)


class TestGetAgent:
    @respx.mock
    def test_get_agent(self, client):
        respx.get(f"{BASE}/api/v1/agents/agent-001").mock(
            return_value=httpx.Response(200, json={
                "id": "agent-001",
                "display_name": "test-agent",
                "record_type": "AGENT",
                "status": "active",
            })
        )
        agent = client.governance.get_agent("agent-001")
        assert agent.id == "agent-001"
        assert agent.status == "active"


class TestApprove:
    @respx.mock
    def test_approve(self, client):
        respx.post(f"{BASE}/api/v1/agents/agent-001/approve").mock(
            return_value=httpx.Response(200, json={"status": "approved"})
        )
        result = client.governance.approve("agent-001", reviewed_by="admin@co.com")
        assert result["status"] == "approved"


class TestSuspend:
    @respx.mock
    def test_suspend(self, client):
        respx.post(f"{BASE}/api/v1/agents/agent-001/suspend").mock(
            return_value=httpx.Response(200, json={"status": "suspended"})
        )
        result = client.governance.suspend("agent-001", reason="security incident")
        assert result["status"] == "suspended"


class TestReactivate:
    @respx.mock
    def test_reactivate(self, client):
        respx.post(f"{BASE}/api/v1/agents/agent-001/reactivate").mock(
            return_value=httpx.Response(200, json={"status": "active"})
        )
        result = client.governance.reactivate("agent-001")
        assert result["status"] == "active"


class TestDecommission:
    @respx.mock
    def test_decommission(self, client):
        respx.post(f"{BASE}/api/v1/agents/agent-001/decommission").mock(
            return_value=httpx.Response(200, json={"status": "decommissioned"})
        )
        result = client.governance.decommission("agent-001")
        assert result["status"] == "decommissioned"


class TestUpdateAgent:
    @respx.mock
    def test_patch(self, client):
        respx.patch(f"{BASE}/api/v1/agents/agent-001").mock(
            return_value=httpx.Response(200, json={
                "id": "agent-001",
                "display_name": "updated-agent",
                "record_type": "AGENT",
                "status": "active",
            })
        )
        agent = client.governance.update_agent("agent-001", display_name="updated-agent")
        assert agent.display_name == "updated-agent"


class TestApprovalCriteria:
    @respx.mock
    def test_get_criteria(self, client):
        respx.get(f"{BASE}/api/v1/agents/agent-001/approval-criteria").mock(
            return_value=httpx.Response(200, json={
                "agent_id": "agent-001",
                "criteria": [{"name": "toxic_combos", "met": True}],
                "all_met": True,
            })
        )
        result = client.governance.get_approval_criteria("agent-001")
        assert isinstance(result, ApprovalCriteria)
        assert result.all_met is True


class TestRegisterMCP:
    @respx.mock
    def test_register_mcp(self, client):
        respx.post(f"{BASE}/api/v1/mcp/register").mock(
            return_value=httpx.Response(201, json={
                "id": "mcp-001",
                "display_name": "test-mcp",
                "record_type": "MCP_SERVER",
                "status": "pending_review",
            })
        )
        mcp = client.governance.register_mcp(display_name="test-mcp")
        assert isinstance(mcp, MCPServer)
        assert mcp.record_type == "MCP_SERVER"


class TestGates:
    @respx.mock
    def test_evaluate_gates(self, client):
        respx.post(f"{BASE}/api/v1/mcp/mcp-001/gates/evaluate").mock(
            return_value=httpx.Response(200, json={"status": "evaluated"})
        )
        result = client.governance.evaluate_gates("mcp-001")
        assert result["status"] == "evaluated"

    @respx.mock
    def test_get_gate_status(self, client):
        respx.get(f"{BASE}/api/v1/mcp/mcp-001/gates/status").mock(
            return_value=httpx.Response(200, json={
                "mcp_id": "mcp-001",
                "gates": [],
                "all_passed": True,
            })
        )
        status = client.governance.get_gate_status("mcp-001")
        assert isinstance(status, GateStatus)
        assert status.all_passed is True


class TestDelegation:
    @respx.mock
    def test_delegate(self, client):
        respx.post(f"{BASE}/api/v1/agents/agent-001/delegate").mock(
            return_value=httpx.Response(200, json={"status": "delegated"})
        )
        result = client.governance.delegate("agent-001", delegate_to="agent-002")
        assert result["status"] == "delegated"

    @respx.mock
    def test_get_delegation_chain(self, client):
        respx.get(f"{BASE}/api/v1/agents/agent-001/delegation-chain").mock(
            return_value=httpx.Response(200, json={
                "agent_id": "agent-001",
                "chain": [{"from": "agent-001", "to": "agent-002"}],
            })
        )
        chain = client.governance.get_delegation_chain("agent-001")
        assert isinstance(chain, DelegationChain)
        assert len(chain.chain) == 1
