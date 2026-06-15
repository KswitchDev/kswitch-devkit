"""Tests for Pydantic model validation."""

from __future__ import annotations

from datetime import datetime

import pytest

from kswitch.models import (
    Agent,
    AuthZenDecision,
    AuthZenRequest,
    BlanketKillRequest,
    BoundaryAnalysis,
    Dashboard,
    DecisionExplanation,
    EnforcementDecision,
    Event,
    EventStats,
    FleetRiskSummary,
    GateStatus,
    IdentityStats,
    KillSwitchResult,
    PaginatedResponse,
    Policy,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyValidation,
    RiskScore,
    ServiceIdentity,
    Skill,
    SpiffeIdentity,
    Tool,
    ToxicComboDashboard,
    ToxicComboResult,
    ToxicComboRule,
    ToxicComboViolation,
    TrustDomain,
)


class TestAgentModel:
    def test_minimal(self):
        agent = Agent(id="a1", display_name="Test")
        assert agent.id == "a1"
        assert agent.record_type == "AGENT"
        assert agent.status == "pending_review"

    def test_full(self):
        agent = Agent(
            id="a1",
            display_name="Full Agent",
            record_type="AGENT",
            status="active",
            risk_tier="tier_1",
            owning_division="engineering",
            owning_team="platform",
            description="A test agent",
            environment="production",
            source_repo="https://github.com/org/repo",
            framework="langchain",
            version="1.0.0",
            contact_email="dev@company.com",
            data_classification="confidential",
        )
        assert agent.risk_tier == "tier_1"
        assert agent.data_classification == "confidential"

    def test_extra_fields_allowed(self):
        agent = Agent(id="a1", display_name="Test", custom_field="custom_value")
        assert agent.custom_field == "custom_value"  # type: ignore[attr-defined]


class TestPaginatedResponse:
    def test_empty(self):
        resp = PaginatedResponse[Agent](data=[], total=0)
        assert len(resp.data) == 0
        assert resp.total == 0

    def test_with_agents(self):
        agents = [Agent(id=f"a{i}", display_name=f"Agent {i}") for i in range(3)]
        resp = PaginatedResponse[Agent](data=agents, total=3, page=1, page_size=50)
        assert len(resp.data) == 3
        assert resp.data[0].id == "a0"


class TestPolicyModels:
    def test_policy(self):
        p = Policy(id="p1", name="test-policy", mode="enforce")
        assert p.mode == "enforce"

    def test_policy_decision(self):
        d = PolicyDecision(decision=True, policies_matched=["policy-1"])
        assert d.decision is True
        assert len(d.policies_matched) == 1

    def test_policy_validation(self):
        v = PolicyValidation(valid=True)
        assert v.valid is True
        assert v.errors == []


class TestToxicComboModels:
    def test_violation(self):
        v = ToxicComboViolation(
            rule_id="r1",
            rule_name="admin-plus-deploy",
            severity="critical",
            skills=["admin", "deploy"],
        )
        assert v.severity == "critical"
        assert len(v.skills) == 2

    def test_result_clean(self):
        r = ToxicComboResult(agent_id="a1", violations=[], clean=True)
        assert r.clean is True

    def test_result_dirty(self):
        v = ToxicComboViolation(rule_id="r1", severity="high")
        r = ToxicComboResult(agent_id="a1", violations=[v], clean=False)
        assert r.clean is False
        assert len(r.violations) == 1

    def test_dashboard(self):
        d = ToxicComboDashboard(total_violations=5, clean_agents=10)
        assert d.total_violations == 5

    def test_rule(self):
        r = ToxicComboRule(id="r1", name="test-rule", severity="medium", waivable=True)
        assert r.waivable is True


class TestIdentityModels:
    def test_spiffe(self):
        s = SpiffeIdentity(agent_id="a1", spiffe_id="spiffe://trust/agent/a1", status="active")
        assert s.spiffe_id is not None

    def test_service_identity(self):
        si = ServiceIdentity(id="si1", agent_id="a1", identity_type="api_key", status="active")
        assert si.identity_type == "api_key"

    def test_trust_domain(self):
        td = TrustDomain(name="trust.example.com", status="active")
        assert td.name == "trust.example.com"

    def test_stats(self):
        s = IdentityStats(total=100, active=80, revoked=10, expiring_soon=5)
        assert s.total == 100


class TestKillSwitchModels:
    def test_result(self):
        r = KillSwitchResult(suspended=["a1", "a2"], spiffe_revoked=2, service_identities_revoked=1)
        assert len(r.suspended) == 2

    def test_blanket_request(self):
        b = BlanketKillRequest(id="bk1", reason="security incident", status="pending")
        assert b.status == "pending"


class TestAuthZenModels:
    def test_decision(self):
        d = AuthZenDecision(decision=True)
        assert d.decision is True

    def test_request(self):
        r = AuthZenRequest(
            subject={"type": "agent", "id": "a1"},
            resource={"type": "tool", "id": "t1"},
            action={"name": "invoke"},
        )
        assert r.subject.type == "agent"


class TestEventModels:
    def test_event(self):
        e = Event(id="ev1", event_type="agent.registered", status="delivered")
        assert e.event_type == "agent.registered"

    def test_stats(self):
        s = EventStats(pending=5, delivered=100, failed=2, dead_letter=1, delivery_rate=98.0)
        assert s.delivery_rate == 98.0


class TestMiscModels:
    def test_enforcement_decision(self):
        d = EnforcementDecision(allowed=True, reason="policy allows")
        assert d.allowed is True

    def test_enforcement_decision_ep221_fields(self):
        d = EnforcementDecision(
            allowed=False,
            reason="device_context_missing",
            context_snapshot_id="pcs_py",
            context_snapshot_digest="sha256:py",
            context_snapshot={
                "schema_version": "kswitch.policy_context.v1",
                "replay": {
                    "request_hash": "sha256:req",
                    "context_hash": "sha256:ctx",
                    "pdp_input_hash": "sha256:pdp",
                },
                "integrity": {
                    "binding_state": "append_only_audit_record_bound",
                    "snapshot_binding_digest": "sha256:binding",
                    "audit_record_id": "audit_ep221",
                },
            },
            decision_explanation={
                "schema_version": "kswitch.decision_explanation.v1",
                "outcome": "deny",
            },
        )

        assert d.context_snapshot_id == "pcs_py"
        assert d.context_snapshot_digest == "sha256:py"
        assert isinstance(d.context_snapshot, PolicyContextSnapshot)
        assert isinstance(d.decision_explanation, DecisionExplanation)
        assert d.context_snapshot.schema_version == "kswitch.policy_context.v1"
        assert d.context_snapshot.replay["pdp_input_hash"] == "sha256:pdp"
        assert d.context_snapshot.integrity["audit_record_id"] == "audit_ep221"
        assert d.decision_explanation.outcome == "deny"

    def test_boundary_analysis(self):
        b = BoundaryAnalysis(agent_id="a1", tier_violations=[{"from": "t3", "to": "t1"}])
        assert len(b.tier_violations) == 1

    def test_risk_score(self):
        r = RiskScore(agent_id="a1", score=150, level="high")
        assert r.level == "high"

    def test_gate_status(self):
        g = GateStatus(mcp_id="m1", all_passed=True)
        assert g.all_passed is True

    def test_skill(self):
        s = Skill(id="s1", name="web-search", category="retrieval")
        assert s.category == "retrieval"

    def test_tool(self):
        t = Tool(id="t1", name="read-db", mcp_server_id="mcp-1")
        assert t.mcp_server_id == "mcp-1"

    def test_dashboard(self):
        d = Dashboard(total_agents=50, total_mcp_servers=10)
        assert d.total_agents == 50

    def test_fleet_risk_summary(self):
        s = FleetRiskSummary(
            total_agents=100,
            distribution={"clean": 80, "low": 10, "medium": 5, "high": 3, "critical": 2},
        )
        assert s.distribution["clean"] == 80
