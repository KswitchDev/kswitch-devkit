"""Tests for LocalPDPEvaluator — allow, deny, revocation, conditional escalation."""
import hashlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from kswitch.local_pdp.evaluator import LocalDecision, LocalPDPEvaluator


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"
TOOL = "initiate_payment"


def _make_bundle(enforce_count=1, shadow_count=0, tool_index=None, version=5):
    """Build a mock LocalBundle."""
    from kswitch.bundle.local_cache import LocalBundle
    return LocalBundle(
        version=version,
        bundle_id=f"bundle:v{version}",
        compiled_at="2026-03-28T21:00:00Z",
        cedar_text_enforce='permit(principal, action, resource);',
        cedar_text_shadow="",
        enforce_count=enforce_count,
        shadow_count=shadow_count,
        tool_count=len(tool_index or {}),
        tool_index=tool_index or {},
    )


def _make_context(status="active", risk_tier="medium", data_classifications=None,
                  is_revoked=False, pack_version=3):
    """Build a mock LocalContextPack."""
    from kswitch.context.local_cache import LocalContextPack
    return LocalContextPack(
        agent_id=AGENT_ID,
        status=status,
        risk_tier=risk_tier,
        data_classifications=data_classifications or [],
        is_revoked=is_revoked,
        pack_version=pack_version,
    )


class TestLocalPDPRevocationDeny:
    def test_revoked_agent_denied(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = True
            decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "deny"
        assert decision.reason == "agent_revoked"
        assert not decision.allowed
        assert "revocation_cache_hit" in decision.decision_path

    def test_non_revoked_agent_proceeds(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = None
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        # Should escalate due to missing context (medium risk)
        assert decision.outcome == "conditional"


class TestLocalPDPContextMiss:
    def test_context_miss_medium_escalates(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = None
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL, context={"risk_tier": "medium"})
        assert decision.outcome == "conditional"
        assert decision.reason == "context_pack_miss"

    def test_context_miss_high_denies(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = None
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL, context={"risk_tier": "high"})
        assert decision.outcome == "deny"
        assert decision.reason == "context_pack_unavailable"

    def test_context_miss_critical_denies(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = None
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL, context={"risk_tier": "critical"})
        assert decision.outcome == "deny"


class TestLocalPDPAgentStatus:
    def test_suspended_agent_denied(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context(status="suspended")
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "deny"
        assert decision.reason == "agent_suspended"

    def test_inactive_agent_denied(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context(status="revoked")
                decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "deny"
        assert decision.allowed is False


class TestLocalPDPBundleMiss:
    def test_bundle_miss_escalates(self):
        ev = LocalPDPEvaluator()
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context()
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = None
                    decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "conditional"
        assert decision.reason == "bundle_unavailable"


class TestLocalPDPCedarpy:
    def test_cedarpy_unavailable_escalates(self):
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = False
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context()
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle()
                    decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "conditional"
        assert decision.reason == "cedarpy_unavailable"

    def test_no_policies_allows(self):
        """When enforce_count=0, no Cedar evaluation needed — allow."""
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = True
        # Mock cedarpy module
        mock_cedar = MagicMock()
        mock_cedar.Decision.Deny = "Deny"
        mock_cedar.is_authorized.return_value = MagicMock(decision="Allow")
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context()
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle(enforce_count=0)
                    with patch.dict("sys.modules", {"cedarpy": mock_cedar}):
                        decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "allow"
        assert decision.allowed is True
        assert "no_policies" in decision.decision_path

    def test_cedar_allow(self):
        """Cedar returns Allow → local allow decision."""
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = True
        mock_cedar = MagicMock()
        mock_cedar.Decision.Deny = "Deny"
        mock_cedar.is_authorized.return_value = MagicMock(decision="Allow")
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context()
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle(enforce_count=1)
                    with patch.dict("sys.modules", {"cedarpy": mock_cedar}):
                        decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "allow"

    def test_cedar_deny(self):
        """Cedar returns Deny → local deny decision."""
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = True
        mock_cedar = MagicMock()
        mock_cedar.Decision.Deny = "Deny"
        mock_cedar.is_authorized.return_value = MagicMock(decision="Deny")
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context()
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle(enforce_count=1)
                    with patch.dict("sys.modules", {"cedarpy": mock_cedar}):
                        decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.outcome == "deny"
        assert decision.reason == "policy_denied"
        assert "cedar_denied" in decision.decision_path


class TestLocalPDPOutputPolicy:
    def test_pii_classification_masks_fields(self):
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = True
        mock_cedar = MagicMock()
        mock_cedar.Decision.Deny = "Deny"
        mock_cedar.is_authorized.return_value = MagicMock(decision="Allow")
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context(data_classifications=["PII"])
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle(enforce_count=0)
                    with patch.dict("sys.modules", {"cedarpy": mock_cedar}):
                        decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.output_policy is not None
        assert decision.output_policy["mode"] == "mask_fields"
        assert "PII" in decision.output_policy["masking_classifications"]

    def test_no_sensitive_classification_allows_raw(self):
        ev = LocalPDPEvaluator()
        ev._cedarpy_available = True
        mock_cedar = MagicMock()
        mock_cedar.Decision.Deny = "Deny"
        mock_cedar.is_authorized.return_value = MagicMock(decision="Allow")
        with patch("kswitch.local_pdp.evaluator.get_revocation_cache") as mock_rev:
            mock_rev.return_value.is_revoked.return_value = False
            with patch("kswitch.local_pdp.evaluator.load_context_pack") as mock_ctx:
                mock_ctx.return_value = _make_context(data_classifications=[])
                with patch("kswitch.local_pdp.evaluator.load_current_bundle") as mock_bun:
                    mock_bun.return_value = _make_bundle(enforce_count=0)
                    with patch.dict("sys.modules", {"cedarpy": mock_cedar}):
                        decision = ev.evaluate(AGENT_ID, MCP_ID, TOOL)
        assert decision.output_policy["mode"] == "allow_raw"


class TestLocalDecisionProperties:
    def test_is_local_for_allow(self):
        d = LocalDecision(outcome="allow", reason="allowed", allowed=True)
        assert d.is_local
        assert not d.needs_escalation

    def test_is_local_for_deny(self):
        d = LocalDecision(outcome="deny", reason="denied", allowed=False)
        assert d.is_local
        assert not d.needs_escalation

    def test_needs_escalation_for_conditional(self):
        d = LocalDecision(outcome="conditional", reason="bundle_miss", allowed=False)
        assert not d.is_local
        assert d.needs_escalation

    @pytest.mark.parametrize(
        ("outcome", "reason", "allowed"),
        [
            ("allow", "allowed", True),
            ("deny", "policy_denied", False),
            ("conditional", "bundle_unavailable", False),
        ],
    )
    def test_ep221_local_decision_generates_bounded_evidence(self, outcome, reason, allowed):
        raw_values = [
            "agent:alice.sensitive@example.internal",
            "mcp:payroll@example.internal",
            "export_salary_records",
        ]
        d = LocalDecision(
            outcome=outcome,
            reason=reason,
            allowed=allowed,
            decision_path=["local_sdk", "cedar_denied"],
            agent_id=raw_values[0],
            mcp_server_id=raw_values[1],
            tool_name=raw_values[2],
            bundle_version="bundle:v7",
            context_pack_id="cp:v9",
        )

        assert d.context_snapshot_id.startswith("pcs_")
        assert d.context_snapshot_digest.startswith("sha256:")
        assert d.context_snapshot["schema_version"] == "kswitch.policy_context.v1"
        assert d.context_snapshot["context_snapshot_id"] == d.context_snapshot_id
        assert d.context_snapshot["decision_id"] == d.enforcement_id
        assert d.context_snapshot["mode"]["evaluation_mode"] == "local_pdp"
        assert "identity.agent_id" in d.context_snapshot["source_status"]["present_deterministic"]
        assert d.decision_explanation["schema_version"] == "kswitch.decision_explanation.v1"
        assert d.decision_explanation["context_snapshot_id"] == d.context_snapshot_id
        assert d.decision_explanation["outcome"] == outcome
        assert d.decision_explanation["policy_attribution"]["matched_policy_ids"] == []
        assert d.decision_explanation["policy_attribution"]["attribution_state"] == "unavailable_until_per_policy_eval"
        assert d.decision_explanation["policy_attribution"]["attribution_method"] == "local_pdp_aggregate_bundle_without_per_policy_eval"

        serialized = json.dumps({
            "snapshot": d.context_snapshot,
            "explanation": d.decision_explanation,
        })
        for raw in raw_values:
            assert raw not in serialized

    def test_ep221_fields_are_optional(self):
        d = LocalDecision(
            outcome="allow",
            reason="allowed",
            allowed=True,
            context_snapshot_id="pcs_local_py",
            context_snapshot_digest="sha256:local",
            context_snapshot={"schema_version": "kswitch.policy_context.v1"},
            decision_explanation={"outcome": "allow"},
        )

        assert d.context_snapshot_id == "pcs_local_py"
        assert d.context_snapshot_digest == "sha256:local"
        assert d.context_snapshot["schema_version"] == "kswitch.policy_context.v1"
        assert d.decision_explanation["outcome"] == "allow"
