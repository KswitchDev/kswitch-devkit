"""Parity test: local decision matches server response shape for standard scenarios.

The LocalDecision fields and the server EnforcementDecision should map
consistently for the standard allow/deny scenarios. This verifies the
_local_to_decision() converter produces a structurally compatible object.
"""
from unittest.mock import MagicMock, patch

import pytest

from kswitch.interceptor import _local_to_decision
from kswitch.local_pdp.evaluator import LocalDecision
from kswitch.models import EnforcementDecision, Obligation, OutputPolicy


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"
TOOL = "initiate_payment"


def _local_allow(obligations=None, output_policy=None):
    return LocalDecision(
        outcome="allow",
        reason="allowed",
        allowed=True,
        decision_path=["local_sdk", "cedar_allowed", "enforcement_complete"],
        obligations=obligations or [],
        output_policy=output_policy or {"mode": "allow_raw", "masking_classifications": []},
        enforcement_id="local-dec-abc",
        evaluation_mode="LOCAL_RUNTIME_PYTHON",
        bundle_version="bundle:v5",
        context_pack_id="cp:v3",
        risk_tier="medium",
        agent_id=AGENT_ID,
        mcp_server_id=MCP_ID,
        tool_name=TOOL,
    )


def _local_deny():
    return LocalDecision(
        outcome="deny",
        reason="policy_denied",
        allowed=False,
        decision_path=["local_sdk", "cedar_denied"],
        enforcement_id="local-dec-xyz",
        evaluation_mode="LOCAL_RUNTIME_PYTHON",
        bundle_version="bundle:v5",
        context_pack_id="cp:v3",
        risk_tier="medium",
        agent_id=AGENT_ID,
        mcp_server_id=MCP_ID,
        tool_name=TOOL,
    )


class TestLocalToDecisionConversion:
    def test_allow_fields_match(self):
        ld = _local_allow()
        ed = _local_to_decision(ld)

        assert isinstance(ed, EnforcementDecision)
        assert ed.allowed == ld.allowed
        assert ed.reason == ld.reason
        assert ed.outcome == ld.outcome
        assert ed.decision_path == ld.decision_path
        assert ed.enforcement_id == ld.enforcement_id
        assert ed.evaluation_mode == ld.evaluation_mode
        assert ed.bundle_version == ld.bundle_version
        assert ed.context_pack_id == ld.context_pack_id

    def test_ep221_fields_match(self):
        ld = _local_allow()
        ld.context_snapshot_id = "pcs_local_py"
        ld.context_snapshot_digest = "sha256:local"
        ld.context_snapshot = {"schema_version": "kswitch.policy_context.v1"}
        ld.decision_explanation = {"outcome": "allow"}

        ed = _local_to_decision(ld)

        assert ed.context_snapshot_id == ld.context_snapshot_id
        assert ed.context_snapshot_digest == ld.context_snapshot_digest
        assert ed.context_snapshot is not None
        assert ed.decision_explanation is not None
        assert ed.context_snapshot.schema_version == "kswitch.policy_context.v1"
        assert ed.decision_explanation.outcome == "allow"

    def test_deny_fields_match(self):
        ld = _local_deny()
        ed = _local_to_decision(ld)

        assert ed.allowed is False
        assert ed.reason == "policy_denied"
        assert ed.outcome == "deny"

    def test_output_policy_converted(self):
        ld = _local_allow(output_policy={"mode": "mask_fields", "masking_classifications": ["PII"]})
        ed = _local_to_decision(ld)

        assert ed.output_policy is not None
        assert isinstance(ed.output_policy, OutputPolicy)
        assert ed.output_policy.mode == "mask_fields"
        assert "PII" in ed.output_policy.masking_classifications

    def test_obligations_converted(self):
        obligations = [
            {"type": "audit_flag", "obligation_type": "audit_flag", "level": "low", "detail": "test"},
        ]
        ld = _local_allow(obligations=obligations)
        ed = _local_to_decision(ld)

        assert len(ed.obligations) == 1
        ob = ed.obligations[0]
        assert isinstance(ob, Obligation)
        assert ob.type == "audit_flag"
        assert ob.obligation_type == "audit_flag"
        assert ob.level == "low"

    def test_no_output_policy_converts_to_none(self):
        ld = LocalDecision(
            outcome="allow",
            reason="allowed",
            allowed=True,
            output_policy=None,
        )
        ed = _local_to_decision(ld)
        assert ed.output_policy is None

    def test_empty_obligations_converts_to_empty_list(self):
        ld = _local_allow(obligations=[])
        ed = _local_to_decision(ld)
        assert ed.obligations == []


class TestDecisionShapeCompatibility:
    def test_local_allow_shape_matches_server_shape(self):
        """The EnforcementDecision fields from local and server paths are both valid."""
        # Local path
        ld = _local_allow()
        local_ed = _local_to_decision(ld)

        # Server path (simulated)
        server_ed = EnforcementDecision(
            allowed=True,
            reason="allowed",
            outcome="allow",
            decision_path=["cedar_allowed"],
            obligations=[],
            output_policy=OutputPolicy(mode="allow_raw", masking_classifications=[]),
            enforcement_id="server-dec-abc",
            evaluation_mode="central",
            bundle_version="bundle:v5",
            context_pack_id="cp:v3",
        )

        # Both have the same field structure
        assert hasattr(local_ed, "allowed")
        assert hasattr(local_ed, "reason")
        assert hasattr(local_ed, "outcome")
        assert hasattr(local_ed, "decision_path")
        assert hasattr(local_ed, "obligations")
        assert hasattr(local_ed, "output_policy")
        assert hasattr(local_ed, "enforcement_id")
        assert hasattr(local_ed, "evaluation_mode")
        assert hasattr(local_ed, "bundle_version")
        assert hasattr(local_ed, "context_pack_id")

        assert local_ed.allowed == server_ed.allowed
        assert local_ed.outcome == server_ed.outcome

    def test_local_deny_shape_matches_server_deny_shape(self):
        ld = _local_deny()
        local_ed = _local_to_decision(ld)

        server_ed = EnforcementDecision(
            allowed=False,
            reason="policy_denied",
            outcome="deny",
            enforcement_id="server-dec-xyz",
            evaluation_mode="central",
        )

        assert local_ed.allowed == server_ed.allowed
        assert local_ed.outcome == server_ed.outcome
        assert local_ed.reason == server_ed.reason


class TestInterceptorLocalVsServerBehavior:
    def test_local_allow_and_server_allow_produce_same_result(self, tmp_path):
        """The tool output is the same whether allowed locally or via server."""
        from kswitch.interceptor import KSwitchInterceptor
        from kswitch.audit import emitter as audit_mod
        from kswitch.audit.emitter import AuditEmitter
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        tool_output = {"status": "success", "amount": 100}
        tool_fn = MagicMock(return_value=tool_output)

        try:
            # Local allow path
            mock_client = MagicMock()
            interceptor = KSwitchInterceptor(mock_client)

            local_decision = _local_allow()
            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = local_decision
                local_result = interceptor.check_and_invoke(
                    agent_id=AGENT_ID,
                    mcp_server_id=MCP_ID,
                    tool_name=TOOL,
                    tool_fn=tool_fn,
                )

            # Server allow path
            conditional_decision = LocalDecision(
                outcome="conditional", reason="bundle_miss", allowed=False,
                agent_id=AGENT_ID, mcp_server_id=MCP_ID, tool_name=TOOL,
            )
            server_ed = EnforcementDecision(
                allowed=True, reason="allowed", outcome="allow",
                output_policy=OutputPolicy(mode="allow_raw"),
            )
            mock_client.enforcement.enforce_mcp_call.return_value = server_ed

            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = conditional_decision
                server_result = interceptor.check_and_invoke(
                    agent_id=AGENT_ID,
                    mcp_server_id=MCP_ID,
                    tool_name=TOOL,
                    tool_fn=tool_fn,
                )

            # Both paths return the same tool output
            assert local_result == server_result == tool_output

        finally:
            audit_mod._emitter = original_emitter
