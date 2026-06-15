"""Integration test: governed invocation produces audit row with required fields."""
import json
import os
from unittest.mock import MagicMock, patch, call

import pytest

from kswitch.invoke import KSwitchRuntime
from kswitch.audit.emitter import AuditEmitter
from kswitch.local_pdp.evaluator import LocalDecision


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"
TOOL = "initiate_payment"

_REQUIRED_AUDIT_FIELDS = {
    "event_id", "event_type", "event_version",
    "agent_id", "mcp_server_id", "tool_name", "action",
    "decision_id", "allowed", "outcome", "reason",
    "decision_path", "obligations", "output_policy_mode",
    "bundle_version", "context_pack_id", "risk_tier", "runtime_mode",
    "elapsed_ms", "evaluated_at",
}


def _make_allow_decision():
    return LocalDecision(
        outcome="allow",
        reason="allowed",
        allowed=True,
        decision_path=["local_sdk", "agent_active", "bundle_v5", "no_policies", "enforcement_complete"],
        output_policy={"mode": "allow_raw", "masking_classifications": []},
        bundle_version="bundle:v5",
        context_pack_id="cp:v3",
        risk_tier="medium",
        agent_id=AGENT_ID,
        mcp_server_id=MCP_ID,
        tool_name=TOOL,
    )


class TestSDKEventFlow:
    def test_allow_decision_produces_audit_row(self, tmp_path):
        """Full flow: runtime.invoke() → local allow → audit row in events.jsonl."""
        # Redirect audit emitter to tmp dir
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            tool_fn = MagicMock(return_value={"result": "ok"})
            runtime.register(TOOL, tool_fn)

            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = _make_allow_decision()
                result = runtime.invoke(TOOL)

            assert result == {"result": "ok"}

            # Verify audit row
            events_path = os.path.join(str(tmp_path), "events.jsonl")
            assert os.path.exists(events_path)
            with open(events_path) as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "enforcement.allow"
            assert event["agent_id"] == AGENT_ID
            assert event["mcp_server_id"] == MCP_ID
            assert event["tool_name"] == TOOL
            assert event["allowed"] is True
            assert event["outcome"] == "allow"
            assert event["bundle_version"] == "bundle:v5"
            assert event["context_pack_id"] == "cp:v3"
            assert event["runtime_mode"] == "LOCAL_RUNTIME_PYTHON"

        finally:
            audit_mod._emitter = original_emitter

    def test_deny_decision_produces_audit_row(self, tmp_path):
        """Deny flow: runtime.invoke() → local deny → audit row with deny outcome."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            runtime.register(TOOL, MagicMock())
            deny_decision = LocalDecision(
                outcome="deny",
                reason="agent_revoked",
                allowed=False,
                decision_path=["local_sdk", "revocation_cache_hit"],
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
            )

            from kswitch.interceptor import KSwitchEnforcementError
            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = deny_decision
                with pytest.raises(KSwitchEnforcementError):
                    runtime.invoke(TOOL)

            events_path = os.path.join(str(tmp_path), "events.jsonl")
            assert os.path.exists(events_path)
            with open(events_path) as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "enforcement.revocation_deny"
            assert event["allowed"] is False
            assert event["outcome"] == "deny"
            assert event["reason"] == "agent_revoked"

        finally:
            audit_mod._emitter = original_emitter

    def test_audit_row_has_all_required_fields(self, tmp_path):
        """Verify the complete set of required audit fields is present."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            runtime.register(TOOL, MagicMock(return_value={}))

            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = _make_allow_decision()
                runtime.invoke(TOOL)

            events_path = os.path.join(str(tmp_path), "events.jsonl")
            with open(events_path) as f:
                event = json.loads(f.readline())

            missing = _REQUIRED_AUDIT_FIELDS - set(event.keys())
            assert not missing, f"Missing required audit fields: {missing}"

        finally:
            audit_mod._emitter = original_emitter

    def test_each_decision_gets_unique_event_id(self, tmp_path):
        """Each invocation should produce an audit row with unique event_id."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            runtime.register(TOOL, MagicMock(return_value={}))

            for _ in range(3):
                with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                    mock_ev.return_value.evaluate.return_value = _make_allow_decision()
                    runtime.invoke(TOOL)

            events_path = os.path.join(str(tmp_path), "events.jsonl")
            with open(events_path) as f:
                event_ids = [json.loads(l)["event_id"] for l in f]

            assert len(set(event_ids)) == 3

        finally:
            audit_mod._emitter = original_emitter

    # ── PR-12: Central forwarding tests ───────────────────────────────────────

    def test_emit_enqueues_to_sender_when_configured(self, tmp_path):
        """set_sender on emitter → emit_decision_event → sender.enqueue called."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        audit_mod._emitter = emitter

        mock_sender = MagicMock()
        emitter.set_sender(mock_sender)

        try:
            from kswitch.audit.emitter import emit_decision_event
            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=True,
                reason="allowed",
            )
            mock_sender.enqueue.assert_called_once()
            enqueued_event = mock_sender.enqueue.call_args[0][0]
            assert enqueued_event["agent_id"] == AGENT_ID
            assert enqueued_event["allowed"] is True
        finally:
            audit_mod._emitter = original_emitter

    def test_jsonl_written_even_if_sender_fails(self, tmp_path):
        """sender raises on enqueue → JSONL file still has the event."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        audit_mod._emitter = emitter

        bad_sender = MagicMock()
        bad_sender.enqueue.side_effect = RuntimeError("sender exploded")
        emitter.set_sender(bad_sender)

        try:
            from kswitch.audit.emitter import emit_decision_event
            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=True,
                reason="allowed",
            )
            events_path = os.path.join(str(tmp_path), "events.jsonl")
            assert os.path.exists(events_path)
            with open(events_path) as f:
                event = json.loads(f.readline())
            assert event["agent_id"] == AGENT_ID
        finally:
            audit_mod._emitter = original_emitter

    def test_allow_and_deny_both_forwarded(self, tmp_path):
        """Both allow and deny event types are enqueued to sender."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        audit_mod._emitter = emitter

        mock_sender = MagicMock()
        emitter.set_sender(mock_sender)

        try:
            from kswitch.audit.emitter import emit_decision_event
            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=True,
                reason="allowed",
            )
            emit_decision_event(
                event_type="enforcement.deny",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=False,
                reason="policy_violation",
            )
            assert mock_sender.enqueue.call_count == 2
            calls = mock_sender.enqueue.call_args_list
            event_types = [c[0][0]["event_type"] for c in calls]
            assert "enforcement.allow" in event_types
            assert "enforcement.deny" in event_types
        finally:
            audit_mod._emitter = original_emitter
