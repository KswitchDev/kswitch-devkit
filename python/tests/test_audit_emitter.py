"""Tests for AuditEmitter — JSONL file writing, field presence, rotation."""
import json
import os
import time

import pytest

from kswitch.audit.emitter import AuditEmitter, emit_decision_event, _build_event


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"
TOOL = "initiate_payment"


class TestAuditEmitterWrite:
    def test_emit_creates_file(self, tmp_path):
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        emitter.emit({"event_type": "test", "agent_id": AGENT_ID})
        events_path = os.path.join(str(tmp_path), "events.jsonl")
        assert os.path.exists(events_path)

    def test_emit_writes_valid_json(self, tmp_path):
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        emitter.emit({"event_type": "enforcement.allow", "agent_id": AGENT_ID})
        events_path = os.path.join(str(tmp_path), "events.jsonl")
        with open(events_path) as f:
            line = f.readline().strip()
        event = json.loads(line)
        assert event["event_type"] == "enforcement.allow"
        assert event["agent_id"] == AGENT_ID

    def test_emit_multiple_rows(self, tmp_path):
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        for i in range(5):
            emitter.emit({"event_type": f"test_{i}", "agent_id": AGENT_ID})
        events_path = os.path.join(str(tmp_path), "events.jsonl")
        with open(events_path) as f:
            lines = f.readlines()
        assert len(lines) == 5

    def test_emit_never_raises(self, tmp_path):
        emitter = AuditEmitter(audit_dir="/nonexistent/path/that/cannot/exist")
        # Should not raise even with bad path
        emitter.emit({"event_type": "test"})

    def test_emit_creates_directory(self, tmp_path):
        audit_dir = os.path.join(str(tmp_path), "deep", "audit")
        emitter = AuditEmitter(audit_dir=audit_dir)
        emitter.emit({"event_type": "test"})
        assert os.path.exists(audit_dir)


class TestBuildEvent:
    def test_required_fields_present(self):
        event = _build_event(
            event_type="enforcement.allow",
            agent_id=AGENT_ID,
            mcp_server_id=MCP_ID,
            tool_name=TOOL,
            allowed=True,
            reason="allowed",
            decision_id="dec-123",
            decision_path=["local_sdk", "cedar_allowed"],
            obligations=[],
            output_policy={"mode": "allow_raw"},
            evaluation_mode="LOCAL_RUNTIME_PYTHON",
            bundle_version="bundle:v5",
            context_pack_id="cp:v3",
            risk_tier="high",
            elapsed_ms=12.5,
        )
        # Required fields
        assert event["event_id"]
        assert event["event_type"] == "enforcement.allow"
        assert event["event_version"] == "1.0"
        assert event["agent_id"] == AGENT_ID
        assert event["mcp_server_id"] == MCP_ID
        assert event["tool_name"] == TOOL
        assert event["decision_id"] == "dec-123"
        assert event["allowed"] is True
        assert event["outcome"] == "allow"
        assert event["reason"] == "allowed"
        assert event["decision_path"] == ["local_sdk", "cedar_allowed"]
        assert event["bundle_version"] == "bundle:v5"
        assert event["context_pack_id"] == "cp:v3"
        assert event["risk_tier"] == "high"
        assert event["runtime_mode"] == "LOCAL_RUNTIME_PYTHON"
        assert event["elapsed_ms"] == 12.5
        assert event["evaluated_at"]
        assert event["output_policy_mode"] == "allow_raw"

    def test_deny_event_outcome(self):
        event = _build_event(
            event_type="enforcement.deny",
            agent_id=AGENT_ID,
            mcp_server_id=MCP_ID,
            tool_name=TOOL,
            allowed=False,
            reason="agent_revoked",
            decision_id="dec-456",
            decision_path=[],
            obligations=[],
            output_policy=None,
            evaluation_mode="LOCAL_RUNTIME_PYTHON",
        )
        assert event["outcome"] == "deny"
        assert event["allowed"] is False
        assert event["output_policy_mode"] == ""

    def test_event_id_is_unique(self):
        args = dict(
            event_type="test",
            agent_id=AGENT_ID,
            mcp_server_id=MCP_ID,
            tool_name=TOOL,
            allowed=True,
            reason="test",
            decision_id="x",
            decision_path=[],
            obligations=[],
            output_policy=None,
            evaluation_mode="LOCAL_RUNTIME_PYTHON",
        )
        e1 = _build_event(**args)
        e2 = _build_event(**args)
        assert e1["event_id"] != e2["event_id"]


class TestEmitDecisionEvent:
    def test_emit_allow_event(self, tmp_path, monkeypatch):
        from kswitch.audit import emitter as mod
        original_emitter = mod._emitter
        mod._emitter = AuditEmitter(audit_dir=str(tmp_path))
        try:
            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=True,
                reason="allowed",
                decision_id="test-dec",
                bundle_version="bundle:v5",
                risk_tier="medium",
            )
            events_path = os.path.join(str(tmp_path), "events.jsonl")
            with open(events_path) as f:
                event = json.loads(f.readline())
            assert event["allowed"] is True
            assert event["bundle_version"] == "bundle:v5"
        finally:
            mod._emitter = original_emitter

    def test_emit_generates_decision_id_when_missing(self, tmp_path):
        from kswitch.audit import emitter as mod
        original = mod._emitter
        mod._emitter = AuditEmitter(audit_dir=str(tmp_path))
        try:
            emit_decision_event(
                event_type="enforcement.deny",
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                allowed=False,
                reason="denied",
                decision_id="",  # Empty — should auto-generate
            )
            events_path = os.path.join(str(tmp_path), "events.jsonl")
            with open(events_path) as f:
                event = json.loads(f.readline())
            assert event["decision_id"]  # Auto-generated UUID
        finally:
            mod._emitter = original


class TestAuditRotation:
    def test_rotation_on_large_file(self, tmp_path):
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        events_path = os.path.join(str(tmp_path), "events.jsonl")
        # Create a "large" file (simulate > MAX_FILE_SIZE)
        from kswitch.audit.emitter import _MAX_FILE_SIZE
        with open(events_path, "w") as f:
            f.write("x" * (_MAX_FILE_SIZE + 1))
        emitter.emit({"event_type": "test"})
        # Original should be rotated (renamed), new file exists
        assert os.path.exists(events_path)
        rotated = [f for f in os.listdir(str(tmp_path)) if f.startswith("events.jsonl.")]
        assert len(rotated) >= 1
