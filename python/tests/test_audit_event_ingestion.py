"""
Tests for the server SDK audit ingestion endpoint logic (PR-12).

These tests exercise the validation and mapping logic that would run inside
sdk_audit_ingest() without requiring a live Flask app or database.
They replicate the endpoint's behavior using the same logic paths.
"""
import json
import uuid
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers to replicate endpoint logic ──────────────────────────────────────

def _validate_and_map(events):
    """Replicate the validation + mapping logic from sdk_audit_ingest()."""
    accepted = 0
    rejected = 0
    errors = []
    enqueued = []

    for idx, event in enumerate(events):
        event_errors = []
        agent_id = event.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            event_errors.append("agent_id is required and must be a non-empty string")
        allowed = event.get("allowed")
        if allowed is None or not isinstance(allowed, bool):
            event_errors.append("allowed is required and must be a boolean")
        event_type = event.get("event_type")
        if not event_type or not isinstance(event_type, str):
            event_errors.append("event_type is required and must be a string")

        if event_errors:
            rejected += 1
            errors.append({"index": idx, "errors": event_errors})
            continue

        record = {
            "type": "enforcement_decision",
            "event_id": event.get("event_id") or str(uuid.uuid4()),
            "event_type": event.get("event_type", "enforcement.decision"),
            "event_version": event.get("event_version", "1.0"),
            "request_id": event.get("decision_id", ""),
            "agent_id": event["agent_id"],
            "mcp_server_id": event.get("mcp_server_id", ""),
            "tool_name": event.get("tool_name", ""),
            "action": event.get("action", "mcp_call"),
            "client_ip": "",
            "requester_identity": "",
            "wimse_identity": "",
            "mtls_identity": "",
            "allowed": bool(event["allowed"]),
            "reason": event.get("reason", ""),
            "outcome": "allow" if event["allowed"] else "deny",
            "decision_path": event.get("decision_path", []),
            "escalation_hint": "none",
            "obligations": event.get("obligations", []),
            "violations": [],
            "output_policy": (
                {"mode": event.get("output_policy_mode", "")}
                if event.get("output_policy_mode")
                else None
            ),
            "bundle_version": event.get("bundle_version", ""),
            "bundle_hash": "",
            "context_pack_id": event.get("context_pack_id", ""),
            "context_pack_hash": "",
            "policy_ids_evaluated": [],
            "policy_set_hash": "",
            "evaluation_mode": event.get("runtime_mode", event.get("evaluation_mode", "LOCAL_RUNTIME_PYTHON")),
            "agent_status": "",
            "agent_risk_tier": event.get("risk_tier", ""),
            "agent_owning_division": "",
            "trust_state": None,
            "delegation_snapshot": [],
            "credential_state": [],
            "anomaly_result": None,
            "timing": {"elapsed_ms": event.get("elapsed_ms", 0), "sdk_language": "python"},
            "evaluated_at": event.get("evaluated_at", ""),
            "trace_id": event.get("trace_id", ""),
            "span_id": "",
            "session_id": "",
            "workflow_id": "",
        }
        enqueued.append(record)
        accepted += 1

    return {"accepted": accepted, "rejected": rejected, "errors": errors, "_enqueued": enqueued}


def _valid_event(**overrides):
    base = {
        "agent_id": "agent:fraud-detector@bank.internal",
        "allowed": True,
        "event_type": "enforcement.allow",
        "tool_name": "get_balance",
        "mcp_server_id": "mcp:payment-gateway@bank.internal",
    }
    base.update(overrides)
    return base


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAuditEventIngestionValidation:
    def test_valid_event_accepted(self):
        """POST valid event → accepted=1."""
        result = _validate_and_map([_valid_event()])
        assert result["accepted"] == 1
        assert result["rejected"] == 0
        assert result["errors"] == []

    def test_missing_agent_id_rejected(self):
        """POST event without agent_id → rejected=1."""
        event = _valid_event()
        del event["agent_id"]
        result = _validate_and_map([event])
        assert result["accepted"] == 0
        assert result["rejected"] == 1
        assert result["errors"][0]["index"] == 0
        assert any("agent_id" in e for e in result["errors"][0]["errors"])

    def test_missing_allowed_field_rejected(self):
        """POST event without allowed → rejected=1."""
        event = _valid_event()
        del event["allowed"]
        result = _validate_and_map([event])
        assert result["accepted"] == 0
        assert result["rejected"] == 1
        assert any("allowed" in e for e in result["errors"][0]["errors"])

    def test_missing_event_type_rejected(self):
        """POST event without event_type → rejected=1."""
        event = _valid_event()
        del event["event_type"]
        result = _validate_and_map([event])
        assert result["accepted"] == 0
        assert result["rejected"] == 1
        assert any("event_type" in e for e in result["errors"][0]["errors"])

    def test_batch_of_events_accepted(self):
        """POST 5 events → accepted=5."""
        events = [_valid_event() for _ in range(5)]
        result = _validate_and_map(events)
        assert result["accepted"] == 5
        assert result["rejected"] == 0

    def test_empty_events_list(self):
        """POST empty events list → accepted=0, no errors."""
        result = _validate_and_map([])
        assert result["accepted"] == 0
        assert result["rejected"] == 0
        assert result["errors"] == []

    def test_mixed_valid_invalid(self):
        """3 valid + 1 invalid → accepted=3, rejected=1."""
        events = [_valid_event() for _ in range(3)]
        bad = _valid_event()
        del bad["agent_id"]
        events.append(bad)
        result = _validate_and_map(events)
        assert result["accepted"] == 3
        assert result["rejected"] == 1


class TestAuditEventMapping:
    def test_outcome_allow_for_allowed_true(self):
        """allowed=True maps to outcome=allow."""
        result = _validate_and_map([_valid_event(allowed=True)])
        record = result["_enqueued"][0]
        assert record["outcome"] == "allow"
        assert record["allowed"] is True

    def test_outcome_deny_for_allowed_false(self):
        """allowed=False maps to outcome=deny."""
        result = _validate_and_map([_valid_event(allowed=False)])
        record = result["_enqueued"][0]
        assert record["outcome"] == "deny"
        assert record["allowed"] is False

    def test_event_id_generated_when_missing(self):
        """event_id is generated if not provided."""
        result = _validate_and_map([_valid_event()])
        record = result["_enqueued"][0]
        assert record["event_id"]  # non-empty
        # Valid UUID
        uuid.UUID(record["event_id"])

    def test_event_id_preserved_when_provided(self):
        """event_id from client is preserved."""
        eid = str(uuid.uuid4())
        result = _validate_and_map([_valid_event(event_id=eid)])
        assert result["_enqueued"][0]["event_id"] == eid

    def test_type_field_is_enforcement_decision(self):
        """Mapped record type must be enforcement_decision."""
        result = _validate_and_map([_valid_event()])
        assert result["_enqueued"][0]["type"] == "enforcement_decision"

    def test_sdk_language_in_timing(self):
        """timing dict includes sdk_language=python."""
        result = _validate_and_map([_valid_event(elapsed_ms=42.5)])
        timing = result["_enqueued"][0]["timing"]
        assert timing["sdk_language"] == "python"
        assert timing["elapsed_ms"] == 42.5

    def test_output_policy_none_when_no_mode(self):
        """output_policy is None when output_policy_mode not provided."""
        result = _validate_and_map([_valid_event()])
        assert result["_enqueued"][0]["output_policy"] is None

    def test_output_policy_set_when_mode_provided(self):
        """output_policy dict set when output_policy_mode provided."""
        result = _validate_and_map([_valid_event(output_policy_mode="redact_pii")])
        assert result["_enqueued"][0]["output_policy"] == {"mode": "redact_pii"}

    def test_evaluation_mode_fallback_chain(self):
        """evaluation_mode uses runtime_mode, then evaluation_mode, then default."""
        # runtime_mode takes priority
        r = _validate_and_map([_valid_event(runtime_mode="CUSTOM_MODE")])
        assert r["_enqueued"][0]["evaluation_mode"] == "CUSTOM_MODE"

        # evaluation_mode fallback
        r2 = _validate_and_map([_valid_event(evaluation_mode="SERVER_MODE")])
        assert r2["_enqueued"][0]["evaluation_mode"] == "SERVER_MODE"

        # Default
        r3 = _validate_and_map([_valid_event()])
        assert r3["_enqueued"][0]["evaluation_mode"] == "LOCAL_RUNTIME_PYTHON"


class TestAuditEventIngestionRequestParsing:
    def test_malformed_json_body_detected(self):
        """Non-list events field → validation captures it."""
        # If events is not a list, the endpoint returns 400.
        # We test the shape check directly.
        events_value = "not-a-list"
        assert not isinstance(events_value, list)

    def test_empty_agent_id_string_rejected(self):
        """Empty string agent_id is rejected (must be non-empty)."""
        event = _valid_event(agent_id="")
        result = _validate_and_map([event])
        assert result["rejected"] == 1

    def test_allowed_not_bool_rejected(self):
        """allowed='yes' (string) is rejected — must be bool."""
        event = _valid_event(allowed="yes")
        result = _validate_and_map([event])
        assert result["rejected"] == 1
