"""
Unit tests for parity_helpers.py (Phase 2).

These tests run entirely without a live server or database.
They verify the normalization and comparison logic in isolation.
"""
import unittest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.parity_helpers import (
    ParityRecord,
    ParityMismatch,
    normalize_local_decision,
    normalize_server_response,
    compare_parity_records,
    assert_parity,
    assert_local_vs_server_parity,
    _extract_reason_class,
    _extract_obligation_types,
    _extract_output_control_mode,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_local_decision(outcome="allow", reason="allowed", obligations=None, output_policy=None, allowed=None):
    from kswitch.local_pdp.evaluator import LocalDecision
    return LocalDecision(
        outcome=outcome,
        reason=reason,
        allowed=(outcome == "allow") if allowed is None else allowed,
        decision_path=["local_sdk"],
        obligations=obligations or [],
        output_policy=output_policy or {"mode": "allow_raw", "masking_classifications": []},
        evaluation_mode="LOCAL_RUNTIME_PYTHON",
        bundle_version="bundle:v1",
        context_pack_id="cp:v1",
        risk_tier="low",
        agent_id="agent:test@corp",
        mcp_server_id="mcp:test@corp",
        tool_name="test_tool",
    )


def _server_response(allowed=True, reason="allowed", obligations=None, output_policy=None):
    return {
        "allowed": allowed,
        "reason": reason,
        "obligations": obligations or [],
        "output_policy": output_policy,
        "decision_path": ["server_pdp"],
        "evaluation_mode": "SERVER_CEDAR",
        "enforcement_id": "eid-12345",
        "timestamp": "2026-03-28T12:00:00Z",
    }


# ── _extract_reason_class tests ────────────────────────────────────────────────

class TestExtractReasonClass(unittest.TestCase):

    def test_simple_reason(self):
        self.assertEqual(_extract_reason_class("allowed"), "allowed")

    def test_colon_separated_reason(self):
        self.assertEqual(_extract_reason_class("agent_revoked:kill_switch:manual"), "agent_revoked")

    def test_space_separated_reason(self):
        self.assertEqual(_extract_reason_class("policy_denied reason detail"), "policy_denied")

    def test_none_reason(self):
        self.assertEqual(_extract_reason_class(None), "unknown")

    def test_empty_string(self):
        self.assertEqual(_extract_reason_class(""), "unknown")

    def test_reason_normalized_to_lower(self):
        self.assertEqual(_extract_reason_class("POLICY_DENIED"), "policy_denied")

    def test_blanket_kill_reason(self):
        self.assertEqual(_extract_reason_class("blanket_kill"), "blanket_kill")


# ── _extract_obligation_types tests ───────────────────────────────────────────

class TestExtractObligationTypes(unittest.TestCase):

    def test_empty_obligations(self):
        self.assertEqual(_extract_obligation_types([]), [])

    def test_none_obligations(self):
        self.assertEqual(_extract_obligation_types(None), [])

    def test_dict_obligations(self):
        obs = [
            {"obligation_type": "data_masking", "level": "medium"},
            {"obligation_type": "audit_flag", "level": "low"},
        ]
        result = _extract_obligation_types(obs)
        self.assertEqual(result, ["audit_flag", "data_masking"])  # sorted

    def test_dict_with_type_key(self):
        obs = [{"type": "credential_risk"}, {"type": "rate_limit"}]
        result = _extract_obligation_types(obs)
        self.assertEqual(result, ["credential_risk", "rate_limit"])

    def test_object_obligations(self):
        from unittest.mock import MagicMock
        ob1 = MagicMock()
        ob1.obligation_type = "delegation_trust"
        ob2 = MagicMock()
        ob2.obligation_type = "audit_flag"
        result = _extract_obligation_types([ob1, ob2])
        self.assertEqual(result, ["audit_flag", "delegation_trust"])

    def test_sorted_output(self):
        obs = [{"obligation_type": "z_type"}, {"obligation_type": "a_type"}, {"obligation_type": "m_type"}]
        result = _extract_obligation_types(obs)
        self.assertEqual(result, ["a_type", "m_type", "z_type"])

    def test_normalized_to_lower(self):
        obs = [{"obligation_type": "DATA_MASKING"}]
        result = _extract_obligation_types(obs)
        self.assertEqual(result, ["data_masking"])


# ── _extract_output_control_mode tests ────────────────────────────────────────

class TestExtractOutputControlMode(unittest.TestCase):

    def test_none_defaults_to_allow_raw(self):
        self.assertEqual(_extract_output_control_mode(None), "allow_raw")

    def test_dict_mode(self):
        self.assertEqual(_extract_output_control_mode({"mode": "mask_fields"}), "mask_fields")

    def test_dict_deny_export(self):
        self.assertEqual(_extract_output_control_mode({"mode": "deny_export"}), "deny_export")

    def test_object_mode(self):
        from unittest.mock import MagicMock
        op = MagicMock()
        op.mode = "mask_fields"
        self.assertEqual(_extract_output_control_mode(op), "mask_fields")

    def test_normalized_to_lower(self):
        self.assertEqual(_extract_output_control_mode({"mode": "ALLOW_RAW"}), "allow_raw")

    def test_dict_missing_mode_key(self):
        self.assertEqual(_extract_output_control_mode({}), "allow_raw")


# ── normalize_local_decision tests ────────────────────────────────────────────

class TestNormalizeLocalDecision(unittest.TestCase):

    def test_allow_decision(self):
        ld = _make_local_decision("allow", "allowed")
        rec = normalize_local_decision(ld)
        self.assertEqual(rec.allowed, True)
        self.assertEqual(rec.reason_class, "allowed")
        self.assertEqual(rec.obligation_types, [])
        self.assertEqual(rec.output_control_mode, "allow_raw")
        self.assertEqual(rec.source, "local")

    def test_deny_decision(self):
        ld = _make_local_decision("deny", "policy_denied", allowed=False)
        rec = normalize_local_decision(ld)
        self.assertEqual(rec.allowed, False)
        self.assertEqual(rec.reason_class, "policy_denied")

    def test_revocation_decision(self):
        ld = _make_local_decision("deny", "agent_revoked", allowed=False)
        rec = normalize_local_decision(ld)
        self.assertEqual(rec.allowed, False)
        self.assertEqual(rec.reason_class, "agent_revoked")

    def test_with_obligations(self):
        ld = _make_local_decision(
            obligations=[{"obligation_type": "data_masking"}, {"obligation_type": "audit_flag"}]
        )
        rec = normalize_local_decision(ld)
        self.assertEqual(rec.obligation_types, ["audit_flag", "data_masking"])

    def test_with_output_policy(self):
        ld = _make_local_decision(output_policy={"mode": "mask_fields", "masking_classifications": ["PII"]})
        rec = normalize_local_decision(ld)
        self.assertEqual(rec.output_control_mode, "mask_fields")


# ── normalize_server_response tests ───────────────────────────────────────────

class TestNormalizeServerResponse(unittest.TestCase):

    def test_allow_response(self):
        resp = _server_response(allowed=True, reason="allowed")
        rec = normalize_server_response(resp)
        self.assertEqual(rec.allowed, True)
        self.assertEqual(rec.reason_class, "allowed")
        self.assertEqual(rec.obligation_types, [])
        self.assertEqual(rec.output_control_mode, "allow_raw")
        self.assertEqual(rec.source, "server")

    def test_deny_response(self):
        resp = _server_response(allowed=False, reason="policy_denied")
        rec = normalize_server_response(resp)
        self.assertEqual(rec.allowed, False)
        self.assertEqual(rec.reason_class, "policy_denied")

    def test_dynamic_fields_excluded(self):
        # timestamp, enforcement_id, decision_path are in the raw response but excluded from normalized record
        resp = _server_response(allowed=True)
        resp["timestamp"] = "2026-01-01T00:00:00Z"
        resp["enforcement_id"] = "eid-abc-uuid-123"
        resp["elapsed_ms"] = 42.7
        rec = normalize_server_response(resp)
        # These fields must not be in ParityRecord
        self.assertFalse(hasattr(rec, "timestamp"))
        self.assertFalse(hasattr(rec, "enforcement_id"))
        self.assertFalse(hasattr(rec, "elapsed_ms"))

    def test_with_obligations(self):
        resp = _server_response(
            obligations=[{"obligation_type": "credential_risk"}, {"obligation_type": "rate_limit"}]
        )
        rec = normalize_server_response(resp)
        self.assertEqual(rec.obligation_types, ["credential_risk", "rate_limit"])

    def test_with_output_policy(self):
        resp = _server_response(output_policy={"mode": "deny_export"})
        rec = normalize_server_response(resp)
        self.assertEqual(rec.output_control_mode, "deny_export")


# ── compare_parity_records tests ──────────────────────────────────────────────

class TestCompareParity(unittest.TestCase):

    def _rec(self, allowed=True, reason_class="allowed", obligation_types=None, output_control_mode="allow_raw", source=""):
        return ParityRecord(
            allowed=allowed,
            reason_class=reason_class,
            obligation_types=obligation_types or [],
            output_control_mode=output_control_mode,
            source=source,
        )

    def test_identical_records_no_mismatches(self):
        local = self._rec(allowed=True, reason_class="allowed")
        server = self._rec(allowed=True, reason_class="allowed")
        mismatches = compare_parity_records(local, server)
        self.assertEqual(mismatches, [])

    def test_allowed_mismatch(self):
        local = self._rec(allowed=True)
        server = self._rec(allowed=False)
        mismatches = compare_parity_records(local, server)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].field, "allowed")

    def test_reason_class_mismatch(self):
        local = self._rec(reason_class="allowed")
        server = self._rec(reason_class="policy_denied")
        mismatches = compare_parity_records(local, server)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].field, "reason_class")

    def test_obligation_types_mismatch(self):
        local = self._rec(obligation_types=["data_masking"])
        server = self._rec(obligation_types=["audit_flag"])
        mismatches = compare_parity_records(local, server)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].field, "obligation_types")

    def test_output_control_mode_mismatch(self):
        local = self._rec(output_control_mode="mask_fields")
        server = self._rec(output_control_mode="allow_raw")
        mismatches = compare_parity_records(local, server)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].field, "output_control_mode")

    def test_multiple_mismatches(self):
        local = self._rec(allowed=True, reason_class="allowed", output_control_mode="deny_export")
        server = self._rec(allowed=False, reason_class="policy_denied", output_control_mode="allow_raw")
        mismatches = compare_parity_records(local, server)
        self.assertEqual(len(mismatches), 3)
        fields = {m.field for m in mismatches}
        self.assertIn("allowed", fields)
        self.assertIn("reason_class", fields)
        self.assertIn("output_control_mode", fields)

    def test_source_field_not_compared(self):
        """source is for diagnostics only — must not cause a parity mismatch."""
        local = self._rec(source="local")
        server = self._rec(source="server")
        mismatches = compare_parity_records(local, server)
        self.assertEqual(mismatches, [])


# ── assert_parity tests ───────────────────────────────────────────────────────

class TestAssertParity(unittest.TestCase):

    def _rec(self, **kwargs):
        defaults = dict(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw")
        defaults.update(kwargs)
        return ParityRecord(**defaults)

    def test_passes_on_equal_records(self):
        local = self._rec(allowed=True)
        server = self._rec(allowed=True)
        # Must not raise
        assert_parity(local, server, scenario="test allow")

    def test_raises_on_mismatch_with_field_info(self):
        local = self._rec(allowed=True, reason_class="allowed")
        server = self._rec(allowed=False, reason_class="policy_denied")
        with self.assertRaises(AssertionError) as ctx:
            assert_parity(local, server, scenario="mismatch test")
        error_msg = str(ctx.exception)
        # Must identify the scenario
        self.assertIn("mismatch test", error_msg)
        # Must identify both drifted fields
        self.assertIn("allowed", error_msg)
        self.assertIn("reason_class", error_msg)
        # Must show local and server values
        self.assertIn("True", error_msg)
        self.assertIn("False", error_msg)
        # Must include parity failure header
        self.assertIn("PARITY FAILURE", error_msg)

    def test_raises_shows_likely_source_of_drift(self):
        local = self._rec(output_control_mode="mask_fields")
        server = self._rec(output_control_mode="allow_raw")
        with self.assertRaises(AssertionError) as ctx:
            assert_parity(local, server)
        error_msg = str(ctx.exception)
        self.assertIn("output_control_mode", error_msg)
        self.assertIn("policy configuration", error_msg)


# ── assert_local_vs_server_parity tests ───────────────────────────────────────

class TestAssertLocalVsServerParity(unittest.TestCase):

    def test_allow_parity_passes(self):
        ld = _make_local_decision("allow", "allowed")
        resp = _server_response(allowed=True, reason="allowed")
        # Must not raise
        assert_local_vs_server_parity(ld, resp, "allow parity")

    def test_deny_parity_passes(self):
        ld = _make_local_decision("deny", "policy_denied", allowed=False)
        resp = _server_response(allowed=False, reason="policy_denied")
        assert_local_vs_server_parity(ld, resp, "deny parity")

    def test_revocation_parity_passes(self):
        ld = _make_local_decision("deny", "agent_revoked", allowed=False)
        resp = _server_response(allowed=False, reason="agent_revoked")
        assert_local_vs_server_parity(ld, resp, "revocation parity")

    def test_obligation_parity_passes(self):
        ld = _make_local_decision(
            obligations=[{"obligation_type": "data_masking"}],
            output_policy={"mode": "mask_fields", "masking_classifications": []}
        )
        resp = _server_response(
            obligations=[{"obligation_type": "data_masking"}],
            output_policy={"mode": "mask_fields"}
        )
        assert_local_vs_server_parity(ld, resp, "obligation parity")

    def test_allow_vs_deny_raises(self):
        ld = _make_local_decision("allow", "allowed")
        resp = _server_response(allowed=False, reason="policy_denied")
        with self.assertRaises(AssertionError) as ctx:
            assert_local_vs_server_parity(ld, resp, "expected mismatch")
        self.assertIn("expected mismatch", str(ctx.exception))
        self.assertIn("allowed", str(ctx.exception))

    def test_mismatch_output_is_diff_friendly(self):
        """Mismatch output must be human-readable enough to debug rollout drift."""
        ld = _make_local_decision("deny", "agent_revoked", allowed=False)
        resp = _server_response(allowed=True, reason="allowed")
        with self.assertRaises(AssertionError) as ctx:
            assert_local_vs_server_parity(ld, resp, "rollout drift scenario")
        msg = str(ctx.exception)
        # Must show both sides
        self.assertIn("local=", msg.lower())
        self.assertIn("server=", msg.lower())
        # Must show field-level diff
        self.assertIn("allowed", msg)


# ── ParityRecord equality tests ───────────────────────────────────────────────

class TestParityRecordEquality(unittest.TestCase):

    def test_equal_records(self):
        r1 = ParityRecord(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw")
        r2 = ParityRecord(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw")
        self.assertEqual(r1, r2)

    def test_different_source_still_equal(self):
        """source is diagnostic only, must not affect equality."""
        r1 = ParityRecord(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw", source="local")
        r2 = ParityRecord(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw", source="server")
        self.assertEqual(r1, r2)

    def test_different_allowed_not_equal(self):
        r1 = ParityRecord(allowed=True, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw")
        r2 = ParityRecord(allowed=False, reason_class="allowed", obligation_types=[], output_control_mode="allow_raw")
        self.assertNotEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
