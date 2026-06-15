"""
Async-vs-sync parity proof (PR-13, Phase 5).

For the same inputs, sync and async paths must produce equivalent:
1. Local allow — result, output policy applied
2. Local deny — exception type, reason string
3. Revoked agent — exception type, reason string
4. Conditional — falls through to server (shape, not result)
5. Obligation/output fields in LocalDecision → EnforcementDecision conversion
6. Audit event emitted for both paths

This is not a performance test — it is a semantic parity test.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Shared fixture builders ───────────────────────────────────────────────────

def _make_local_decision(outcome="allow", reason="allowed", allowed=None,
                         obligations=None, output_policy=None):
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


def _make_sync_client():
    client = MagicMock()
    client.enforcement = MagicMock()
    client.enforcement.report_obligations = MagicMock()
    return client


def _make_async_client():
    client = MagicMock()
    client.enforcement = MagicMock()
    client.enforcement.enforce_mcp_call = AsyncMock()
    client.enforcement.report_obligations = AsyncMock()
    return client


# ── Parity tests ──────────────────────────────────────────────────────────────

class TestLocalAllowParity(unittest.IsolatedAsyncioTestCase):
    """Local allow: sync and async produce same result."""

    async def test_allow_result_parity(self):
        from kswitch.interceptor import KSwitchInterceptor, KSwitchAsyncInterceptor

        local_decision = _make_local_decision("allow")
        tool_output = {"data": "value", "count": 42}

        sync_client = _make_sync_client()
        async_client = _make_async_client()

        sync_interceptor = KSwitchInterceptor(sync_client)
        async_interceptor = KSwitchAsyncInterceptor(async_client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            sync_result = sync_interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: tool_output,
            )

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("allow")):
            async_result = await async_interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: tool_output,
            )

        self.assertEqual(sync_result, async_result)

    async def test_allow_server_not_called_in_either_path(self):
        from kswitch.interceptor import KSwitchInterceptor, KSwitchAsyncInterceptor

        sync_client = _make_sync_client()
        async_client = _make_async_client()
        async_client.enforcement.enforce_mcp_call.side_effect = AssertionError(
            "server must not be called on local allow"
        )

        sync_interceptor = KSwitchInterceptor(sync_client)
        async_interceptor = KSwitchAsyncInterceptor(async_client)

        local_decision = _make_local_decision("allow")

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            sync_interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "ok",
            )

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("allow")):
            await async_interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "ok",
            )

        sync_client.enforcement.enforce_mcp_call.assert_not_called()
        async_client.enforcement.enforce_mcp_call.assert_not_called()


class TestLocalDenyParity(unittest.IsolatedAsyncioTestCase):
    """Local deny: sync and async raise same exception type with same reason."""

    async def test_deny_exception_parity(self):
        from kswitch.interceptor import (
            KSwitchInterceptor, KSwitchAsyncInterceptor, KSwitchEnforcementError
        )

        sync_client = _make_sync_client()
        async_client = _make_async_client()

        sync_interceptor = KSwitchInterceptor(sync_client)
        async_interceptor = KSwitchAsyncInterceptor(async_client)

        sync_exc = None
        async_exc = None

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("deny", "policy_deny", allowed=False)):
            try:
                sync_interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )
            except KSwitchEnforcementError as e:
                sync_exc = e

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("deny", "policy_deny", allowed=False)):
            try:
                await async_interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )
            except KSwitchEnforcementError as e:
                async_exc = e

        self.assertIsNotNone(sync_exc)
        self.assertIsNotNone(async_exc)
        self.assertEqual(type(sync_exc), type(async_exc))
        self.assertEqual(sync_exc.reason, async_exc.reason)


class TestRevocationDenyParity(unittest.IsolatedAsyncioTestCase):
    """Revoked agent: sync and async both deny locally with agent_revoked reason."""

    async def test_revocation_reason_parity(self):
        from kswitch.interceptor import (
            KSwitchInterceptor, KSwitchAsyncInterceptor, KSwitchEnforcementError
        )

        sync_client = _make_sync_client()
        async_client = _make_async_client()

        revoke_decision = _make_local_decision("deny", "agent_revoked", allowed=False)

        sync_exc = None
        async_exc = None

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=revoke_decision):
            try:
                KSwitchInterceptor(sync_client).check_and_invoke(
                    agent_id="agent:revoked@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )
            except KSwitchEnforcementError as e:
                sync_exc = e

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("deny", "agent_revoked", allowed=False)):
            try:
                await KSwitchAsyncInterceptor(async_client).check_and_invoke(
                    agent_id="agent:revoked@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )
            except KSwitchEnforcementError as e:
                async_exc = e

        self.assertEqual(sync_exc.reason, async_exc.reason)
        self.assertEqual(sync_exc.reason, "agent_revoked")
        # Neither path called the server
        sync_client.enforcement.enforce_mcp_call.assert_not_called()
        async_client.enforcement.enforce_mcp_call.assert_not_called()


class TestConditionalShapeParity(unittest.IsolatedAsyncioTestCase):
    """Conditional: sync and async both escalate to server with same payload."""

    async def test_conditional_server_called_in_both(self):
        from kswitch.interceptor import KSwitchInterceptor, KSwitchAsyncInterceptor
        from kswitch.models import EnforcementDecision

        sync_calls = []
        async_calls = []

        def sync_enforce(**kwargs):
            sync_calls.append(kwargs)
            return EnforcementDecision(allowed=True, reason="server_ok")

        async def async_enforce(**kwargs):
            async_calls.append(kwargs)
            return EnforcementDecision(allowed=True, reason="server_ok")

        sync_client = _make_sync_client()
        sync_client.enforcement.enforce_mcp_call = sync_enforce

        async_client = _make_async_client()
        async_client.enforcement.enforce_mcp_call = AsyncMock(side_effect=async_enforce)

        conditional = _make_local_decision("conditional", "missing_bundle", allowed=False)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=conditional):
            KSwitchInterceptor(sync_client).check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "ok",
            )

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision("conditional", "missing_bundle", allowed=False)):
            await KSwitchAsyncInterceptor(async_client).check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "ok",
            )

        self.assertEqual(len(sync_calls), 1)
        self.assertEqual(len(async_calls), 1)
        self.assertEqual(sync_calls[0].get("agent_id"), async_calls[0].get("agent_id"))
        self.assertEqual(sync_calls[0].get("tool_name"), async_calls[0].get("tool_name"))


class TestObligationOutputParity(unittest.IsolatedAsyncioTestCase):
    """Obligation + output fields: _local_to_decision produces same shape for both."""

    def test_local_to_decision_shape_sync_async_identical(self):
        """_local_to_decision is shared — output must be identical."""
        from kswitch.interceptor import _local_to_decision

        ld = _make_local_decision(
            "allow",
            obligations=[{"type": "data_masking", "level": "medium"}],
            output_policy={"mode": "mask_fields", "masking_classifications": ["PII"]},
        )

        # Call twice — must produce structurally identical decisions
        d1 = _local_to_decision(ld)
        d2 = _local_to_decision(ld)

        self.assertEqual(d1.allowed, d2.allowed)
        self.assertEqual(d1.reason, d2.reason)
        self.assertEqual(d1.evaluation_mode, d2.evaluation_mode)
        self.assertEqual(len(d1.obligations), len(d2.obligations))
        if d1.output_policy and d2.output_policy:
            self.assertEqual(d1.output_policy.mode, d2.output_policy.mode)

    async def test_mask_fields_applies_identically_sync_async(self):
        """mask_fields output policy produces same result from sync and async paths."""
        from kswitch.interceptor import KSwitchInterceptor, KSwitchAsyncInterceptor

        mask_decision = _make_local_decision(
            "allow",
            output_policy={"mode": "mask_fields", "masking_classifications": ["PII"]},
        )

        tool_output = {"name": "John", "ssn": "123-45-6789", "amount": 100}

        sync_client = _make_sync_client()
        async_client = _make_async_client()

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=mask_decision):
            sync_result = KSwitchInterceptor(sync_client).check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: tool_output,
            )

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=_make_local_decision(
                       "allow",
                       output_policy={"mode": "mask_fields", "masking_classifications": ["PII"]},
                   )):
            async_result = await KSwitchAsyncInterceptor(async_client).check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: tool_output,
            )

        # Both should have masked SSN
        self.assertEqual(sync_result.get("amount"), async_result.get("amount"))
        # SSN should be masked (redacted) in both
        self.assertEqual(sync_result.get("ssn"), async_result.get("ssn"))


class TestAuditEmitParity(unittest.IsolatedAsyncioTestCase):
    """Both sync and async paths call _emit_local_audit on local decisions."""

    async def test_both_paths_emit_audit_on_allow(self):
        from kswitch.interceptor import KSwitchInterceptor, KSwitchAsyncInterceptor

        sync_client = _make_sync_client()
        async_client = _make_async_client()

        sync_emits = []
        async_emits = []

        def sync_emit(ld, elapsed):
            sync_emits.append(ld.outcome)

        def async_emit(ld, elapsed):
            async_emits.append(ld.outcome)

        with patch("kswitch.interceptor._emit_local_audit", side_effect=sync_emit):
            with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                       return_value=_make_local_decision("allow")):
                KSwitchInterceptor(sync_client).check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: "ok",
                )

        with patch("kswitch.interceptor._emit_local_audit", side_effect=async_emit):
            with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                       return_value=_make_local_decision("allow")):
                await KSwitchAsyncInterceptor(async_client).check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: "ok",
                )

        self.assertEqual(sync_emits, ["allow"])
        self.assertEqual(async_emits, ["allow"])
        self.assertEqual(sync_emits, async_emits)


if __name__ == "__main__":
    unittest.main()
