"""
Unit tests for the async local PDP path (PR-13).

Covers:
- Local allow via KSwitchAsyncInterceptor (no network)
- Local deny via KSwitchAsyncInterceptor (no network)
- Conditional escalation routes to server
- LOCAL_RUNTIME_PYTHON_ASYNC mode tag on local decisions
- Output policy applied on async allow
- Pre-invoke obligation blocking on async allow
- Audit event emitted on async local allow/deny
- AsyncGovernedTool.__call__ routes through runtime
- KSwitchAsyncRuntime.invoke() local-only path
"""
import asyncio
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_local_decision(outcome="allow", reason="allowed", allowed=None):
    """Build a LocalDecision for mocking."""
    from kswitch.local_pdp.evaluator import LocalDecision
    return LocalDecision(
        outcome=outcome,
        reason=reason,
        allowed=(outcome == "allow") if allowed is None else allowed,
        decision_path=["local_sdk"],
        obligations=[],
        output_policy={"mode": "allow_raw", "masking_classifications": []},
        evaluation_mode="LOCAL_RUNTIME_PYTHON",
        bundle_version="bundle:v1",
        context_pack_id="cp:v1",
        risk_tier="low",
        agent_id="agent:test@corp",
        mcp_server_id="mcp:test@corp",
        tool_name="test_tool",
    )


def _make_async_client():
    """Build a mock KSwitchAsyncClient."""
    client = MagicMock()
    client.enforcement = MagicMock()
    client.enforcement.enforce_mcp_call = AsyncMock()
    client.enforcement.report_obligations = AsyncMock()
    return client


async def _run(coro):
    return await coro


class TestAsyncLocalAllow(unittest.IsolatedAsyncioTestCase):
    """Local allow via async interceptor — no network call."""

    async def test_local_allow_invokes_tool(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)

        local_decision = _make_local_decision("allow")
        tool_called = []

        async def my_tool(x):
            tool_called.append(x)
            return f"result:{x}"

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=my_tool,
                tool_args={"x": 42},
            )

        self.assertEqual(result, "result:42")
        self.assertEqual(tool_called, [42])
        # Server enforce_mcp_call must NOT be called
        client.enforcement.enforce_mcp_call.assert_not_called()

    async def test_local_allow_with_sync_tool(self):
        """Sync tool functions also work from async path."""
        from kswitch.interceptor import KSwitchAsyncInterceptor

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("allow")

        def sync_tool(value):
            return value * 2

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=sync_tool,
                tool_args={"value": 5},
            )

        self.assertEqual(result, 10)
        client.enforcement.enforce_mcp_call.assert_not_called()


class TestAsyncLocalDeny(unittest.IsolatedAsyncioTestCase):
    """Local deny via async interceptor — no network call."""

    async def test_local_deny_raises_enforcement_error(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor, KSwitchEnforcementError

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("deny", "policy_deny", allowed=False)
        tool_called = []

        def tool_fn():
            tool_called.append(True)
            return "should_not_reach"

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(KSwitchEnforcementError) as ctx:
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=tool_fn,
                )

        self.assertIn("policy_deny", str(ctx.exception))
        self.assertEqual(tool_called, [])  # tool never called
        client.enforcement.enforce_mcp_call.assert_not_called()

    async def test_revocation_deny_no_server_call(self):
        """Revoked agent is denied locally — no server enforcement call."""
        from kswitch.interceptor import KSwitchAsyncInterceptor, KSwitchEnforcementError

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("deny", "agent_revoked", allowed=False)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(KSwitchEnforcementError):
                await interceptor.check_and_invoke(
                    agent_id="agent:revoked@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )

        client.enforcement.enforce_mcp_call.assert_not_called()


class TestAsyncConditionalEscalation(unittest.IsolatedAsyncioTestCase):
    """Conditional outcome routes to server — only valid network path."""

    async def test_conditional_calls_server(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor
        from kswitch.models import EnforcementDecision

        client = _make_async_client()
        server_decision = EnforcementDecision(allowed=True, reason="server_allow")
        client.enforcement.enforce_mcp_call.return_value = server_decision

        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("conditional", "missing_bundle", allowed=False)

        def tool_fn():
            return "server_result"

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=tool_fn,
            )

        self.assertEqual(result, "server_result")
        client.enforcement.enforce_mcp_call.assert_called_once()

    async def test_local_crash_falls_through_to_server(self):
        """If local PDP crashes, fall through to server (not fail closed)."""
        from kswitch.interceptor import KSwitchAsyncInterceptor
        from kswitch.models import EnforcementDecision

        client = _make_async_client()
        server_decision = EnforcementDecision(allowed=True, reason="server_allow")
        client.enforcement.enforce_mcp_call.return_value = server_decision

        interceptor = KSwitchAsyncInterceptor(client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   side_effect=RuntimeError("evaluator crashed")):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "fallback_result",
            )

        self.assertEqual(result, "fallback_result")
        client.enforcement.enforce_mcp_call.assert_called_once()


class TestAsyncRuntimeModeTag(unittest.IsolatedAsyncioTestCase):
    """LOCAL_RUNTIME_PYTHON_ASYNC mode tag applied on local decisions."""

    async def test_evaluation_mode_tagged_async(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("allow")
        # evaluation_mode starts as sync
        self.assertEqual(local_decision.evaluation_mode, "LOCAL_RUNTIME_PYTHON")

        tagged_modes = []

        original_emit = None
        try:
            from kswitch.audit import emitter as _emitter_mod
            original_emit = _emitter_mod.emit_decision_event

            def capturing_emit(**kwargs):
                tagged_modes.append(kwargs.get("evaluation_mode"))

            _emitter_mod.emit_decision_event = capturing_emit
            with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                       return_value=local_decision):
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: "result",
                )
        finally:
            if original_emit:
                _emitter_mod.emit_decision_event = original_emit

        self.assertTrue(any("ASYNC" in (m or "") for m in tagged_modes),
                        f"Expected ASYNC in mode tag, got: {tagged_modes}")


class TestAsyncAuditEmit(unittest.IsolatedAsyncioTestCase):
    """Audit events emitted on async local allow and deny."""

    async def test_audit_emitted_on_local_allow(self):
        import tempfile, os
        from kswitch.interceptor import KSwitchAsyncInterceptor
        from kswitch.audit.emitter import AuditEmitter

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("allow")

        with tempfile.TemporaryDirectory() as tmpdir:
            test_emitter = AuditEmitter(audit_dir=tmpdir)
            with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                       return_value=local_decision), \
                 patch("kswitch.interceptor._emit_local_audit") as mock_emit:
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: "output",
                )

        mock_emit.assert_called_once()

    async def test_audit_emitted_on_local_deny(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor, KSwitchEnforcementError

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("deny", "policy_deny", allowed=False)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision), \
             patch("kswitch.interceptor._emit_local_audit") as mock_emit:
            with self.assertRaises(KSwitchEnforcementError):
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )

        mock_emit.assert_called_once()


class TestAsyncOutputGuard(unittest.IsolatedAsyncioTestCase):
    """Output policy applied on async local allow."""

    async def test_deny_export_raises_output_denied(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor, OutputDeniedError

        client = _make_async_client()
        interceptor = KSwitchAsyncInterceptor(client)
        local_decision = _make_local_decision("allow")
        local_decision.output_policy = {"mode": "deny_export", "masking_classifications": []}

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(OutputDeniedError):
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: {"secret": "data"},
                )


class TestAsyncGovernedTool(unittest.IsolatedAsyncioTestCase):
    """AsyncGovernedTool.__call__ routes through KSwitchAsyncRuntime."""

    async def test_async_governed_tool_call_routes_through_runtime(self):
        from kswitch.invoke import KSwitchAsyncRuntime

        local_decision = _make_local_decision("allow")
        results = []

        async def my_tool(n):
            results.append(n)
            return n * 3

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        governed = runtime.register("my_tool", my_tool)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await governed(n=7)

        self.assertEqual(result, 21)
        self.assertEqual(results, [7])

    async def test_async_governed_tool_unsafe_raw_warns(self):
        import warnings
        from kswitch.invoke import KSwitchAsyncRuntime

        async def my_tool():
            return "raw"

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        governed = runtime.register("my_tool", my_tool)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            governed._unsafe_raw_call()  # kswitch: allow-unsafe — test-only: verifying the warning is emitted by _unsafe_raw_call()
            self.assertTrue(any("bypasses KSwitch governance" in str(warning.message)
                                for warning in w))


class TestKSwitchAsyncRuntimeLocalOnly(unittest.IsolatedAsyncioTestCase):
    """KSwitchAsyncRuntime local-only path (no client configured)."""

    async def test_local_only_allow(self):
        from kswitch.invoke import KSwitchAsyncRuntime

        local_decision = _make_local_decision("allow")

        async def my_tool(x):
            return x + 1

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        runtime.register("my_tool", my_tool)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await runtime.invoke("my_tool", x=10)

        self.assertEqual(result, 11)

    async def test_local_only_deny_raises(self):
        from kswitch.invoke import KSwitchAsyncRuntime
        from kswitch.interceptor import KSwitchEnforcementError

        local_decision = _make_local_decision("deny", "policy_deny", allowed=False)

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        runtime.register("my_tool", lambda: None)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(KSwitchEnforcementError):
                await runtime.invoke("my_tool")

    async def test_local_only_conditional_raises_runtime_error(self):
        from kswitch.invoke import KSwitchAsyncRuntime

        local_decision = _make_local_decision("conditional", "missing_bundle", allowed=False)

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        runtime.register("my_tool", lambda: None)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(RuntimeError) as ctx:
                await runtime.invoke("my_tool")

        self.assertIn("no client configured", str(ctx.exception))

    async def test_unregistered_tool_raises_key_error(self):
        from kswitch.invoke import KSwitchAsyncRuntime

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )

        with self.assertRaises(KeyError):
            await runtime.invoke("nonexistent_tool")


if __name__ == "__main__":
    unittest.main()
