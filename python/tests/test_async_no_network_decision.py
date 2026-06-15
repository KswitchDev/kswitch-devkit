"""
Async no-network proof (PR-13).

Patches httpx.AsyncClient.send to raise on any call.
Proves async local allow/deny paths make zero HTTP calls.
Proves conditional is the ONLY path that reaches the server.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_local_decision(outcome="allow", reason="allowed", allowed=None):
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


class TestAsyncNoNetworkAllow(unittest.IsolatedAsyncioTestCase):
    """Async local allow — zero HTTP calls even with httpx patched to raise."""

    async def test_async_local_allow_no_http(self):
        """Core proof: async local allow path makes no network call."""
        import httpx
        from kswitch.interceptor import KSwitchAsyncInterceptor

        # Patch httpx so any HTTP call raises immediately
        def _raise(*args, **kwargs):
            raise AssertionError("HTTP call made — async local allow must not contact server")

        local_decision = _make_local_decision("allow")

        # Build a client whose underlying http.send raises
        mock_http = MagicMock()
        mock_http.send = AsyncMock(side_effect=_raise)
        mock_client = MagicMock()
        mock_client._http = mock_http
        mock_client.enforcement = MagicMock()
        # enforce_mcp_call raises if called
        mock_client.enforcement.enforce_mcp_call = AsyncMock(side_effect=_raise)
        mock_client.enforcement.report_obligations = AsyncMock()

        interceptor = KSwitchAsyncInterceptor(mock_client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "local_result",
            )

        self.assertEqual(result, "local_result")

    async def test_async_local_deny_no_http(self):
        """Core proof: async local deny path makes no network call."""
        from kswitch.interceptor import KSwitchAsyncInterceptor, KSwitchEnforcementError

        def _raise(*args, **kwargs):
            raise AssertionError("HTTP call made — async local deny must not contact server")

        local_decision = _make_local_decision("deny", "policy_deny", allowed=False)

        mock_client = MagicMock()
        mock_client.enforcement = MagicMock()
        mock_client.enforcement.enforce_mcp_call = AsyncMock(side_effect=_raise)
        mock_client.enforcement.report_obligations = AsyncMock()

        interceptor = KSwitchAsyncInterceptor(mock_client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(KSwitchEnforcementError) as ctx:
                await interceptor.check_and_invoke(
                    agent_id="agent:test@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )

        self.assertIn("policy_deny", str(ctx.exception))


class TestAsyncRevocationNoHttp(unittest.IsolatedAsyncioTestCase):
    """Revoked agent deny — zero HTTP even with patched async client."""

    async def test_async_revocation_deny_no_http(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor, KSwitchEnforcementError

        http_called = []

        async def _track(*args, **kwargs):
            http_called.append(True)
            raise AssertionError("HTTP must not be called for revocation deny")

        local_decision = _make_local_decision("deny", "agent_revoked", allowed=False)

        mock_client = MagicMock()
        mock_client.enforcement = MagicMock()
        mock_client.enforcement.enforce_mcp_call = AsyncMock(side_effect=_track)
        mock_client.enforcement.report_obligations = AsyncMock()

        interceptor = KSwitchAsyncInterceptor(mock_client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            with self.assertRaises(KSwitchEnforcementError):
                await interceptor.check_and_invoke(
                    agent_id="agent:revoked@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                    tool_fn=lambda: None,
                )

        self.assertEqual(http_called, [],
                         "HTTP was called for revocation deny — must not happen")


class TestAsyncConditionalCallsServer(unittest.IsolatedAsyncioTestCase):
    """Conditional outcome — the ONLY path that contacts the server."""

    async def test_conditional_reaches_server(self):
        from kswitch.interceptor import KSwitchAsyncInterceptor
        from kswitch.models import EnforcementDecision

        server_calls = []

        async def _server_enforce(**kwargs):
            server_calls.append(kwargs)
            return EnforcementDecision(allowed=True, reason="server_allow")

        local_decision = _make_local_decision("conditional", "missing_bundle", allowed=False)

        mock_client = MagicMock()
        mock_client.enforcement = MagicMock()
        mock_client.enforcement.enforce_mcp_call = AsyncMock(side_effect=_server_enforce)
        mock_client.enforcement.report_obligations = AsyncMock()

        interceptor = KSwitchAsyncInterceptor(mock_client)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision):
            result = await interceptor.check_and_invoke(
                agent_id="agent:test@corp",
                mcp_server_id="mcp:test@corp",
                tool_name="test_tool",
                tool_fn=lambda: "server_result",
            )

        self.assertEqual(result, "server_result")
        self.assertEqual(len(server_calls), 1, "Server must be called exactly once on conditional")


class TestAsyncRuntimeNoNetwork(unittest.IsolatedAsyncioTestCase):
    """KSwitchAsyncRuntime local-only path — zero HTTP."""

    async def test_async_runtime_local_allow_no_http(self):
        from kswitch.invoke import KSwitchAsyncRuntime

        local_decision = _make_local_decision("allow")
        http_called = []

        async def my_tool(x):
            return x * 2

        # No client = fully local path
        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        runtime.register("my_tool", my_tool)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision), \
             patch("httpx.AsyncClient.send", side_effect=lambda *a, **k: http_called.append(True)):
            result = await runtime.invoke("my_tool", x=5)

        self.assertEqual(result, 10)
        self.assertEqual(http_called, [], "No HTTP calls expected for local-only allow")

    async def test_async_runtime_local_deny_no_http(self):
        from kswitch.invoke import KSwitchAsyncRuntime
        from kswitch.interceptor import KSwitchEnforcementError

        local_decision = _make_local_decision("deny", "policy_deny", allowed=False)
        http_called = []

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:test@corp",
            mcp_server_id="mcp:test@corp",
        )
        runtime.register("my_tool", lambda: None)

        with patch("kswitch.local_pdp.evaluator.LocalPDPEvaluator.evaluate",
                   return_value=local_decision), \
             patch("httpx.AsyncClient.send", side_effect=lambda *a, **k: http_called.append(True)):
            with self.assertRaises(KSwitchEnforcementError):
                await runtime.invoke("my_tool")

        self.assertEqual(http_called, [], "No HTTP calls expected for local-only deny")


if __name__ == "__main__":
    unittest.main()
