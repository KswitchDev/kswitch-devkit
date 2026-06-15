"""Tests for KSwitchRuntime governed invocation API."""
import warnings
from unittest.mock import MagicMock, patch

import pytest

from kswitch.invoke import GovernedTool, KSwitchRuntime, _make_bare_decision
from kswitch.interceptor import KSwitchEnforcementError


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"


def _make_allow_decision():
    from kswitch.local_pdp.evaluator import LocalDecision
    return LocalDecision(
        outcome="allow",
        reason="allowed",
        allowed=True,
        decision_path=["local_sdk", "agent_active", "bundle_v5", "no_policies", "enforcement_complete"],
        output_policy={"mode": "allow_raw", "masking_classifications": []},
    )


def _make_deny_decision():
    from kswitch.local_pdp.evaluator import LocalDecision
    return LocalDecision(
        outcome="deny",
        reason="agent_revoked",
        allowed=False,
        decision_path=["local_sdk", "revocation_cache_hit"],
    )


def _make_conditional_decision():
    from kswitch.local_pdp.evaluator import LocalDecision
    return LocalDecision(
        outcome="conditional",
        reason="bundle_unavailable",
        allowed=False,
        decision_path=["local_sdk", "agent_active", "bundle_miss_escalate"],
    )


class TestKSwitchRuntimeRegister:
    def test_register_returns_governed_tool(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        gt = runtime.register("my_tool", lambda: "result")
        assert isinstance(gt, GovernedTool)
        assert gt.name == "my_tool"

    def test_list_tools(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        runtime.register("tool_a", lambda: None)
        runtime.register("tool_b", lambda: None)
        assert set(runtime.list_tools()) == {"tool_a", "tool_b"}

    def test_get_tool_by_name(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        gt = runtime.register("my_tool", lambda: None)
        assert runtime.tool("my_tool") is gt

    def test_tool_not_found_returns_none(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        assert runtime.tool("nonexistent") is None


class TestKSwitchRuntimeInvoke:
    def test_unregistered_tool_raises_key_error(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        with pytest.raises(KeyError, match="not registered"):
            runtime.invoke("unknown_tool")

    def test_governed_invoke_allows_locally(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        tool_fn = MagicMock(return_value={"balance": 100})
        runtime.register("get_balance", tool_fn)

        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = _make_allow_decision()
            with patch("kswitch.audit.emitter.emit_decision_event"):
                result = runtime.invoke("get_balance")

        assert result == {"balance": 100}
        tool_fn.assert_called_once()

    def test_governed_invoke_denies_locally(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        tool_fn = MagicMock(return_value="should_not_be_called")
        runtime.register("get_balance", tool_fn)

        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = _make_deny_decision()
            with patch("kswitch.audit.emitter.emit_decision_event"):
                with pytest.raises(KSwitchEnforcementError, match="agent_revoked"):
                    runtime.invoke("get_balance")

        tool_fn.assert_not_called()

    def test_conditional_without_client_raises_runtime_error(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)  # No client
        runtime.register("my_tool", lambda: None)

        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = _make_conditional_decision()
            with pytest.raises(RuntimeError, match="server escalation"):
                runtime.invoke("my_tool")

    def test_governed_tool_call_routes_through_governance(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        tool_fn = MagicMock(return_value="result")
        gt = runtime.register("my_tool", tool_fn)

        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = _make_allow_decision()
            with patch("kswitch.audit.emitter.emit_decision_event"):
                result = gt()  # Calling GovernedTool directly

        assert result == "result"


class TestGovernedToolRawCall:
    def test_raw_call_warns(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        tool_fn = MagicMock(return_value="raw_result")
        gt = runtime.register("my_tool", tool_fn)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = gt._unsafe_raw_call()  # kswitch: allow-unsafe — test-only: verifying the UserWarning is emitted by _unsafe_raw_call()
            assert len(w) == 1
            assert "bypasses KSwitch governance" in str(w[0].message)
            assert issubclass(w[0].category, UserWarning)

        assert result == "raw_result"
        tool_fn.assert_called_once()

    def test_governed_tool_repr(self):
        runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
        gt = runtime.register("payment_tool", lambda: None)
        assert "payment_tool" in repr(gt)


class TestKSwitchRuntimeWithClient:
    def test_with_client_uses_interceptor(self):
        mock_client = MagicMock()
        # Server returns allow decision
        from kswitch.models import EnforcementDecision, OutputPolicy
        server_decision = EnforcementDecision(
            allowed=True,
            reason="allowed",
            outcome="allow",
            output_policy=OutputPolicy(mode="allow_raw"),
        )
        mock_client.enforcement.enforce_mcp_call.return_value = server_decision

        runtime = KSwitchRuntime(AGENT_ID, MCP_ID, client=mock_client)
        tool_fn = MagicMock(return_value="server_result")
        runtime.register("my_tool", tool_fn)

        # Force local PDP to escalate (conditional) — patch at the source module
        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = _make_conditional_decision()
            result = runtime.invoke("my_tool")

        assert result == "server_result"
        mock_client.enforcement.enforce_mcp_call.assert_called_once()


class TestMakeBareDecision:
    def test_bare_decision_fields(self):
        ld = _make_allow_decision()
        decision = _make_bare_decision(ld)
        assert decision.allowed == ld.allowed
        assert decision.reason == ld.reason
        assert decision.outcome == ld.outcome
