"""No-network test: local allow and deny work without any HTTP calls.

The mock network layer is configured to raise on any HTTP attempt, proving
that normal-path allow/deny decisions do NOT touch the network.
"""
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from kswitch.invoke import KSwitchRuntime
from kswitch.interceptor import KSwitchEnforcementError
from kswitch.local_pdp.evaluator import LocalDecision
from kswitch.audit.emitter import AuditEmitter


AGENT_ID = "agent:fraud-detector@bank.internal"
MCP_ID = "mcp:payment-gateway@bank.internal"
TOOL = "get_balance"


def _network_should_never_be_called(*args, **kwargs):
    raise AssertionError(
        "NETWORK CALL DETECTED: Local PDP should not call the network "
        "for a normal allow/deny decision."
    )


def _allow_decision():
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


def _deny_decision():
    return LocalDecision(
        outcome="deny",
        reason="agent_revoked",
        allowed=False,
        decision_path=["local_sdk", "revocation_cache_hit"],
        agent_id=AGENT_ID,
        mcp_server_id=MCP_ID,
        tool_name=TOOL,
    )


class TestNoNetworkAllow:
    def test_local_allow_no_http(self, tmp_path):
        """Allow path: no HTTP call made."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            # Runtime with NO client (local-only path)
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            tool_fn = MagicMock(return_value={"balance": 999})
            runtime.register(TOOL, tool_fn)

            # Patch httpx to raise if called (no network allowed)
            with patch("httpx.Client.send", side_effect=_network_should_never_be_called):
                with patch("httpx.AsyncClient.send", side_effect=_network_should_never_be_called):
                    with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                        mock_ev.return_value.evaluate.return_value = _allow_decision()
                        result = runtime.invoke(TOOL)

            assert result == {"balance": 999}
            tool_fn.assert_called_once()

        finally:
            audit_mod._emitter = original_emitter

    def test_local_deny_no_http(self, tmp_path):
        """Deny path: no HTTP call made."""
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            runtime = KSwitchRuntime(AGENT_ID, MCP_ID)
            tool_fn = MagicMock(return_value="should_not_be_called")
            runtime.register(TOOL, tool_fn)

            with patch("httpx.Client.send", side_effect=_network_should_never_be_called):
                with patch("httpx.AsyncClient.send", side_effect=_network_should_never_be_called):
                    with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                        mock_ev.return_value.evaluate.return_value = _deny_decision()
                        with pytest.raises(KSwitchEnforcementError):
                            runtime.invoke(TOOL)

            tool_fn.assert_not_called()

        finally:
            audit_mod._emitter = original_emitter


class TestNoNetworkWithInterceptor:
    def test_interceptor_allow_no_http(self, tmp_path):
        """KSwitchInterceptor local allow does not call server."""
        from kswitch.interceptor import KSwitchInterceptor
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            mock_client = MagicMock()
            # Patch enforce_mcp_call to raise if called (should not be called on local allow)
            mock_client.enforcement.enforce_mcp_call.side_effect = _network_should_never_be_called

            interceptor = KSwitchInterceptor(mock_client)
            tool_fn = MagicMock(return_value="result")

            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = _allow_decision()
                result = interceptor.check_and_invoke(
                    agent_id=AGENT_ID,
                    mcp_server_id=MCP_ID,
                    tool_name=TOOL,
                    tool_fn=tool_fn,
                )

            assert result == "result"
            mock_client.enforcement.enforce_mcp_call.assert_not_called()

        finally:
            audit_mod._emitter = original_emitter

    def test_interceptor_deny_no_http(self, tmp_path):
        """KSwitchInterceptor local deny does not call server."""
        from kswitch.interceptor import KSwitchInterceptor
        from kswitch.audit import emitter as audit_mod
        original_emitter = audit_mod._emitter
        audit_mod._emitter = AuditEmitter(audit_dir=str(tmp_path))

        try:
            mock_client = MagicMock()
            mock_client.enforcement.enforce_mcp_call.side_effect = _network_should_never_be_called

            interceptor = KSwitchInterceptor(mock_client)
            tool_fn = MagicMock()

            with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
                mock_ev.return_value.evaluate.return_value = _deny_decision()
                with pytest.raises(KSwitchEnforcementError, match="agent_revoked"):
                    interceptor.check_and_invoke(
                        agent_id=AGENT_ID,
                        mcp_server_id=MCP_ID,
                        tool_name=TOOL,
                        tool_fn=tool_fn,
                    )

            tool_fn.assert_not_called()
            mock_client.enforcement.enforce_mcp_call.assert_not_called()

        finally:
            audit_mod._emitter = original_emitter

    def test_interceptor_conditional_calls_server(self):
        """Conditional escalation DOES call server (expected)."""
        from kswitch.interceptor import KSwitchInterceptor
        from kswitch.models import EnforcementDecision, OutputPolicy

        conditional_decision = LocalDecision(
            outcome="conditional",
            reason="bundle_unavailable",
            allowed=False,
            decision_path=["local_sdk", "bundle_miss_escalate"],
            agent_id=AGENT_ID,
            mcp_server_id=MCP_ID,
            tool_name=TOOL,
        )

        mock_client = MagicMock()
        server_allow = EnforcementDecision(
            allowed=True, reason="allowed", outcome="allow",
            output_policy=OutputPolicy(mode="allow_raw"),
        )
        mock_client.enforcement.enforce_mcp_call.return_value = server_allow

        interceptor = KSwitchInterceptor(mock_client)
        tool_fn = MagicMock(return_value="escalated_result")

        with patch("kswitch.local_pdp.evaluator.get_evaluator") as mock_ev:
            mock_ev.return_value.evaluate.return_value = conditional_decision
            result = interceptor.check_and_invoke(
                agent_id=AGENT_ID,
                mcp_server_id=MCP_ID,
                tool_name=TOOL,
                tool_fn=tool_fn,
            )

        assert result == "escalated_result"
        mock_client.enforcement.enforce_mcp_call.assert_called_once()
