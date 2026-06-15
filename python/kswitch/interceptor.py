"""KSwitch SDK interceptor — mandatory safe execution path (PR-05/PR-06).

KSwitchInterceptor wraps enforcement + pre-invoke obligation blocking +
tool invocation + output filtering + obligation reporting into a single
``check_and_invoke()`` call. Callers must not bypass this path.

Bypass prevention contract:
  - If enforcement returns denied  → raises KSwitchEnforcementError  (never invokes tool)
  - If credential_risk critical/high obligation is present → raises KSwitchObligationError
    (never invokes tool)
  - If anomaly_detection critical obligation is present   → raises KSwitchObligationError
    (never invokes tool)
  - If output_policy.mode == deny_export                  → raises OutputDeniedError
    (tool ran but output is suppressed)
  - All other output_policy modes apply field masking / truncation to returned value

Obligation reporting is best-effort (errors are silently swallowed); the
server validates whether reported obligations match the original decision.
"""

from __future__ import annotations

import json
import os
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Callable

from .models import EnforcementDecision, OutputPolicy

if TYPE_CHECKING:
    from .client import KSwitchClient, KSwitchAsyncClient

# ── Optional OTEL tracing for Layer C (eBPF correlation) ─────────────────────
try:
    from opentelemetry import trace
    _tracer = trace.get_tracer("kswitch.enforcement")
except ImportError:
    _tracer = None  # type: ignore[assignment]

# ── Execution token context — stores the active token for the current call ───
# Downstream HTTP clients can read this to attach Authorization: Bearer headers.
_active_execution_token: ContextVar[str | None] = ContextVar(
    "kswitch_active_execution_token", default=None
)


def get_active_execution_token() -> str | None:
    """Return the execution token for the current governed call, or None.

    Downstream tool implementations can call this to attach the token::

        token = kswitch.interceptor.get_active_execution_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    """
    return _active_execution_token.get()


def _extract_token_jti(token: str | None) -> str:
    """Extract the JTI claim from a JWT execution token. Never raises."""
    if not token:
        return ""
    try:
        import base64 as _b64
        parts = token.split(".")
        if len(parts) != 3:
            return ""
        claims = json.loads(_b64.urlsafe_b64decode(parts[1] + "=="))
        return claims.get("jti", "")
    except Exception:
        return ""


def _try_issue_token(
    decision: Any,
    agent_id: str,
    mcp_server_id: str,
    tool_name: str,
    context: dict | None,
) -> str | None:
    """Issue execution token if tokens are enabled. Never raises — best-effort."""
    if not os.environ.get("KSWITCH_EXECUTION_TOKENS_ENABLED", "false").lower() == "true":
        return None
    try:
        from .tokens.issuer import KSwitchTokenIssuer
        issuer = KSwitchTokenIssuer.from_env()
        token = issuer.issue(
            decision,
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            context=context,
        )
        _emit_token_issuance_audit(token, agent_id, mcp_server_id, tool_name)
        return token
    except Exception as _te:
        import logging as _logging
        _logging.getLogger(__name__).debug("Token issuance skipped: %s", _te)
        return None


def _emit_token_issuance_audit(
    token: str, agent_id: str, mcp_server_id: str, tool_name: str
) -> None:
    """Emit execution_token_issued event via SDK AuditEmitter. Never raises."""
    try:
        import base64 as _b64, json as _json, uuid as _uuid, time as _t
        from datetime import datetime, timezone
        parts = token.split(".")
        if len(parts) != 3:
            return
        claims = _json.loads(_b64.urlsafe_b64decode(parts[1] + "==" ))
        risk_tier = claims.get("risk_tier", "low")
        ttl = int(claims.get("exp", 0)) - int(claims.get("iat", 0))

        from .audit.emitter import emit_decision_event
        emit_decision_event(
            event_type="execution_token_issued",
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            allowed=True,
            reason="token_issued",
            decision_id=claims.get("decision_id", ""),
            extra={
                "jti": claims.get("jti"),
                "risk_tier": risk_tier,
                "single_use": claims.get("single_use", False),
                "ttl_seconds": ttl,
                "req_hash_included": "req_hash" in claims,
                "sdk_language": "python",
            },
        )
    except Exception:
        pass


# ── Interceptor-specific exceptions ──────────────────────────────────────────


class KSwitchEnforcementError(Exception):
    """Raised when the enforcement decision is DENY.

    The tool function is never invoked when this is raised.
    """

    def __init__(self, reason: str, decision: EnforcementDecision):
        super().__init__(f"MCP call denied: {reason}")
        self.reason = reason
        self.decision = decision


class KSwitchObligationError(Exception):
    """Raised when a pre-invoke obligation mandates blocking the call.

    Triggered by:
      - credential_risk at level critical or high
      - anomaly_detection at level critical

    The tool function is never invoked when this is raised.
    """

    def __init__(self, reason: str, obligation: Any, decision: EnforcementDecision):
        super().__init__(f"Pre-invoke obligation blocked call: {reason}")
        self.reason = reason
        self.obligation = obligation
        self.decision = decision


class OutputDeniedError(Exception):
    """Raised when output_policy.mode == deny_export.

    The tool ran but its output must not be returned to the caller.
    """

    def __init__(self, message: str = "Output export denied by governance policy"):
        super().__init__(message)
        self.message = message


# ── Obligation type constants (mirrors server-side ObligationType) ────────────

_OB_CREDENTIAL_RISK = "credential_risk"
_OB_ANOMALY_DETECTION = "anomaly_detection"

# Levels that trigger pre-invoke blocking for credential_risk
_CRED_BLOCK_LEVELS = frozenset({"critical", "high"})

# ── Output policy mode constants ──────────────────────────────────────────────

_MODE_ALLOW_RAW = "allow_raw"
_MODE_DENY_EXPORT = "deny_export"
_MODE_MASK_FIELDS = "mask_fields"
_MODE_TRUNCATE = "truncate"
_MODE_SUMMARIZE_ONLY = "summarize_only"
_MODE_REQUIRE_RELEASE = "require_release"

# Field name substrings that indicate sensitive content (mirrors server-side list)
_SENSITIVE_FIELD_PATTERNS = (
    "ssn", "social_security", "passport", "dob", "date_of_birth",
    "account_number", "card_number", "cvv", "routing_number",
    "tax_id", "ein", "phone", "email", "address", "zip", "postal",
    "salary", "income", "net_worth", "balance", "position", "trade",
    "ticker", "isin", "cusip", "mnpi", "insider",
    "password", "secret", "token", "api_key", "private_key", "credential",
    "health", "diagnosis", "medication", "prescription", "patient",
)


# ── Synchronous interceptor ───────────────────────────────────────────────────


class KSwitchInterceptor:
    """Synchronous interceptor: enforce → block → invoke → filter → report.

    Usage::

        interceptor = KSwitchInterceptor(client)
        result = interceptor.check_and_invoke(
            agent_id="agent:fraud-detector@bank.internal",
            mcp_server_id="mcp:payment-gateway@bank.internal",
            tool_name="initiate_payment",
            tool_fn=payment_tool.initiate_payment,
            tool_args={"amount": 100, "currency": "USD"},
        )
    """

    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def check_and_invoke(
        self,
        *,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Enforce, invoke, and filter. Tries local PDP first, escalates if needed.

        Local path (no network):
          revocation cache → context pack → bundle → Cedar → allow/deny

        Escalation path (network, exception only):
          local path returns "conditional" → fall back to server HTTP

        Always emits audit event.
        """
        if _tracer is not None:
            with _tracer.start_as_current_span("kswitch.check_and_invoke") as span:
                return self._check_and_invoke_inner(
                    span=span,
                    agent_id=agent_id,
                    mcp_server_id=mcp_server_id,
                    tool_name=tool_name,
                    tool_fn=tool_fn,
                    tool_args=tool_args,
                    context=context,
                )
        return self._check_and_invoke_inner(
            span=None,
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            tool_fn=tool_fn,
            tool_args=tool_args,
            context=context,
        )

    def _check_and_invoke_inner(
        self,
        *,
        span: Any,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        import time as _time
        _t0 = _time.time()

        # ── 1. Try local PDP evaluation ───────────────────────────────────────
        local_decision = None
        try:
            from .local_pdp.evaluator import get_evaluator
            _evaluator = get_evaluator()
            local_decision = _evaluator.evaluate(
                agent_id=agent_id,
                mcp_server_id=mcp_server_id,
                tool_name=tool_name,
                context=context,
            )
        except Exception:
            # Local PDP failed unexpectedly — fall through to server
            local_decision = None

        # ── 2. Route: local deny ──────────────────────────────────────────────
        if local_decision is not None and local_decision.outcome == "deny":
            elapsed = (_time.time() - _t0) * 1000
            _emit_local_audit(local_decision, elapsed)
            if span is not None:
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", False)
                span.set_attribute("kswitch.deny_reason", local_decision.reason)
            raise KSwitchEnforcementError(local_decision.reason, _local_to_decision(local_decision))

        # ── 3. Route: local allow — skip server entirely ──────────────────────
        if local_decision is not None and local_decision.outcome == "allow":
            # Pre-invoke obligation check (credential_risk, anomaly_detection)
            synthetic_decision = _local_to_decision(local_decision)
            _enforce_pre_invoke_obligations(synthetic_decision)

            # L2: Issue execution token on ALLOW; store in ContextVar for tool use
            _exec_token = _try_issue_token(synthetic_decision, agent_id, mcp_server_id, tool_name, context)
            _tok_reset = _active_execution_token.set(_exec_token)

            if span is not None:
                span.set_attribute("kswitch.token_id", _extract_token_jti(_exec_token))
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", True)

            # Invoke tool
            try:
                raw_output = tool_fn(**(tool_args or {}))
            finally:
                _active_execution_token.reset(_tok_reset)

            # Apply output policy (local)
            op = None
            if local_decision.output_policy:
                from .models import OutputPolicy
                op = OutputPolicy(**local_decision.output_policy)
            filtered = _apply_output_policy(raw_output, op)

            elapsed = (_time.time() - _t0) * 1000
            _emit_local_audit(local_decision, elapsed)
            # Best-effort report to server (non-blocking)
            _report_obligations_sync(self._client, synthetic_decision)
            return filtered

        # ── 4. Route: conditional/escalation — call server ────────────────────
        # (This is the fallback path for: missing bundle, missing context, cedarpy absent)
        decision = self._client.enforcement.enforce_mcp_call(  # kswitch: allow-unsafe — sdk-internal: server fallback after local PDP conditional/miss
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            context=context,
        )

        if not decision.allowed:
            elapsed = (_time.time() - _t0) * 1000
            _emit_server_audit(decision, agent_id, mcp_server_id, tool_name, elapsed)
            if span is not None:
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", False)
                span.set_attribute("kswitch.deny_reason", decision.reason or "denied")
            raise KSwitchEnforcementError(decision.reason or "denied", decision)

        _enforce_pre_invoke_obligations(decision)

        # L2: Issue execution token on server ALLOW; server may also return one
        _exec_token = _try_issue_token(decision, agent_id, mcp_server_id, tool_name, context)
        _tok_reset = _active_execution_token.set(_exec_token)

        if span is not None:
            span.set_attribute("kswitch.token_id", _extract_token_jti(_exec_token))
            span.set_attribute("kswitch.tool_name", tool_name)
            span.set_attribute("kswitch.governed", True)

        try:
            raw_output = tool_fn(**(tool_args or {}))
        finally:
            _active_execution_token.reset(_tok_reset)

        filtered = _apply_output_policy(raw_output, decision.output_policy)
        elapsed = (_time.time() - _t0) * 1000
        _emit_server_audit(decision, agent_id, mcp_server_id, tool_name, elapsed)
        _report_obligations_sync(self._client, decision)
        return filtered


# ── Asynchronous interceptor ──────────────────────────────────────────────────


class KSwitchAsyncInterceptor:
    """Asynchronous interceptor: enforce → block → invoke → filter → report.

    Usage::

        interceptor = KSwitchAsyncInterceptor(async_client)
        result = await interceptor.check_and_invoke(
            agent_id="agent:fraud-detector@bank.internal",
            mcp_server_id="mcp:payment-gateway@bank.internal",
            tool_name="initiate_payment",
            tool_fn=payment_tool.initiate_payment_async,
            tool_args={"amount": 100, "currency": "USD"},
        )
    """

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._client = client

    async def check_and_invoke(
        self,
        *,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Async enforce, invoke, filter. Tries local PDP first, escalates if needed.

        PR-13 (Async Local PDP): Mirrors the sync KSwitchInterceptor path exactly.

        Local path (no network):
          revocation cache → context pack → bundle → Cedar → allow/deny
          Uses asyncio.to_thread() to run the sync-safe local evaluator without
          blocking the event loop.

        Escalation path (network, exception only):
          local path returns "conditional" → fall back to server HTTP

        Always emits audit event. Runtime tagged as LOCAL_RUNTIME_PYTHON_ASYNC.
        """
        if _tracer is not None:
            with _tracer.start_as_current_span("kswitch.check_and_invoke") as span:
                return await self._check_and_invoke_inner(
                    span=span,
                    agent_id=agent_id,
                    mcp_server_id=mcp_server_id,
                    tool_name=tool_name,
                    tool_fn=tool_fn,
                    tool_args=tool_args,
                    context=context,
                )
        return await self._check_and_invoke_inner(
            span=None,
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            tool_fn=tool_fn,
            tool_args=tool_args,
            context=context,
        )

    async def _check_and_invoke_inner(
        self,
        *,
        span: Any,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        import asyncio
        import inspect
        import time as _time
        _t0 = _time.time()

        # ── 1. Try local PDP evaluation (non-blocking via to_thread) ─────────
        # The local evaluator is sync-safe (threading.RLock, disk reads only).
        # asyncio.to_thread() runs it in the default ThreadPoolExecutor so it
        # never blocks the event loop.
        local_decision = None
        try:
            from .local_pdp.evaluator import get_evaluator
            _evaluator = get_evaluator()
            local_decision = await asyncio.to_thread(
                _evaluator.evaluate,
                agent_id,
                mcp_server_id,
                tool_name,
                context,
            )
            # Tag async runtime mode for audit/telemetry
            if local_decision is not None:
                local_decision.evaluation_mode = "LOCAL_RUNTIME_PYTHON_ASYNC"
        except Exception:
            # Local PDP failed unexpectedly — fall through to server
            local_decision = None

        # ── 2. Route: local deny ──────────────────────────────────────────────
        if local_decision is not None and local_decision.outcome == "deny":
            elapsed = (_time.time() - _t0) * 1000
            _emit_local_audit(local_decision, elapsed)
            if span is not None:
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", False)
                span.set_attribute("kswitch.deny_reason", local_decision.reason)
            raise KSwitchEnforcementError(
                local_decision.reason, _local_to_decision(local_decision)
            )

        # ── 3. Route: local allow — skip server entirely ──────────────────────
        if local_decision is not None and local_decision.outcome == "allow":
            synthetic_decision = _local_to_decision(local_decision)
            _enforce_pre_invoke_obligations(synthetic_decision)

            # L2: Issue execution token; store in ContextVar
            _exec_token = _try_issue_token(synthetic_decision, agent_id, mcp_server_id, tool_name, context)
            _tok_reset = _active_execution_token.set(_exec_token)

            if span is not None:
                span.set_attribute("kswitch.token_id", _extract_token_jti(_exec_token))
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", True)

            # Invoke tool (await if coroutine)
            try:
                if inspect.iscoroutinefunction(tool_fn):
                    raw_output = await tool_fn(**(tool_args or {}))
                else:
                    raw_output = tool_fn(**(tool_args or {}))
            finally:
                _active_execution_token.reset(_tok_reset)

            # Apply output policy
            op = None
            if local_decision.output_policy:
                from .models import OutputPolicy
                op = OutputPolicy(**local_decision.output_policy)
            filtered = _apply_output_policy(raw_output, op)

            elapsed = (_time.time() - _t0) * 1000
            _emit_local_audit(local_decision, elapsed)
            # Best-effort obligation report to server (async, non-blocking)
            await _report_obligations_async(self._client, synthetic_decision)
            return filtered

        # ── 4. Route: conditional/escalation — call server ────────────────────
        # Only reached when: local PDP returned "conditional" (missing bundle/
        # context/cedarpy) OR local PDP crashed. Server is the sole network hop.
        decision = await self._client.enforcement.enforce_mcp_call(  # kswitch: allow-unsafe — sdk-internal: async server fallback after local PDP conditional/miss
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            context=context,
        )

        if not decision.allowed:
            elapsed = (_time.time() - _t0) * 1000
            _emit_server_audit(decision, agent_id, mcp_server_id, tool_name, elapsed)
            if span is not None:
                span.set_attribute("kswitch.tool_name", tool_name)
                span.set_attribute("kswitch.governed", False)
                span.set_attribute("kswitch.deny_reason", decision.reason or "denied")
            raise KSwitchEnforcementError(decision.reason or "denied", decision)

        _enforce_pre_invoke_obligations(decision)

        # L2: Issue execution token on server ALLOW
        _exec_token = _try_issue_token(decision, agent_id, mcp_server_id, tool_name, context)
        _tok_reset = _active_execution_token.set(_exec_token)

        if span is not None:
            span.set_attribute("kswitch.token_id", _extract_token_jti(_exec_token))
            span.set_attribute("kswitch.tool_name", tool_name)
            span.set_attribute("kswitch.governed", True)

        try:
            if inspect.iscoroutinefunction(tool_fn):
                raw_output = await tool_fn(**(tool_args or {}))
            else:
                raw_output = tool_fn(**(tool_args or {}))
        finally:
            _active_execution_token.reset(_tok_reset)

        filtered = _apply_output_policy(raw_output, decision.output_policy)
        elapsed = (_time.time() - _t0) * 1000
        _emit_server_audit(decision, agent_id, mcp_server_id, tool_name, elapsed)
        await _report_obligations_async(self._client, decision)
        return filtered


# ── Shared enforcement helpers (module-level, usable without an interceptor) ──


def _enforce_pre_invoke_obligations(decision: EnforcementDecision) -> None:
    """Raise KSwitchObligationError for any obligation that must block invocation.

    Blocking obligations:
      - credential_risk at level critical or high
      - anomaly_detection at level critical
    """
    for ob in decision.obligations or []:
        ob_type = (ob.obligation_type or ob.type or "").lower()
        level = (ob.level or "").lower()

        if ob_type == _OB_CREDENTIAL_RISK and level in _CRED_BLOCK_LEVELS:
            raise KSwitchObligationError(
                f"credential_risk={level} blocks tool invocation",
                ob,
                decision,
            )

        if ob_type == _OB_ANOMALY_DETECTION and level == "critical":
            raise KSwitchObligationError(
                "anomaly_detection=critical blocks tool invocation",
                ob,
                decision,
            )


def _apply_output_policy(output: Any, policy: OutputPolicy | None) -> Any:
    """Apply SDK-side output policy to raw tool output.

    This mirrors the server-side apply_output_policy() and is the
    client-side enforcement of the output_guard.
    """
    if policy is None:
        return output

    mode = (policy.mode or _MODE_ALLOW_RAW).lower()

    if mode == _MODE_ALLOW_RAW:
        return output

    if mode == _MODE_DENY_EXPORT:
        raise OutputDeniedError(
            f"Output export denied by governance policy "
            f"(classifications: {policy.masking_classifications or 'critical'})"
        )

    if mode == _MODE_MASK_FIELDS:
        return _mask_output(output, policy.masking_classifications or [])

    if mode == _MODE_TRUNCATE:
        return _truncate_output(output, policy.max_output_bytes)

    if mode == _MODE_SUMMARIZE_ONLY:
        # PR-09 stub
        return {
            "_output_mode": "summarize_only",
            "_note": "Output summarization not yet implemented (PR-09)",
            "_original_type": type(output).__name__,
        }

    if mode == _MODE_REQUIRE_RELEASE:
        # PR-08 stub
        return {
            "_output_mode": "require_release",
            "_note": "Output held pending human release authorization",
            "_held": True,
        }

    # Unknown mode — allow raw (fail-open for output)
    return output


def _mask_output(output: Any, classifications: list[str]) -> Any:
    """Recursively redact sensitive fields."""
    if isinstance(output, dict):
        return {k: _redact_value(k, v, classifications) for k, v in output.items()}
    if isinstance(output, list):
        return [_mask_output(item, classifications) for item in output]
    return output


def _redact_value(key: str, value: Any, classifications: list[str]) -> Any:
    key_lower = key.lower().replace("-", "_").replace(" ", "_")
    cls_patterns = tuple(c.lower() for c in classifications)
    is_sensitive = (
        any(pat in key_lower for pat in _SENSITIVE_FIELD_PATTERNS)
        or any(pat in key_lower for pat in cls_patterns)
    )
    if is_sensitive:
        cls_label = ", ".join(classifications) if classifications else "sensitive"
        return f"[REDACTED: {cls_label}]"
    if isinstance(value, (dict, list)):
        return _mask_output(value, classifications)
    return value


def _truncate_output(output: Any, max_bytes: int | None) -> Any:
    if max_bytes is None or max_bytes <= 0:
        return output
    if isinstance(output, str):
        raw = output.encode("utf-8")
        if len(raw) <= max_bytes:
            return output
        return raw[:max_bytes].decode("utf-8", errors="replace") + "…[TRUNCATED]"
    try:
        serialized = json.dumps(output, separators=(",", ":"))
    except Exception:
        serialized = str(output)
    raw = serialized.encode("utf-8")
    if len(raw) <= max_bytes:
        return output
    truncated = raw[:max_bytes].decode("utf-8", errors="replace")
    return {"_truncated": True, "_max_bytes": max_bytes, "_content": truncated + "…"}


def _report_obligations_sync(client: Any, decision: EnforcementDecision) -> None:
    """Best-effort obligation report (sync). Never raises."""
    enforcement_id = decision.enforcement_id or ""
    if not enforcement_id:
        return
    ob_types = [
        (ob.obligation_type or ob.type or "") for ob in (decision.obligations or [])
    ]
    try:
        client.enforcement.report_obligations(enforcement_id, ob_types)
    except Exception:
        pass  # Best-effort: reporting failure must never fail the tool call


async def _report_obligations_async(client: Any, decision: EnforcementDecision) -> None:
    """Best-effort obligation report (async). Never raises."""
    enforcement_id = decision.enforcement_id or ""
    if not enforcement_id:
        return
    ob_types = [
        (ob.obligation_type or ob.type or "") for ob in (decision.obligations or [])
    ]
    try:
        await client.enforcement.report_obligations(enforcement_id, ob_types)
    except Exception:
        pass


def _local_to_decision(ld: Any) -> "EnforcementDecision":
    """Convert LocalDecision to EnforcementDecision for obligation/output processing."""
    from .models import EnforcementDecision, Obligation, OutputPolicy
    obs = []
    for ob in (ld.obligations or []):
        obs.append(Obligation(
            type=ob.get("type", ""),
            obligation_type=ob.get("obligation_type", ""),
            level=ob.get("level", "low"),
        ))
    op = None
    if ld.output_policy:
        op = OutputPolicy(**ld.output_policy)
    return EnforcementDecision(
        allowed=ld.allowed,
        reason=ld.reason,
        outcome=ld.outcome,
        decision_path=ld.decision_path,
        obligations=obs,
        output_policy=op,
        enforcement_id=ld.enforcement_id,
        evaluation_mode=ld.evaluation_mode,
        bundle_version=ld.bundle_version,
        context_pack_id=ld.context_pack_id,
        context_snapshot_id=getattr(ld, "context_snapshot_id", ""),
        context_snapshot_digest=getattr(ld, "context_snapshot_digest", ""),
        context_snapshot=getattr(ld, "context_snapshot", None),
        decision_explanation=getattr(ld, "decision_explanation", None),
    )


def _emit_local_audit(ld: Any, elapsed_ms: float) -> None:
    """Emit audit event for a local PDP decision."""
    try:
        from .audit.emitter import emit_decision_event
        event_type = f"enforcement.{'allow' if ld.allowed else 'deny'}"
        if ld.reason in ("agent_revoked",):
            event_type = "enforcement.revocation_deny"
        emit_decision_event(
            event_type=event_type,
            agent_id=ld.agent_id,
            mcp_server_id=ld.mcp_server_id,
            tool_name=ld.tool_name,
            allowed=ld.allowed,
            reason=ld.reason,
            decision_id=ld.enforcement_id,
            decision_path=ld.decision_path,
            obligations=ld.obligations,
            output_policy=ld.output_policy,
            evaluation_mode=ld.evaluation_mode,
            bundle_version=ld.bundle_version,
            context_pack_id=ld.context_pack_id,
            risk_tier=ld.risk_tier,
            elapsed_ms=elapsed_ms,
        )
    except Exception:
        pass  # Audit failure never fails the call


def _emit_server_audit(decision: Any, agent_id: str, mcp_server_id: str,
                       tool_name: str, elapsed_ms: float) -> None:
    """Emit audit event for a server-escalated decision."""
    try:
        from .audit.emitter import emit_decision_event
        emit_decision_event(
            event_type=f"enforcement.{'allow' if decision.allowed else 'deny'}",
            agent_id=agent_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            allowed=decision.allowed,
            reason=decision.reason or "",
            decision_id=decision.enforcement_id or "",
            decision_path=decision.decision_path,
            obligations=[{
                "type": ob.type or ob.obligation_type,
                "level": ob.level,
            } for ob in decision.obligations],
            output_policy=decision.output_policy.model_dump() if decision.output_policy else None,
            evaluation_mode=decision.evaluation_mode or "central",
            bundle_version=decision.bundle_version or "",
            context_pack_id=decision.context_pack_id or "",
            elapsed_ms=elapsed_ms,
        )
    except Exception:
        pass
