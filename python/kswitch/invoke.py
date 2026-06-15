"""
KSwitchRuntime — governed tool invocation model (Phase 5: bypass-resistant API).

This is the PRIMARY public-facing tool invocation API.
Raw tool functions are NOT the intended public interface.

Usage:
    runtime = KSwitchRuntime(
        agent_id="agent:fraud-detector@bank.internal",
        mcp_server_id="mcp:payment-gateway@bank.internal",
        client=client,  # Optional: for server escalation/obligation reporting
    )

    # Register tools (governed path becomes the default callable surface)
    runtime.register("initiate_payment", payment_tool.initiate_payment)
    runtime.register("get_balance", payment_tool.get_balance)

    # Governed invocation — enforce → invoke → output filter → audit
    result = runtime.invoke("initiate_payment", amount=100, currency="USD")

    # Unsafe/raw invocation is explicitly constrained
    # payment_tool.initiate_payment(amount=100)  ← NOT the supported path

PR-11 (Revocation Sync):
    KSwitchRuntime optionally starts a background RevocationSyncWorker when
    a client is provided. The sync worker polls the server for revocation state
    changes and atomically updates the local cache in the background.
    Normal-path invocations continue using O(1) local lookup — no sync latency.

    Auto-sync is enabled by default (KSWITCH_REVOCATION_SYNC_ENABLED=true).
    Disable by passing start_revocation_sync=False or setting the env var.
"""

from __future__ import annotations

import warnings
from typing import Any, Callable, Optional, TYPE_CHECKING

from .interceptor import (
    KSwitchInterceptor, KSwitchEnforcementError,
    KSwitchObligationError, OutputDeniedError,
)

if TYPE_CHECKING:
    from .client import KSwitchClient


class GovernedTool:
    """A tool wrapped for governed invocation. Not a raw callable by design."""

    def __init__(self, name: str, fn: Callable, runtime: "KSwitchRuntime"):
        self._name = name
        self._fn = fn
        self._runtime = runtime
        # Discourage direct access to raw callable
        self.__doc__ = (
            f"Governed tool '{name}'. "
            f"Call via runtime.invoke('{name}', ...) not directly."
        )

    @property
    def name(self) -> str:
        return self._name

    def _unsafe_raw_call(self, **kwargs) -> Any:
        """Direct raw invocation — bypasses governance. NOT the supported path.

        .. warning::
            This bypasses enforcement, output filtering, and audit.
            Only use for testing. Use runtime.invoke() for production.
        """
        warnings.warn(
            f"Direct raw invocation of '{self._name}' bypasses KSwitch governance "
            "(no enforcement, no output filtering, no audit). "
            "Use KSwitchRuntime.invoke() instead.",
            stacklevel=2,
            category=UserWarning,
        )
        return self._fn(**kwargs)  # kswitch: allow-unsafe — deprecated helper: emits UserWarning before raw call; intentional escape hatch for migration

    def __call__(self, **kwargs) -> Any:
        """Calling a GovernedTool directly routes through governance."""
        return self._runtime.invoke(self._name, **kwargs)

    def __repr__(self) -> str:
        return f"<GovernedTool name={self._name!r}>"


class KSwitchRuntime:
    """Governed tool invocation runtime.

    This is the bypass-resistant Python SDK API. Tools are registered
    with the runtime and exposed only as governed callables.

    The governed path (runtime.invoke) is the primary API.
    Raw function access is structurally discouraged.

    PR-11: If a client is provided, a background RevocationSyncWorker is started
    automatically (controlled by KSWITCH_REVOCATION_SYNC_ENABLED). Stop it via
    runtime.stop_revocation_sync() or it will auto-stop when the process exits.
    """

    def __init__(
        self,
        agent_id: str,
        mcp_server_id: str,
        client: Optional["KSwitchClient"] = None,
        start_revocation_sync: Optional[bool] = None,
    ):
        """
        Args:
            agent_id:               Agent identity string.
            mcp_server_id:          MCP server identity string.
            client:                 Optional KSwitchClient for server fallback and
                                    obligation reporting. Also used for revocation sync.
            start_revocation_sync:  Override sync auto-start. None = use config default.
        """
        self._agent_id = agent_id
        self._mcp_server_id = mcp_server_id
        self._tools: dict[str, GovernedTool] = {}
        self._interceptor: Optional[KSwitchInterceptor] = None
        self._sync_worker = None
        self._context_invalidation_worker = None
        self._audit_sender = None

        if client is not None:
            self._interceptor = KSwitchInterceptor(client)
            self._maybe_start_sync_worker(client, start_revocation_sync)
            self._maybe_start_audit_sender(client)

    def _maybe_start_sync_worker(self, client: Any, override: Optional[bool]) -> None:
        """Start the revocation sync worker if enabled."""
        try:
            from . import config
            enabled = override if override is not None else config.REVOCATION_SYNC_ENABLED
            if not enabled:
                return
            from .revocation.sync import start_sync_worker
            # Access the underlying httpx client from KSwitchClient
            http_client = getattr(client, "_http", None)
            base_url = getattr(client, "_base_url", None)
            if http_client is None or base_url is None:
                return
            self._sync_worker = start_sync_worker(
                http_client=http_client,
                base_url=base_url,
                interval=config.REVOCATION_SYNC_INTERVAL,
                stale_threshold=config.REVOCATION_STALE_THRESHOLD,
                stale_mode=config.REVOCATION_STALE_MODE,
            )
            if config.CONTEXT_INVALIDATION_SYNC_ENABLED:
                from .context.invalidation_sync import start_invalidation_sync_worker
                self._context_invalidation_worker = start_invalidation_sync_worker(
                    http_client=http_client,
                    base_url=base_url,
                    interval=config.CONTEXT_INVALIDATION_SYNC_INTERVAL,
                )
        except Exception:
            pass  # Sync start failure is non-fatal — local cache still functions

    def stop_revocation_sync(self) -> None:
        """Stop background revocation and context invalidation sync workers."""
        if self._sync_worker is not None:
            self._sync_worker.stop()
            self._sync_worker = None
        if self._context_invalidation_worker is not None:
            self._context_invalidation_worker.stop()
            self._context_invalidation_worker = None

    def _maybe_start_audit_sender(self, client: Any) -> None:
        """Start the audit sender if forwarding is enabled."""
        try:
            from . import config
            if not config.AUDIT_FORWARDING_ENABLED:
                return
            from .audit.sender import start_audit_sender
            from .audit.emitter import get_audit_emitter
            http_client = getattr(client, "_http", None)
            base_url = getattr(client, "_base_url", None)
            if http_client is None or base_url is None:
                return
            ingest_url = config.AUDIT_INGEST_URL or (base_url.rstrip("/") + "/api/v1/sdk/audit/events")
            self._audit_sender = start_audit_sender(
                http_client=http_client,
                ingest_url=ingest_url,
                batch_size=config.AUDIT_BATCH_SIZE,
                flush_interval=config.AUDIT_FLUSH_INTERVAL,
                max_retries=config.AUDIT_MAX_RETRIES,
            )
            # Wire sender into emitter singleton
            get_audit_emitter().set_sender(self._audit_sender)
        except Exception:
            pass  # Audit sender start failure is non-fatal

    def stop_audit_sender(self) -> None:
        """Stop the background audit sender (for clean shutdown)."""
        if self._audit_sender is not None:
            from .audit.sender import stop_audit_sender
            stop_audit_sender()
            self._audit_sender = None

    def audit_diagnostics(self) -> dict:
        """Return audit forwarding status for observability."""
        from .audit.emitter import get_audit_emitter
        from .audit.sender import get_audit_sender
        sender = get_audit_sender()
        return {
            "forwarding_enabled": sender is not None and sender.is_running(),
            "sender": sender.diagnostics() if sender else {"running": False},
            "local_jsonl_path": get_audit_emitter()._path,
        }

    def revocation_sync_diagnostics(self) -> dict:
        """Return revocation sync status for observability."""
        context_diag = (
            self._context_invalidation_worker.diagnostics()
            if self._context_invalidation_worker is not None
            else {"running": False, "reason": "not_configured"}
        )
        if self._sync_worker is not None:
            diag = self._sync_worker.diagnostics()
            diag["context_invalidation_sync"] = context_diag
            return diag
        from .revocation.cache import get_revocation_cache
        return {
            "sync_worker": {"running": False, "reason": "not_configured"},
            "context_invalidation_sync": context_diag,
            "cache": get_revocation_cache().get_diagnostics(),
        }

    def register(self, tool_name: str, tool_fn: Callable) -> "GovernedTool":
        """Register a tool. Returns a GovernedTool (governed callable).

        The raw tool_fn is stored internally and ONLY invoked via the
        governed path. Callers should use runtime.invoke() or the
        returned GovernedTool.__call__() — both route through governance.
        """
        governed = GovernedTool(name=tool_name, fn=tool_fn, runtime=self)
        self._tools[tool_name] = governed
        return governed

    def invoke(
        self,
        tool_name: str,
        *,
        context: dict[str, Any] | None = None,
        **tool_kwargs: Any,
    ) -> Any:
        """Governed invocation: enforce → invoke → output filter → audit.

        This is the ONLY supported production invocation path.

        Args:
            tool_name: The registered tool name.
            context:   Optional enforcement context (delegated_from, etc.).
            **tool_kwargs: Arguments forwarded to the tool function.

        Raises:
            KeyError: Tool not registered.
            KSwitchEnforcementError: Decision was DENY.
            KSwitchObligationError: Critical pre-invoke obligation blocks call.
            OutputDeniedError: Output policy = deny_export.
        """
        if tool_name not in self._tools:
            raise KeyError(
                f"Tool '{tool_name}' not registered with KSwitchRuntime. "
                f"Call runtime.register('{tool_name}', fn) first."
            )
        governed_tool = self._tools[tool_name]

        if self._interceptor is not None:
            # Full governed path: local PDP → tool → output guard → audit
            return self._interceptor.check_and_invoke(
                agent_id=self._agent_id,
                mcp_server_id=self._mcp_server_id,
                tool_name=tool_name,
                tool_fn=governed_tool._fn,
                tool_args=tool_kwargs,
                context=context,
            )
        else:
            # No client — local-only path (no obligation reporting to server)
            from .local_pdp.evaluator import get_evaluator
            from .audit.emitter import emit_decision_event
            import time as _time
            _t0 = _time.time()

            evaluator = get_evaluator()
            local_decision = evaluator.evaluate(
                agent_id=self._agent_id,
                mcp_server_id=self._mcp_server_id,
                tool_name=tool_name,
                context=context,
            )

            if local_decision.outcome == "deny":
                _deny_event_type = "enforcement.deny"
                if local_decision.reason == "agent_revoked":
                    _deny_event_type = "enforcement.revocation_deny"
                emit_decision_event(
                    event_type=_deny_event_type,
                    agent_id=self._agent_id,
                    mcp_server_id=self._mcp_server_id,
                    tool_name=tool_name,
                    allowed=False,
                    reason=local_decision.reason,
                    decision_id=local_decision.enforcement_id,
                    decision_path=local_decision.decision_path,
                    evaluation_mode=local_decision.evaluation_mode,
                    bundle_version=local_decision.bundle_version,
                    elapsed_ms=(_time.time() - _t0) * 1000,
                )
                raise KSwitchEnforcementError(
                    local_decision.reason,
                    _make_bare_decision(local_decision),
                )

            if local_decision.outcome == "conditional":
                raise RuntimeError(
                    f"Tool '{tool_name}' requires server escalation but no client configured. "
                    "Pass client= to KSwitchRuntime to enable server fallback."
                )

            # Allow — invoke and filter
            raw_output = governed_tool._fn(**tool_kwargs)  # kswitch: allow-unsafe — sdk-internal: raw call only after Cedar ALLOW + output policy applied below

            from .interceptor import _apply_output_policy
            from .models import OutputPolicy
            op = OutputPolicy(**local_decision.output_policy) if local_decision.output_policy else None
            filtered = _apply_output_policy(raw_output, op)

            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=self._agent_id,
                mcp_server_id=self._mcp_server_id,
                tool_name=tool_name,
                allowed=True,
                reason="allowed",
                decision_id=local_decision.enforcement_id,
                decision_path=local_decision.decision_path,
                obligations=local_decision.obligations,
                output_policy=local_decision.output_policy,
                evaluation_mode=local_decision.evaluation_mode,
                bundle_version=local_decision.bundle_version,
                context_pack_id=local_decision.context_pack_id,
                elapsed_ms=(_time.time() - _t0) * 1000,
            )
            return filtered

    def tool(self, tool_name: str) -> Optional[GovernedTool]:
        """Get a registered GovernedTool by name."""
        return self._tools.get(tool_name)

    def list_tools(self) -> list[str]:
        """List registered tool names."""
        return list(self._tools.keys())


def _make_bare_decision(ld: Any) -> Any:
    """Create a minimal EnforcementDecision from LocalDecision."""
    from .models import EnforcementDecision
    return EnforcementDecision(
        allowed=ld.allowed,
        reason=ld.reason,
        outcome=ld.outcome,
        decision_path=ld.decision_path,
        evaluation_mode=ld.evaluation_mode,
        enforcement_id=ld.enforcement_id,
        context_snapshot_id=getattr(ld, "context_snapshot_id", ""),
        context_snapshot_digest=getattr(ld, "context_snapshot_digest", ""),
        context_snapshot=getattr(ld, "context_snapshot", None),
        decision_explanation=getattr(ld, "decision_explanation", None),
    )


# ── Async governed invocation model (PR-13) ───────────────────────────────────


class AsyncGovernedTool:
    """A tool wrapped for async governed invocation.

    PR-13: Async counterpart to GovernedTool. Calling an AsyncGovernedTool
    returns a coroutine that routes through KSwitchAsyncRuntime.invoke().
    """

    def __init__(self, name: str, fn: Callable, runtime: "KSwitchAsyncRuntime"):
        self._name = name
        self._fn = fn
        self._runtime = runtime
        self.__doc__ = (
            f"Async governed tool '{name}'. "
            f"Call via await runtime.invoke('{name}', ...) not directly."
        )

    @property
    def name(self) -> str:
        return self._name

    def _unsafe_raw_call(self, **kwargs) -> Any:
        """Direct raw invocation — bypasses governance. NOT the supported path.

        .. warning::
            This bypasses enforcement, output filtering, and audit.
            Only use for testing. Use KSwitchAsyncRuntime.invoke() for production.
        """
        warnings.warn(
            f"Direct raw invocation of async '{self._name}' bypasses KSwitch governance "
            "(no enforcement, no output filtering, no audit). "
            "Use KSwitchAsyncRuntime.invoke() instead.",
            stacklevel=2,
            category=UserWarning,
        )
        return self._fn(**kwargs)  # kswitch: allow-unsafe — deprecated helper: emits UserWarning before raw call; intentional async escape hatch for migration

    async def __call__(self, **kwargs) -> Any:
        """Calling an AsyncGovernedTool directly routes through governance."""
        return await self._runtime.invoke(self._name, **kwargs)

    def __repr__(self) -> str:
        return f"<AsyncGovernedTool name={self._name!r}>"


class KSwitchAsyncRuntime:
    """Async governed tool invocation runtime.

    PR-13 (Async Local PDP): Async counterpart to KSwitchRuntime. Uses
    KSwitchAsyncInterceptor which now evaluates locally first via
    asyncio.to_thread(), falling back to server only on conditional.

    Usage::

        runtime = KSwitchAsyncRuntime(
            agent_id="agent:fraud-detector@bank.internal",
            mcp_server_id="mcp:payment-gateway@bank.internal",
            client=async_client,
        )
        runtime.register("initiate_payment", payment_tool.initiate_payment_async)
        result = await runtime.invoke("initiate_payment", amount=100)
    """

    def __init__(
        self,
        agent_id: str,
        mcp_server_id: str,
        client: Optional[Any] = None,
        start_revocation_sync: Optional[bool] = None,
    ):
        self._agent_id = agent_id
        self._mcp_server_id = mcp_server_id
        self._tools: dict[str, AsyncGovernedTool] = {}
        self._interceptor: Optional[Any] = None
        self._sync_worker = None
        self._context_invalidation_worker = None
        self._audit_sender = None

        if client is not None:
            from .interceptor import KSwitchAsyncInterceptor
            self._interceptor = KSwitchAsyncInterceptor(client)
            self._maybe_start_sync_worker(client, start_revocation_sync)
            self._maybe_start_audit_sender(client)

    def _maybe_start_sync_worker(self, client: Any, override: Optional[bool]) -> None:
        """Start the revocation sync worker (same as sync runtime)."""
        try:
            from . import config
            enabled = override if override is not None else config.REVOCATION_SYNC_ENABLED
            if not enabled:
                return
            from .revocation.sync import start_sync_worker
            http_client = getattr(client, "_http", None)
            base_url = getattr(client, "_base_url", None)
            if http_client is None or base_url is None:
                return
            self._sync_worker = start_sync_worker(
                http_client=http_client,
                base_url=base_url,
                interval=config.REVOCATION_SYNC_INTERVAL,
                stale_threshold=config.REVOCATION_STALE_THRESHOLD,
                stale_mode=config.REVOCATION_STALE_MODE,
            )
            if config.CONTEXT_INVALIDATION_SYNC_ENABLED:
                from .context.invalidation_sync import start_invalidation_sync_worker
                self._context_invalidation_worker = start_invalidation_sync_worker(
                    http_client=http_client,
                    base_url=base_url,
                    interval=config.CONTEXT_INVALIDATION_SYNC_INTERVAL,
                )
        except Exception:
            pass

    def _maybe_start_audit_sender(self, client: Any) -> None:
        """Start the audit forwarding sender (same as sync runtime)."""
        try:
            from . import config
            if not config.AUDIT_FORWARDING_ENABLED:
                return
            from .audit.sender import start_audit_sender
            from .audit.emitter import get_audit_emitter
            http_client = getattr(client, "_http", None)
            base_url = getattr(client, "_base_url", None)
            if http_client is None or base_url is None:
                return
            ingest_url = config.AUDIT_INGEST_URL or (
                base_url.rstrip("/") + "/api/v1/sdk/audit/events"
            )
            self._audit_sender = start_audit_sender(
                http_client=http_client,
                ingest_url=ingest_url,
                batch_size=config.AUDIT_BATCH_SIZE,
                flush_interval=config.AUDIT_FLUSH_INTERVAL,
                max_retries=config.AUDIT_MAX_RETRIES,
            )
            get_audit_emitter().set_sender(self._audit_sender)
        except Exception:
            pass

    def register(self, tool_name: str, tool_fn: Callable) -> "AsyncGovernedTool":
        """Register an async tool. Returns an AsyncGovernedTool."""
        governed = AsyncGovernedTool(name=tool_name, fn=tool_fn, runtime=self)
        self._tools[tool_name] = governed
        return governed

    async def invoke(
        self,
        tool_name: str,
        *,
        context: dict[str, Any] | None = None,
        **tool_kwargs: Any,
    ) -> Any:
        """Async governed invocation: enforce → invoke → output filter → audit.

        Local path first (no network for allow/deny), server only on conditional.
        """
        if tool_name not in self._tools:
            raise KeyError(
                f"Tool '{tool_name}' not registered with KSwitchAsyncRuntime. "
                f"Call runtime.register('{tool_name}', fn) first."
            )
        governed_tool = self._tools[tool_name]

        if self._interceptor is not None:
            return await self._interceptor.check_and_invoke(
                agent_id=self._agent_id,
                mcp_server_id=self._mcp_server_id,
                tool_name=tool_name,
                tool_fn=governed_tool._fn,
                tool_args=tool_kwargs,
                context=context,
            )
        else:
            # No client — local-only async path
            import asyncio
            import time as _time
            from .local_pdp.evaluator import get_evaluator
            from .audit.emitter import emit_decision_event
            _t0 = _time.time()

            evaluator = get_evaluator()
            local_decision = await asyncio.to_thread(
                evaluator.evaluate,
                self._agent_id,
                self._mcp_server_id,
                tool_name,
                context,
            )
            local_decision.evaluation_mode = "LOCAL_RUNTIME_PYTHON_ASYNC"

            if local_decision.outcome == "deny":
                _deny_event_type = "enforcement.deny"
                if local_decision.reason == "agent_revoked":
                    _deny_event_type = "enforcement.revocation_deny"
                emit_decision_event(
                    event_type=_deny_event_type,
                    agent_id=self._agent_id,
                    mcp_server_id=self._mcp_server_id,
                    tool_name=tool_name,
                    allowed=False,
                    reason=local_decision.reason,
                    decision_id=local_decision.enforcement_id,
                    decision_path=local_decision.decision_path,
                    evaluation_mode=local_decision.evaluation_mode,
                    bundle_version=local_decision.bundle_version,
                    elapsed_ms=(_time.time() - _t0) * 1000,
                )
                from .interceptor import KSwitchEnforcementError
                raise KSwitchEnforcementError(
                    local_decision.reason,
                    _make_bare_decision(local_decision),
                )

            if local_decision.outcome == "conditional":
                raise RuntimeError(
                    f"Async tool '{tool_name}' requires server escalation "
                    "but no client configured. Pass client= to KSwitchAsyncRuntime."
                )

            # Allow — invoke and filter
            import inspect
            if inspect.iscoroutinefunction(governed_tool._fn):
                raw_output = await governed_tool._fn(**tool_kwargs)  # kswitch: allow-unsafe — sdk-internal: raw call only after Cedar ALLOW; async branch
            else:
                raw_output = governed_tool._fn(**tool_kwargs)  # kswitch: allow-unsafe — sdk-internal: raw call only after Cedar ALLOW; sync branch

            from .interceptor import _apply_output_policy
            from .models import OutputPolicy
            op = OutputPolicy(**local_decision.output_policy) if local_decision.output_policy else None
            filtered = _apply_output_policy(raw_output, op)

            emit_decision_event(
                event_type="enforcement.allow",
                agent_id=self._agent_id,
                mcp_server_id=self._mcp_server_id,
                tool_name=tool_name,
                allowed=True,
                reason="allowed",
                decision_id=local_decision.enforcement_id,
                decision_path=local_decision.decision_path,
                obligations=local_decision.obligations,
                output_policy=local_decision.output_policy,
                evaluation_mode=local_decision.evaluation_mode,
                bundle_version=local_decision.bundle_version,
                context_pack_id=local_decision.context_pack_id,
                elapsed_ms=(_time.time() - _t0) * 1000,
            )
            return filtered

    def tool(self, tool_name: str) -> Optional[AsyncGovernedTool]:
        """Get a registered AsyncGovernedTool by name."""
        return self._tools.get(tool_name)

    def list_tools(self) -> list[str]:
        """List registered tool names."""
        return list(self._tools.keys())

    def stop_revocation_sync(self) -> None:
        """Stop background revocation and context invalidation sync workers."""
        if self._sync_worker is not None:
            self._sync_worker.stop()
            self._sync_worker = None
        if self._context_invalidation_worker is not None:
            self._context_invalidation_worker.stop()
            self._context_invalidation_worker = None

    def revocation_sync_diagnostics(self) -> dict:
        """Return revocation sync status."""
        context_diag = (
            self._context_invalidation_worker.diagnostics()
            if self._context_invalidation_worker is not None
            else {"running": False, "reason": "not_configured"}
        )
        if self._sync_worker is not None:
            diag = self._sync_worker.diagnostics()
            diag["context_invalidation_sync"] = context_diag
            return diag
        from .revocation.cache import get_revocation_cache
        return {
            "sync_worker": {"running": False, "reason": "not_configured"},
            "context_invalidation_sync": context_diag,
            "cache": get_revocation_cache().get_diagnostics(),
        }

    def audit_diagnostics(self) -> dict:
        """Return audit forwarding status."""
        from .audit.emitter import get_audit_emitter
        from .audit.sender import get_audit_sender
        sender = get_audit_sender()
        return {
            "forwarding_enabled": sender is not None and sender.is_running(),
            "sender": sender.diagnostics() if sender else {"running": False},
            "local_jsonl_path": get_audit_emitter()._path,
        }
