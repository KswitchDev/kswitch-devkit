"""
Local audit emitter — writes governed decision events to local JSONL file
and optionally to the server's audit queue.

Audit file: ~/.kswitch/audit/events.jsonl

Event types:
  - enforcement.allow   — local or server ALLOW
  - enforcement.deny    — local or server DENY
  - enforcement.conditional — escalated to server
  - enforcement.revocation_deny — agent in revocation cache

Each event row includes:
  - decision_id, trace_id, bundle_version, context_pack_id
  - policy_set_hash (not available locally — uses bundle_version as proxy)
  - subject tuple (agent_id, mcp_server_id, tool_name)
  - obligations applied, output_policy_mode
  - runtime_mode: LOCAL_RUNTIME_PYTHON
  - timestamp
"""
import json
import os
import threading
import time
import uuid
from typing import Optional, Any

_DEFAULT_AUDIT_DIR = os.path.expanduser("~/.kswitch/audit")
_AUDIT_FILE = "events.jsonl"
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB — rotate after this


class AuditEmitter:
    """Thread-safe local JSONL audit emitter."""

    def __init__(self, audit_dir: str = _DEFAULT_AUDIT_DIR):
        self._dir = audit_dir
        self._lock = threading.Lock()
        self._sender = None  # Optional central AuditSender (PR-12)

    @property
    def _path(self) -> str:
        return os.path.join(self._dir, _AUDIT_FILE)

    def set_sender(self, sender) -> None:
        """Register a central audit sender. Called by KSwitchRuntime when configured."""
        with self._lock:
            self._sender = sender

    def emit(self, event: dict) -> None:
        """Write one event to the JSONL file and optionally forward to server.

        Step 1 (JSONL) is the first and always-present write.
        Step 2 (central forwarding) is optional and non-blocking.
        A failure in Step 2 never affects Step 1.
        """
        # JSONL is the first and always-present write.
        # Central forwarding is optional and non-blocking.
        # A failure in Step 2 never affects Step 1.

        # Step 1: JSONL write (always, never skipped)
        try:
            os.makedirs(self._dir, exist_ok=True)
            # Rotate if too large
            path = self._path
            if os.path.exists(path) and os.path.getsize(path) > _MAX_FILE_SIZE:
                rotated = path + f".{int(time.time())}"
                try:
                    os.rename(path, rotated)
                except OSError:
                    pass
            with self._lock:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, default=str) + "\n")
        except Exception:
            pass  # Audit failure must never fail the governed call

        # Step 2: Central forwarding (best-effort, never blocks)
        try:
            sender = getattr(self, '_sender', None)
            if sender is not None:
                sender.enqueue(event)
        except Exception:
            pass


def _build_event(
    event_type: str,
    agent_id: str,
    mcp_server_id: str,
    tool_name: str,
    allowed: bool,
    reason: str,
    decision_id: str,
    decision_path: list,
    obligations: list,
    output_policy: Optional[dict],
    evaluation_mode: str,
    bundle_version: str = "",
    context_pack_id: str = "",
    risk_tier: str = "medium",
    elapsed_ms: float = 0.0,
) -> dict:
    """Build a structured audit event dict."""
    outcome = "allow" if allowed else "deny"
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_version": "1.0",

        # Subject
        "agent_id": agent_id,
        "mcp_server_id": mcp_server_id,
        "tool_name": tool_name or "",
        "action": "mcp_call",

        # Decision
        "decision_id": decision_id,
        "allowed": allowed,
        "outcome": outcome,
        "reason": reason,
        "decision_path": decision_path,

        # Obligations
        "obligations": obligations or [],
        "output_policy_mode": (output_policy or {}).get("mode", ""),

        # Provenance
        "bundle_version": bundle_version,
        "context_pack_id": context_pack_id,
        "risk_tier": risk_tier,
        "runtime_mode": evaluation_mode,

        # Timing
        "elapsed_ms": elapsed_ms,
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# Module-level singleton
_emitter = AuditEmitter()


def emit_decision_event(
    event_type: str,
    agent_id: str,
    mcp_server_id: str,
    tool_name: str,
    allowed: bool,
    reason: str,
    decision_id: str = "",
    decision_path: list = None,
    obligations: list = None,
    output_policy: Optional[dict] = None,
    evaluation_mode: str = "LOCAL_RUNTIME_PYTHON",
    bundle_version: str = "",
    context_pack_id: str = "",
    risk_tier: str = "medium",
    elapsed_ms: float = 0.0,
) -> None:
    event = _build_event(
        event_type=event_type,
        agent_id=agent_id,
        mcp_server_id=mcp_server_id,
        tool_name=tool_name,
        allowed=allowed,
        reason=reason,
        decision_id=decision_id or str(uuid.uuid4()),
        decision_path=decision_path or [],
        obligations=obligations or [],
        output_policy=output_policy,
        evaluation_mode=evaluation_mode,
        bundle_version=bundle_version,
        context_pack_id=context_pack_id,
        risk_tier=risk_tier,
        elapsed_ms=elapsed_ms,
    )
    _emitter.emit(event)


def get_audit_emitter() -> AuditEmitter:
    return _emitter
