"""Remote read-only AI Brain search/fetch contract for EP-217."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from kswitch_brain_mcp.client import (
    BrainClient,
    BrainUnavailable,
    UnsafeBrainInput,
    validate_query_text,
)

REMOTE_READ_AUDIENCE = "kswitch-ai-brain-remote-read"
REMOTE_READ_SCOPE_SEARCH = "brain.search"
REMOTE_READ_SCOPE_FETCH = "brain.fetch"
REMOTE_READ_MAX_PAYLOAD_BYTES = 4096
REMOTE_READ_MAX_TTL_SECONDS = 300
REMOTE_READ_DEFAULT_TTL_SECONDS = 120
REMOTE_READ_DEV_TOKEN = "dev-local-remote-read-token"
REMOTE_READ_ALLOWED_TOOLS = ("search", "fetch")
REMOTE_SEARCH_SCHEMA = "kswitch.ai_brain.remote_search.request.v1"
REMOTE_FETCH_SCHEMA = "kswitch.ai_brain.remote_fetch.request.v1"


@dataclass(frozen=True)
class RemotePrincipal:
    subject: str
    session_id: str
    audience: str
    scopes: tuple[str, ...]


@dataclass
class ResultLedgerEntry:
    result_id: str
    subject_hash: str
    session_hash: str
    query_hash: str
    memory_id: str
    memory_hash: str
    authority_label: str
    expires_at_epoch: int


@dataclass
class RemoteReadService:
    client: BrainClient
    token_provider: Callable[[], str] | None = None
    now: Callable[[], int] = lambda: int(time.time())
    localhost_dev_mode: bool = False
    ledger: dict[str, ResultLedgerEntry] = field(default_factory=dict)
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def tool_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": "kswitch.ai_brain.remote_tools.v1",
            "tools": list(REMOTE_READ_ALLOWED_TOOLS),
            "read_only": True,
            "write_tools_exposed": False,
        }

    def search(
        self,
        *,
        query: str,
        authorization: str,
        subject: str,
        session_id: str,
        schema_version: str,
        audience: str = REMOTE_READ_AUDIENCE,
        scopes: list[str] | None = None,
        limit: int = 8,
        ttl_seconds: int = REMOTE_READ_DEFAULT_TTL_SECONDS,
    ) -> dict[str, Any]:
        principal = RemotePrincipal(
            subject=str(subject or "").strip(),
            session_id=str(session_id or "").strip(),
            audience=str(audience or "").strip(),
            scopes=tuple(scopes or ()),
        )
        request = {
            "tool": "search",
            "schema_version": schema_version,
            "query": query,
            "authorization": authorization,
            "subject": subject,
            "session_id": session_id,
            "audience": audience,
            "scopes": scopes or [],
            "limit": limit,
            "ttl_seconds": ttl_seconds,
        }
        denied = self._validate_request(
            tool="search",
            authorization=authorization,
            principal=principal,
            request=request,
        )
        if denied:
            return denied
        try:
            safe_query = validate_query_text(query)
        except UnsafeBrainInput as exc:
            return self._deny(principal, "search", "unsafe_input", {"detail": str(exc)})
        clean_limit = max(1, min(int(limit), 25))
        clean_ttl = max(30, min(int(ttl_seconds), REMOTE_READ_MAX_TTL_SECONDS))
        query_hash = self._hash(safe_query)
        expires_at = self.now() + clean_ttl
        try:
            recall = self.client.recall(safe_query, limit=clean_limit, include_unconfirmed=False)
        except BrainUnavailable as exc:
            return self._deny(principal, "search", "brain_unavailable", {"detail": "redacted"}, state="degraded")

        results: list[dict[str, Any]] = []
        for memory in recall.get("memories", []):
            if not isinstance(memory, dict):
                continue
            memory_id = str(memory.get("id") or "")
            if not memory_id:
                self._record_audit(principal, "search", "memory_missing_id", "denied")
                continue
            authority_label = self._authority_label(memory)
            memory_hash = str(memory.get("content_hash") or self._hash(str(memory.get("content") or "")))
            result_id = "brr_" + secrets.token_urlsafe(24)
            self.ledger[result_id] = ResultLedgerEntry(
                result_id=result_id,
                subject_hash=self._hash(principal.subject),
                session_hash=self._hash(principal.session_id),
                query_hash=query_hash,
                memory_id=memory_id,
                memory_hash=memory_hash,
                authority_label=authority_label,
                expires_at_epoch=expires_at,
            )
            results.append(
                {
                    "result_id": result_id,
                    "memory_type": str(memory.get("memory_type") or "memory"),
                    "authority_label": authority_label,
                    "expires_at_epoch": expires_at,
                }
            )
        self._record_audit(
            principal,
            "search",
            "remote_search_allowed",
            "complete",
            result_count=len(results),
            payload={"query_hash": query_hash},
        )
        return {
            "ok": True,
            "schema_version": "kswitch.ai_brain.remote_search.v1",
            "results": results,
            "policy": {
                "read_only": True,
                "opaque_ids_only": True,
                "fetch_requires_same_subject_session": True,
                "ttl_seconds": clean_ttl,
            },
        }

    def fetch(
        self,
        *,
        result_id: str,
        authorization: str,
        subject: str,
        session_id: str,
        schema_version: str,
        audience: str = REMOTE_READ_AUDIENCE,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        principal = RemotePrincipal(
            subject=str(subject or "").strip(),
            session_id=str(session_id or "").strip(),
            audience=str(audience or "").strip(),
            scopes=tuple(scopes or ()),
        )
        request = {
            "tool": "fetch",
            "schema_version": schema_version,
            "result_id": result_id,
            "authorization": authorization,
            "subject": subject,
            "session_id": session_id,
            "audience": audience,
            "scopes": scopes or [],
        }
        denied = self._validate_request(
            tool="fetch",
            authorization=authorization,
            principal=principal,
            request=request,
        )
        if denied:
            return denied
        clean_id = str(result_id or "").strip()
        if not clean_id.startswith("brr_"):
            return self._deny(principal, "fetch", "invalid_result_id", {"result_id_prefix": clean_id[:4]})
        entry = self.ledger.get(clean_id)
        if not entry:
            return self._deny(principal, "fetch", "result_not_found", {"result_id_prefix": clean_id[:4]})
        if entry.expires_at_epoch <= self.now():
            self.ledger.pop(clean_id, None)
            return self._deny(principal, "fetch", "result_expired", {"result_id_prefix": clean_id[:4]})
        if entry.subject_hash != self._hash(principal.subject) or entry.session_hash != self._hash(principal.session_id):
            return self._deny(
                principal,
                "fetch",
                "ledger_subject_session_mismatch",
                {"result_id_prefix": clean_id[:4]},
            )
        try:
            fetched = self.client.fetch_memory(entry.memory_id)
        except BrainUnavailable as exc:
            return self._deny(principal, "fetch", "brain_unavailable", {"detail": "redacted"}, state="degraded")
        if not fetched.get("ok"):
            return self._deny(
                principal,
                "fetch",
                str(fetched.get("reason") or "memory_fetch_denied"),
                {"result_id_prefix": clean_id[:4]},
            )
        memory = fetched.get("memory") if isinstance(fetched.get("memory"), dict) else {}
        content = str(memory.get("content") or memory.get("summary") or "")
        current_hash = str(memory.get("content_hash") or self._hash(content))
        if current_hash != entry.memory_hash:
            return self._deny(
                principal,
                "fetch",
                "result_memory_changed",
                {"result_id_prefix": clean_id[:4]},
            )
        try:
            safe_content = validate_query_text(content, field="content", max_chars=4000)
        except UnsafeBrainInput as exc:
            return self._deny(
                principal,
                "fetch",
                "response_redaction_block",
                {"detail": str(exc), "result_id_prefix": clean_id[:4]},
            )
        self._record_audit(
            principal,
            "fetch",
            "remote_fetch_allowed",
            "complete",
            result_count=1,
            payload={"result_id_prefix": clean_id[:4]},
        )
        return {
            "ok": True,
            "schema_version": "kswitch.ai_brain.remote_fetch.v1",
            "result_id": clean_id,
            "memory": {
                "memory_type": str(memory.get("memory_type") or "memory"),
                "content": safe_content,
                "review_status": str(memory.get("review_status") or ""),
                "authority_label": entry.authority_label,
                "source_refs_redacted": bool(memory.get("source_refs")),
            },
            "policy": {
                "read_only": True,
                "ledger_enforced": True,
                "raw_memory_id_redacted": True,
                "source_refs_redacted": True,
                "quarantine_rechecked": True,
            },
        }

    def _validate_request(
        self,
        *,
        tool: str,
        authorization: str,
        principal: RemotePrincipal,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        if tool not in REMOTE_READ_ALLOWED_TOOLS:
            return self._deny(principal, tool, "tool_not_allowed", {"tool": tool})
        if self._payload_size(request) > REMOTE_READ_MAX_PAYLOAD_BYTES:
            return self._deny(principal, tool, "payload_too_large", {"payload_size": self._payload_size(request)})
        expected_schema = REMOTE_SEARCH_SCHEMA if tool == "search" else REMOTE_FETCH_SCHEMA
        if request.get("schema_version") != expected_schema:
            return self._deny(
                principal,
                tool,
                "schema_version_denied",
                {"schema_version": str(request.get("schema_version") or "")},
            )
        if not principal.subject or not principal.session_id:
            return self._deny(
                principal,
                tool,
                "subject_session_required",
                {"subject_present": bool(principal.subject), "session_present": bool(principal.session_id)},
            )
        auth = str(authorization or "").strip()
        if not auth:
            return self._deny(principal, tool, "auth_missing", {})
        if not auth.lower().startswith("bearer "):
            return self._deny(principal, tool, "auth_scheme_invalid", {})
        if auth.split(" ", 1)[1] != self._remote_read_token():
            return self._deny(principal, tool, "auth_failed", {})
        if self._remote_read_token() == REMOTE_READ_DEV_TOKEN and not self.localhost_dev_mode:
            return self._deny(principal, tool, "default_dev_token_disabled", {})
        if principal.audience != REMOTE_READ_AUDIENCE:
            return self._deny(principal, tool, "audience_denied", {"audience": principal.audience})
        required_scope = REMOTE_READ_SCOPE_SEARCH if tool == "search" else REMOTE_READ_SCOPE_FETCH
        if required_scope not in set(principal.scopes):
            return self._deny(principal, tool, "scope_denied", {"scopes": list(principal.scopes)})
        return None

    def _remote_read_token(self) -> str:
        if self.token_provider:
            return self.token_provider()
        return os.environ.get("KSWITCH_BRAIN_REMOTE_READ_TOKEN", REMOTE_READ_DEV_TOKEN)

    def _deny(
        self,
        principal: RemotePrincipal,
        tool: str,
        reason: str,
        payload: dict[str, Any],
        *,
        state: str = "denied",
    ) -> dict[str, Any]:
        self._record_audit(principal, tool, reason, state, payload=payload)
        return {
            "ok": False,
            "tool": tool,
            "reason": reason,
            "state": state,
        }

    def _record_audit(
        self,
        principal: RemotePrincipal,
        tool: str,
        reason_class: str,
        state: str,
        *,
        result_count: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.audit_events.append(
            {
                "schema_version": "kswitch.ai_brain.remote_read_audit.v1",
                "subject_hash": self._hash(principal.subject),
                "session_hash": self._hash(principal.session_id),
                "tool": tool,
                "reason_class": reason_class,
                "state": state,
                "result_count": max(0, int(result_count)),
                "redacted_payload": self._redact(payload or {}),
                "created_at_epoch": self.now(),
            }
        )

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                if key in {"authorization", "token", "content", "memory", "memories", "source_refs", "result_id"}:
                    redacted[key] = "[redacted]"
                else:
                    redacted[key] = self._redact(item)
            return redacted
        if isinstance(value, list):
            return [self._redact(item) for item in value[:20]]
        if isinstance(value, str):
            try:
                validate_query_text(value, field="audit_value", max_chars=120)
            except UnsafeBrainInput:
                return "[redacted]"
            return value if len(value) <= 120 else "[redacted]"
        return value

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _payload_size(payload: dict[str, Any]) -> int:
        return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def _authority_label(memory: dict[str, Any]) -> str:
        if memory.get("review_status") == "confirmed" and memory.get("can_use_as_instruction"):
            return "confirmed_instruction"
        if memory.get("review_status") == "confirmed":
            return "confirmed_context"
        return "context_only"
