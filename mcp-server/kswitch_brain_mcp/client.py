"""Direct client for the local KSwitch AI Brain sidecar."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BRAIN_URL = "http://127.0.0.1:8765"
DEFAULT_ACCESS_KEY = "dev-local-memory-key"
DEFAULT_WORKSPACE = "kswitch-dev"
DEFAULT_PROJECT = "kswitch"
SUPPORTED_MEMORY_TYPES = {
    "decision": "decisions",
    "output": "outputs",
    "lesson": "lessons",
    "constraint": "constraints",
    "open_question": "unresolved_questions",
    "failure": "failures",
    "work_log": "next_steps",
}


class BrainUnavailable(RuntimeError):
    """Raised when the local Brain sidecar cannot serve a request."""


class UnsafeBrainInput(ValueError):
    """Raised when a tool input should not be sent to the Brain sidecar."""


def _unsafe_reasons(text: str) -> list[str]:
    reasons: list[str] = []
    lowered = text.lower()
    try:
        from tools.dev_memory.server import unsafe_reasons

        reasons.extend(unsafe_reasons(text))
    except Exception:  # pragma: no cover - package fallback outside repo checkout
        if "-----begin private key-----" in lowered:
            reasons.append("private_key")
        if "sk-" in text:
            reasons.append("api_key")
    if "authorization:" in lowered or "bearer " in lowered:
        reasons.append("auth_header")
    if ".env" in lowered:
        reasons.append("env_file")
    return sorted(set(reasons))


def validate_query_text(text: str, *, field: str = "query", max_chars: int = 2000) -> str:
    value = (text or "").strip()
    if not value:
        raise UnsafeBrainInput(f"{field}_empty")
    if len(value) > max_chars:
        raise UnsafeBrainInput(f"{field}_too_large")
    reasons = _unsafe_reasons(value)
    if reasons:
        raise UnsafeBrainInput("unsafe_" + ",".join(sorted(reasons)))
    transcript_markers = (
        "user:",
        "assistant:",
        "system:",
        "<conversation",
        "BEGIN TRANSCRIPT",
        "END TRANSCRIPT",
    )
    if sum(1 for marker in transcript_markers if marker.lower() in value.lower()) >= 2:
        raise UnsafeBrainInput("raw_transcript_shape")
    return value


def validate_source_refs(source_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(source_refs, list) or not source_refs:
        raise UnsafeBrainInput("source_refs_required")
    cleaned: list[dict[str, Any]] = []
    for index, source_ref in enumerate(source_refs):
        if not isinstance(source_ref, dict):
            raise UnsafeBrainInput(f"source_refs_{index}_invalid")
        uri = validate_query_text(str(source_ref.get("uri") or ""), field="source_ref_uri", max_chars=1000)
        cleaned.append(
            {
                "kind": str(source_ref.get("kind") or "repo"),
                "uri": uri,
                "title": str(source_ref.get("title") or uri),
            }
        )
    return cleaned


class BrainClient:
    """Small synchronous HTTP client used by local stdio MCP tools."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        access_key: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.base_url = (base_url or os.environ.get("KSWITCH_DEV_MEMORY_URL") or DEFAULT_BRAIN_URL).rstrip("/")
        self.access_key = access_key or os.environ.get("KSWITCH_DEV_MEMORY_ACCESS_KEY") or DEFAULT_ACCESS_KEY
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        data = None
        headers = {"x-brain-key": self.access_key}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers=headers,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout or self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise BrainUnavailable(f"{method} {path} failed: HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise BrainUnavailable(
                f"Cannot reach dev memory at {self.base_url}. Start it with ./scripts/dev_memory_up.sh"
            ) from exc
        except json.JSONDecodeError as exc:
            raise BrainUnavailable(f"invalid JSON from dev memory: {exc}") from exc

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health/live")

    def time_context(
        self,
        *,
        task: str = "",
        timezone: str = "Europe/London",
        max_age_seconds: int = 1800,
    ) -> dict[str, Any]:
        params = {
            "timezone": timezone,
            "max_age_seconds": str(max_age_seconds),
        }
        if task:
            params["task"] = task
        return self.request("GET", "/api/v1/time/context?" + urllib.parse.urlencode(params))

    def recall(
        self,
        query: str,
        *,
        limit: int = 8,
        include_unconfirmed: bool = False,
        workspace: str = DEFAULT_WORKSPACE,
        project: str = DEFAULT_PROJECT,
    ) -> dict[str, Any]:
        payload = {
            "schema_version": "kswitch.dev_memory.recall.v1",
            "workspace_id": workspace,
            "project_id": project,
            "task_id": None,
            "query": query,
            "scope": {
                "project_only": bool(project),
                "include_unconfirmed": include_unconfirmed,
                "include_stale": False,
            },
            "limits": {"max_items": max(1, min(int(limit), 25))},
        }
        return self.request("POST", "/api/v1/memory/recall", payload)

    def fetch_memory(
        self,
        memory_id: str,
        *,
        workspace: str = DEFAULT_WORKSPACE,
        project: str = DEFAULT_PROJECT,
    ) -> dict[str, Any]:
        payload = {
            "workspace_id": workspace,
            "project_id": project,
            "memory_id": memory_id,
        }
        return self.request("POST", "/api/v1/memory/fetch", payload)

    def graph_context(
        self,
        *,
        query: str = "",
        bundle: str = "agent-onboarding",
        limit: int = 8,
        memory_id: str = "",
        worker_role: str = "",
        workspace: str = DEFAULT_WORKSPACE,
        project: str = DEFAULT_PROJECT,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "workspace_id": workspace,
            "project_id": project,
            "bundle": bundle,
            "limit": max(1, min(int(limit), 25)),
        }
        if query:
            payload["query"] = query
        if memory_id:
            payload["memory_id"] = memory_id
        if worker_role:
            payload["worker_role"] = worker_role
        return self.request("POST", "/api/v1/graph/context-pack", payload)

    def writeback(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.request("POST", "/api/v1/memory/writeback", payload)

    def review_queue(
        self,
        *,
        limit: int = 10,
        include_evidence_only: bool = False,
        workspace: str = DEFAULT_WORKSPACE,
        project: str = DEFAULT_PROJECT,
    ) -> dict[str, Any]:
        params = {
            "workspace_id": workspace,
            "project_id": project,
            "limit": str(max(1, min(int(limit), 50))),
            "include_evidence_only": "true" if include_evidence_only else "false",
        }
        return self.request("GET", "/api/v1/memory/review-queue?" + urllib.parse.urlencode(params))

    def compile_context_pack(
        self,
        *,
        target: str = "agent-onboarding",
        query: str = "",
        task_id: str = "",
        limit: int = 8,
        workspace: str = DEFAULT_WORKSPACE,
        project: str = DEFAULT_PROJECT,
    ) -> dict[str, Any]:
        payload = {
            "workspace_id": workspace,
            "project_id": project,
            "target": target,
            "query": query,
            "task_id": task_id,
            "limit": max(1, min(int(limit), 25)),
        }
        return self.request("POST", "/api/v1/context-pack/compile", payload)
