"""B005.2 KSwitch governed service MCP server.

This W1 entrypoint exposes the agent-facing service surface while failing
closed until trusted identity, registry, policy, and audit context are wired by
later B005.2 workstreams.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP


SERVICE_NAME = "kswitch_service"
TOOL_NAMES = ("fetch", "search", "policy_check", "get_policy", "health")
CRITICAL_DEPENDENCIES = ("identity", "policy", "registry", "audit")
DOWNSTREAM_DEPENDENCIES = ("fetch_broker", "search_adapter")
SUPPORTED_SERVICE_CLASSES = ("broker.webfetch", "provider.feature.search")
HARD_DENY_CLASSES = (
    "non_https_url",
    "ip_literal",
    "private_or_local_target",
    "credential_like_url_material",
    "audit_unavailable",
    "identity_context_unavailable",
)
CALLER_SUPPLIED_AUTHORITY = frozenset({
    "identity",
    "identity_status",
    "join_confidence",
    "agent_wlid",
    "agent_session_id",
    "tenant_id",
    "customer_id",
    "device_id",
    "user",
})

_runtime_context: Any | None = None
_runtime_audit_sink: Callable[[dict[str, Any]], dict[str, Any]] | None = None
_runtime_fetch_dispatcher: Callable[[str, int], dict[str, Any]] | None = None
_runtime_fetch_resolver: Callable[[str], list[str]] | None = None
_runtime_search_adapter: Callable[[dict[str, Any]], dict[str, Any]] | None = None
_runtime_search_classifier: Callable[[dict[str, Any]], dict[str, Any]] | None = None
_runtime_policy_check_rate_limiter: Callable[[dict[str, Any]], dict[str, Any]] | None = None


mcp = FastMCP(
    SERVICE_NAME,
    instructions=(
        "KSwitch B005.2 governed service interface for agent fetch, search, "
        "policy_check, get_policy, and health. In W1 this server is "
        "discoverable and fail-closed until trusted context and brokers are "
        "available."
    ),
)


@mcp.tool()
async def fetch(
    url: str,
    purpose: str,
    task_id: str,
    max_bytes: int = 1048576,
    source_search_decision_id: str = "",
    source_result_id: str = "",
    source_url_hash: str = "",
) -> dict[str, Any]:
    """Fetch public HTTPS content through KSwitch governance."""
    missing = _missing_required({"url": url, "purpose": purpose, "task_id": task_id})
    if missing:
        return _fail_closed("fetch", f"missing_{missing}", f"{missing} is required")
    if _runtime_context is not None and _runtime_audit_sink is not None:
        core = _core()
        if core:
            return core["fetch_tool"](
                {
                    "url": url,
                    "purpose": purpose,
                    "task_id": task_id,
                    "max_bytes": max_bytes,
                    "source_search_decision_id": source_search_decision_id,
                    "source_result_id": source_result_id,
                    "source_url_hash": source_url_hash,
                },
                _runtime_context,
                audit_sink=_runtime_audit_sink,
                dispatcher=_runtime_fetch_dispatcher,
                resolver=_runtime_fetch_resolver,
            )
    return _fail_closed(
        "fetch",
        "identity_context_unavailable",
        "Trusted B005 identity/context binding is not available in W1.",
        target_hash=_hash({"url": _redacted_url_shape(url)}),
        max_bytes=max(1, min(int(max_bytes), 1048576)),
    )


@mcp.tool()
async def search(
    query: str,
    purpose: str,
    task_id: str,
    provider_id: str = "customer_search_default",
    max_results: int = 10,
) -> dict[str, Any]:
    """Search through a governed provider adapter when B005.3 is installed."""
    missing = _missing_required({"query": query, "purpose": purpose, "task_id": task_id})
    if missing:
        return _fail_closed("search", f"missing_{missing}", f"{missing} is required")
    if _runtime_context is not None and _runtime_audit_sink is not None:
        core = _core()
        if core:
            return core["search_tool"](
                {
                    "query": query,
                    "purpose": purpose,
                    "task_id": task_id,
                    "provider_id": provider_id,
                    "max_results": max_results,
                },
                _runtime_context,
                audit_sink=_runtime_audit_sink,
                adapter=_runtime_search_adapter,
                classifier=_runtime_search_classifier,
            )
    return _fail_closed(
        "search",
        "search_adapter_unavailable",
        "B005.3 search adapter is not installed or healthy.",
        query_hash=_hash({"query": query}),
        provider_id=provider_id or "customer_search_default",
        max_results=max(1, min(int(max_results), 10)),
    )


@mcp.tool()
async def policy_check(
    action: str,
    target: dict[str, Any],
    purpose: str,
    task_id: str,
    service_class: str = "provider.model.call",
) -> dict[str, Any]:
    """Return a redacted fail-closed policy-check envelope."""
    missing = _missing_required({"action": action, "purpose": purpose, "task_id": task_id})
    if missing:
        return _fail_closed("policy_check", f"missing_{missing}", f"{missing} is required")
    if _runtime_context is not None and _runtime_audit_sink is not None:
        core = _core()
        if core:
            return core["policy_check_tool"](
                {
                    "tool": action,
                    "target": target,
                    "purpose": purpose,
                    "task_id": task_id,
                    "service_class": service_class,
                },
                _runtime_context,
                audit_sink=_runtime_audit_sink,
                rate_limiter=_runtime_policy_check_rate_limiter,
            )
    return _fail_closed(
        "policy_check",
        "identity_context_unavailable",
        "Trusted B005 identity/context binding is not available in W1.",
        action=action,
        service_class=service_class,
        target_hash=_hash({"target": target}),
    )


@mcp.tool()
async def get_policy() -> dict[str, Any]:
    """Return a redacted B005.2 W1 policy view."""
    if _runtime_context is not None:
        core = _core()
        if core:
            return core["get_policy"](_runtime_context)
    return {
        "ok": True,
        "degraded": True,
        "service": SERVICE_NAME,
        "policy_view": "redacted_w1",
        "hard_denies": list(HARD_DENY_CLASSES),
        "supported_service_classes": list(SUPPORTED_SERVICE_CLASSES),
        "notes": [
            "No customer registry entries or destination lists are exposed.",
            "Trusted context binding is required before tool dispatch.",
        ],
    }


@mcp.tool()
async def health() -> dict[str, Any]:
    """Return B005.2 service health and fail-closed dependency posture."""
    if _runtime_context is not None:
        core = _core()
        if core:
            return core["health"](
                audit_available=_runtime_audit_sink is not None,
                registry_available=True,
                policy_available=True,
                identity_available=True,
                search_adapter_available=_runtime_search_adapter is not None,
            )
    dependencies = {
        **{name: "unavailable" for name in CRITICAL_DEPENDENCIES},
        **{name: "unavailable" for name in DOWNSTREAM_DEPENDENCIES},
    }
    return {
        "ok": False,
        "fail_closed": True,
        "service": SERVICE_NAME,
        "status": "fail_closed",
        "dependencies": dependencies,
        "tools": [{"name": name, "status": _tool_status(name)} for name in TOOL_NAMES],
    }


def configure_runtime(
    *,
    context: Any | None = None,
    audit_sink: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    fetch_dispatcher: Callable[[str, int], dict[str, Any]] | None = None,
    fetch_resolver: Callable[[str], list[str]] | None = None,
    search_adapter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    search_classifier: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    policy_check_rate_limiter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> None:
    """Inject trusted runtime dependencies for embedded tests or gateway hosts.

    Standalone stdio launch remains fail-closed because these dependencies are
    not configured by default.
    """
    global _runtime_context
    global _runtime_audit_sink
    global _runtime_fetch_dispatcher
    global _runtime_fetch_resolver
    global _runtime_search_adapter
    global _runtime_search_classifier
    global _runtime_policy_check_rate_limiter
    _runtime_context = context
    _runtime_audit_sink = audit_sink
    _runtime_fetch_dispatcher = fetch_dispatcher
    _runtime_fetch_resolver = fetch_resolver
    _runtime_search_adapter = search_adapter
    _runtime_search_classifier = search_classifier
    _runtime_policy_check_rate_limiter = policy_check_rate_limiter


def clear_runtime() -> None:
    configure_runtime()


def _core() -> dict[str, Any] | None:
    try:
        from app.b005_kswitch_service import fetch_tool, get_policy, health, policy_check_tool, search_tool
    except Exception:
        return None
    return {
        "fetch_tool": fetch_tool,
        "get_policy": get_policy,
        "health": health,
        "policy_check_tool": policy_check_tool,
        "search_tool": search_tool,
    }


def _tool_status(name: str) -> str:
    if name == "search":
        return "available_when_registered_adapter_configured"
    if name in {"fetch", "policy_check"}:
        return "fail_closed_until_trusted_context"
    return "available"


def _fail_closed(tool: str, reason: str, message: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "ok": False,
        "allowed": False,
        "fail_closed": True,
        "tool": tool,
        "reason": reason,
        "message": message,
        "dispatch_attempted": False,
    }
    payload.update(extra)
    return payload


def _missing_required(values: dict[str, Any]) -> str:
    for key, value in values.items():
        if not isinstance(value, str) or not value.strip():
            return key
    supplied = sorted(CALLER_SUPPLIED_AUTHORITY.intersection(values))
    if supplied:
        return supplied[0]
    return ""


def _redacted_url_shape(raw_url: str) -> dict[str, Any]:
    scheme = ""
    host_present = False
    path_present = False
    query_present = False
    try:
        from urllib.parse import urlparse

        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        host_present = bool(parsed.hostname)
        path_present = bool(parsed.path and parsed.path != "/")
        query_present = bool(parsed.query)
    except Exception:
        pass
    return {
        "scheme": scheme,
        "host_present": host_present,
        "path_present": path_present,
        "query_present": query_present,
    }


def _hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the B005.2 KSwitch service MCP server")
    parser.add_argument("--transport", choices=["stdio"], default="stdio")
    return parser


def main() -> int:
    build_parser().parse_args()
    mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
