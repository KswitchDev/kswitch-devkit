"""KSwitch Governing Proxy — kswitch-proxy entry point.

Sits between AI coding tools (Cursor, Claude Code) and real upstream MCP
servers.  Every tool call passes through three enforcement layers before being
forwarded, and every response is inspected for prompt injection:

Layer architecture (EP-072)::

    AI Tool (Cursor / Claude Code)
          │  MCP protocol (stdio)
          ▼
      kswitch-proxy  ← this file
          │  ├── L2a: local floor rules      (local_rules.py)
          │  ├── L1:  PIJ request inspection (local_inspection.py)
          │  ├── L2b: bundle rules           (policy_cache.py)
          │  ├── Remote: control-plane       (enforcement_client.py)
          │  ├── Upstream call
          │  ├── Remote: response inspection (enforcement_client.py)
          │  └── L1:  PIJ response backup   (local_inspection.py)
          │  MCP protocol (stdio / SSE)
          ▼
      Real upstream MCPs (postgres-mcp, filesystem-mcp, etc.)

Configuration (environment variables)::

    KSWITCH_PROXY_UPSTREAMS       JSON list of upstream configs.
                                  stdio example:
                                    [{"id": "postgres-mcp",
                                      "command": "npx",
                                      "args": ["-y", "@mcp/postgres", "pg://db"]}]
                                  SSE/HTTP example:
                                    [{"id": "files-mcp",
                                      "url": "http://localhost:8080/mcp"}]
    KSWITCH_URL                   KSwitch base URL (default https://localhost:5001)
    KSWITCH_TOKEN                 Bearer token for KSwitch API
    KSWITCH_PROXY_AGENT_ID        Agent ID used in enforcement (default
                                  "kswitch-proxy-session")
    KSWITCH_VERIFY_SSL            "true" / "false" (default "true")
    KSWITCH_LOCAL_INSPECTION_MODE "enforce" | "shadow" | "disabled"
                                  (default "enforce")
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.server.fastmcp import FastMCP

from kswitch_mcp import local_rules
from kswitch_mcp.enforcement_client import KSwitchEnforcementClient, resolve_tls_verify
from kswitch_mcp.local_audit import LocalAuditEntry, append_entry
from kswitch_mcp.local_inspection import inspect_content
from kswitch_mcp.policy_cache import PolicyCache, ReachabilityCache

# BL-047 T9 — proxy-side tool-descriptor hash compute. ``MCP_TOOL_FIELD_ORDER``
# is imported alongside the hasher per the BL-047 plan §2 T9 row even though
# the hasher uses sort_keys internally — the constant is documentation of the
# normative field set and gives operators a single grep target when auditing
# canonical-form drift.  Vendor module lives in the main repo
# (``app/mcp_descriptor_canonical.py``) and is the same module the T10
# control-plane endpoint uses to recompute the authoritative hash, so both
# sides of the wire share one source of truth for canonicalisation.
from kswitch_mcp.mcp_descriptor_canonical import (  # noqa: F401 - field order kept for docs
    MCP_TOOL_FIELD_ORDER,
    build_canonical_tool_spec,
    compute_descriptor_hash,
)

log = logging.getLogger(__name__)


# ── Content extraction helper ─────────────────────────────────────────────


def _extract_content_str(result: Any) -> str:
    """Flatten a CallToolResult's content list to a plain string.

    - Empty content list → ``""``
    - Single TextContent item → ``item.text`` (no extra newline)
    - Multiple items → items joined with ``"\\n"``
    - Non-TextContent items → ``str(item)``
    """
    content = getattr(result, "content", None)
    if not content:
        return ""
    parts: list[str] = []
    for item in content:
        if type(item).__name__ == "TextContent":
            parts.append(item.text)
        else:
            parts.append(str(item))
    return "\n".join(parts)


# ── Closure-safe tool-wrapper factory ────────────────────────────────────


def _make_tool_wrapper(
    upstream_id: str,
    tool_name: str,
    session: ClientSession,
    enf_client: KSwitchEnforcementClient,
    *,
    policy_cache: PolicyCache | None = None,
    base_url: str = "",
    token: str = "",
    verify_ssl: bool | str = True,
) -> Any:
    """Return an async callable that enforces + forwards a single upstream tool.

    Enforcement layers applied on every invocation (EP-072 §5.2):

    Step 0   Tick the reachability cache (determines online/offline mode for
             local audit write decisions).
    Step 1   L2a floor rules — local_rules.check() — BLOCK immediately on fail.
    Step 2   L1 PIJ inspection on request arguments — mode from env var.
    Step 3   L2b bundle rules — policy_cache.check() — BLOCK if loaded.
    Step 4   Remote enforcement check — enf_client.check_access() — fails open.
    Step 5   Upstream tool call.
    Step 6   Remote response inspection — enf_client.inspect_response() — fails
             open on 404 (EP-069 not yet deployed).
    Step 7   L1 PIJ inspection on response (backup; primary when offline).

    A factory function (not a lambda) guarantees each returned callable closes
    over its own ``upstream_id``, ``tool_name``, ``session``, ``enf_client``,
    and ``policy_cache``, avoiding the classic loop-variable capture bug.

    Parameters
    ----------
    upstream_id:
        ID of the upstream MCP server (e.g. ``"postgres-mcp"``).
    tool_name:
        Name of the tool being wrapped (e.g. ``"query_db"``).
    session:
        Active MCP ClientSession for the upstream.
    enf_client:
        KSwitchEnforcementClient instance (fails open on all errors).
    policy_cache:
        Optional PolicyCache carrying the L2b signed bundle.  When ``None``
        the L2b layer is skipped (no bundle available yet).
    base_url:
        KSwitch base URL — used for the reachability tick and audit.
        When empty the reachability check is skipped (offline assumed).
    token:
        Bearer token for reachability HEAD probe.
    verify_ssl:
        Whether to verify TLS certificates on the reachability probe.
    """

    async def tool_fn(**kwargs: Any) -> str:
        event_id: str = str(uuid.uuid4())
        ts: str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        agent_id: str = os.environ.get(
            "KSWITCH_PROXY_AGENT_ID", "kswitch-proxy-session"
        )
        insp_mode: str = os.environ.get("KSWITCH_LOCAL_INSPECTION_MODE", "enforce")

        # ── Step 0 — reachability tick ──────────────────────────────────
        is_online: bool = False
        if base_url:
            rc = ReachabilityCache.instance()
            is_online = await rc.tick(base_url, token, verify_ssl)

        # ── Step 1 — L2a floor rules ────────────────────────────────────
        l2a = local_rules.check(upstream_id, tool_name)
        if not l2a.allowed:
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="blocked",
                    layer="L2a",
                    reason=l2a.reason,
                )
            )
            log.warning(
                "KSwitch L2a (%s) blocked %s/%s for agent=%s: %s",
                l2a.rule_id,
                upstream_id,
                tool_name,
                agent_id,
                l2a.reason,
            )
            return (
                f"[KSwitch] Blocked by local floor rule ({l2a.rule_id}): {l2a.reason}"
            )

        # ── Step 2 — L1 PIJ inspection on request arguments ─────────────
        try:
            args_str = json.dumps(kwargs, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            args_str = str(kwargs)

        req_insp = inspect_content(args_str, mode=insp_mode)
        if not req_insp.allowed:
            ids = [m["id"] for m in req_insp.matched_signatures]
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="blocked",
                    layer="L1_request",
                    reason=f"PIJ detected in request: {ids}",
                )
            )
            log.warning(
                "KSwitch L1 PIJ blocked %s/%s request for agent=%s: %s",
                upstream_id,
                tool_name,
                agent_id,
                ids,
            )
            return "[KSwitch] Request blocked (injection detected in tool arguments)"

        # ── Step 3 — L2b bundle rules ────────────────────────────────────
        # policy_cache.check() evaluates only ``lu_rules`` from the signed
        # bundle.  ``tc_rules`` (toxic-combo rules) are NOT evaluated here —
        # they are reference-only in the bundle and require user/org context
        # that is only available server-side.  TC evaluation happens in Step 4
        # via the control plane (enf_client.check_access()).
        if policy_cache is not None:
            l2b = policy_cache.check(upstream_id, tool_name, agent_id)
            if not l2b.allowed:
                append_entry(
                    LocalAuditEntry(
                        event_id=event_id,
                        ts=ts,
                        agent_id=agent_id,
                        mcp_server_id=upstream_id,
                        tool_name=tool_name,
                        decision="blocked",
                        layer="L2b",
                        reason=l2b.reason,
                    )
                )
                log.warning(
                    "KSwitch L2b (%s) blocked %s/%s for agent=%s: %s",
                    l2b.rule_id,
                    upstream_id,
                    tool_name,
                    agent_id,
                    l2b.reason,
                )
                return (
                    f"[KSwitch] Blocked by governance bundle rule "
                    f"({l2b.rule_id}): {l2b.reason}"
                )

        # ── Step 4 — remote enforcement check ───────────────────────────
        # enf_client.check_access() NEVER raises — fails open on any error.
        decision = await enf_client.check_access(
            agent_id, upstream_id, tool_name, event_id=event_id
        )
        if not decision.get("allowed", True):
            reason = decision.get("reason", "policy_block")
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="blocked",
                    layer="remote",
                    reason=reason,
                )
            )
            log.warning(
                "KSwitch blocked %s/%s for agent=%s: %s",
                upstream_id,
                tool_name,
                agent_id,
                reason,
            )
            return f"[KSwitch] Blocked by governance policy: {reason}"

        # ── Step 5 — forward to upstream ────────────────────────────────
        try:
            result = await session.call_tool(tool_name, arguments=kwargs)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Upstream MCP call failed for %s/%s: %s", upstream_id, tool_name, exc
            )
            return f"[Error] Upstream MCP call failed: {exc}"

        content_str = _extract_content_str(result)

        # ── Step 6 — remote response inspection ─────────────────────────
        # 404 → EP-069 not deployed; handled in client (returns allowed=True).
        inspection = await enf_client.inspect_response(
            agent_id, upstream_id, tool_name, content_str
        )
        if not inspection.get("allowed", True):
            reason = inspection.get("reason", "policy")
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="blocked",
                    layer="L1_response",
                    reason=reason,
                )
            )
            log.warning(
                "KSwitch response inspection blocked %s/%s for agent=%s: %s",
                upstream_id,
                tool_name,
                agent_id,
                reason,
            )
            return f"[KSwitch] Response blocked (injection detected): {reason}"

        # If EP-069 returned sanitised content, trust it and return early.
        if inspection.get("sanitized"):
            return inspection.get("content", content_str)

        # ── Step 7 — L1 PIJ inspection on response (backup / offline ──────
        resp_insp = inspect_content(content_str, mode=insp_mode)
        if not resp_insp.allowed:
            ids = [m["id"] for m in resp_insp.matched_signatures]
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="blocked",
                    layer="L1_response",
                    reason=f"PIJ detected in response: {ids}",
                )
            )
            log.warning(
                "KSwitch L1 PIJ blocked %s/%s response for agent=%s: %s",
                upstream_id,
                tool_name,
                agent_id,
                ids,
            )
            return "[KSwitch] Response blocked (local injection detection)"

        # ── Offline audit — log allowed event when control plane unreachable ─
        if not is_online:
            append_entry(
                LocalAuditEntry(
                    event_id=event_id,
                    ts=ts,
                    agent_id=agent_id,
                    mcp_server_id=upstream_id,
                    tool_name=tool_name,
                    decision="allowed",
                    layer="remote",
                    reason="offline_passthrough",
                )
            )

        return content_str

    # Give the function a meaningful name for FastMCP introspection
    tool_fn.__name__ = f"{upstream_id}__{tool_name}"
    return tool_fn


# ── BL-047 T9 — Tool-descriptor drift check (STARTUP-ONLY hook) ──────────
#
# This is a STARTUP / REFRESH hook, NOT a per-call check.  MCP tool
# descriptions (``name``, ``description``, ``inputSchema``, ``annotations``,
# ``version``) flow over the wire exactly once per session — when the proxy
# issues ``ClientSession.initialize()`` + ``ClientSession.list_tools()``
# against the upstream.  After registration FastMCP serves those descriptions
# from its own table; per-call traffic carries only invocation arguments.
#
# Consequently the supply-chain threat we are mitigating (TC-135: an upstream
# changes a tool description to inject hidden instructions into the LLM's
# system prompt) is bound to the startup window.  The per-call L1 PIJ
# inspection at lines 197-225 inspects request ARGUMENTS, not the tool
# DESCRIPTION served to the LLM — those are different surfaces.  Adding a
# descriptor hash check on every call would (a) be redundant for the same
# descriptor and (b) impose a remote round-trip on the hot path.  So the
# hook fires once on startup, the control plane returns the tier-gated
# action ("block" / "alert" / "allow"), and registration is filtered
# accordingly.  Refresh-triggered re-checks (operator-driven) reuse the
# same code path.


def _build_tool_spec(tool: Any) -> dict[str, Any]:
    """Build the wire-format tool spec dict from an MCP ``Tool`` object.

    Defensive ``getattr`` for ``annotations`` and ``version`` because the
    MCP spec marks both as optional and older upstream servers omit them
    entirely (mcp==1.27.0 verified 2026-05-20 — Tool.annotations is
    ``AnnotationsOptional`` and ``version`` is not standardised, so
    ``getattr(tool, "version", None)`` is the safe access pattern).

    The ``client_hash`` is computed AFTER the dict is assembled, over the
    fields that count toward canonicalisation per
    ``kswitch_mcp.mcp_descriptor_canonical.MCP_TOOL_FIELD_ORDER``. Adding the hash
    LAST and to a fresh dict keeps the hash input free of its own field —
    matching the server-side handling at
    ``app/routes/mcp_tool_descriptors.py:207-210`` which pops ``client_hash``
    before recomputing.
    """
    annotations = getattr(tool, "annotations", None)
    # MCP SDK exposes annotations as a Pydantic model with .model_dump() in
    # mcp>=1.0; fall back to vars() / None for older or shimmed types.
    if annotations is not None and hasattr(annotations, "model_dump"):
        annotations = annotations.model_dump()
    elif annotations is not None and not isinstance(annotations, (dict, list, str, int, float, bool)):
        try:
            annotations = dict(vars(annotations))
        except Exception:  # noqa: BLE001
            annotations = None

    # Single source of truth — same builder the T8 baseline path uses, so
    # the proxy and the control plane produce identical 5-field dicts for
    # the same logical tool. BL-047 hash-parity fix (2026-05-20).
    spec = build_canonical_tool_spec(
        name=tool.name,
        description=tool.description,
        input_schema=getattr(tool, "inputSchema", None),
        annotations=annotations,
        version=getattr(tool, "version", None),
    )
    # Compute over the dict WITHOUT client_hash, then add it for transport.
    spec["client_hash"] = compute_descriptor_hash(spec)
    return spec


async def _drift_check_upstream(
    enf_client: KSwitchEnforcementClient,
    upstream_id: str,
    tools: list[Any],
) -> dict[str, str] | None:
    """Drift-check every tool in ``tools`` against the control plane.

    Returns a mapping ``{tool_name: action}`` where ``action`` is one of
    ``"allow"``, ``"alert"``, or ``"block"``.

    Returns ``None`` on ANY control-plane error (timeout, 5xx, 4xx,
    connection refusal).  The caller MUST interpret ``None`` as
    "register zero tools from this upstream" — bank-grade fail-closed
    per BL-047 EP §5 risk #3.
    """
    if not tools:
        return {}

    specs = [_build_tool_spec(t) for t in tools]
    response = await enf_client.check_tool_descriptors(upstream_id, specs)
    if response is None:
        return None

    checks = response.get("checks")
    if not isinstance(checks, list):
        log.warning(
            "KSwitch check_tool_descriptors for upstream %s returned malformed "
            "response (missing 'checks' list) — failing CLOSED",
            upstream_id,
        )
        return None

    actions: dict[str, str] = {}
    for entry in checks:
        if not isinstance(entry, dict):
            continue
        name = entry.get("tool_name")
        action = entry.get("action")
        if not isinstance(name, str) or action not in ("allow", "alert", "block"):
            log.warning(
                "KSwitch tool-descriptor check entry for upstream %s missing "
                "tool_name/action or has unknown action: %s — failing CLOSED",
                upstream_id,
                entry,
            )
            return None
        actions[name] = action
    return actions


# ── Lifespan — connect upstreams, register tools ─────────────────────────


@asynccontextmanager
async def _proxy_lifespan(server: FastMCP) -> AsyncIterator[None]:
    """FastMCP lifespan: connect to all configured upstream MCP servers.

    Upstream connection failures are logged and skipped — the proxy starts
    regardless of how many upstreams succeed, never raising from this context.

    On startup:
    - Loads the local policy bundle (EP-072 L2b/L3).
    - Connects each configured upstream and registers its tools.
    """
    base_url = os.environ.get("KSWITCH_URL", "https://localhost:5001")
    token = os.environ.get("KSWITCH_TOKEN", "")
    verify_ssl: bool | str = os.environ.get("KSWITCH_VERIFY_SSL", "true").lower() not in (
        "false",
        "0",
        "no",
    )
    verify_ssl = resolve_tls_verify(verify_ssl)

    enf_client = KSwitchEnforcementClient(
        base_url=base_url, token=token, verify_ssl=verify_ssl
    )

    # ── Load local policy bundle (EP-072 L2b/L3) ──────────────────────
    policy_cache = PolicyCache()
    load_result = policy_cache.load()
    log.info("EP-072 policy_cache.load() → %s", load_result.value)

    # Each entry is (context_manager, session) for cleanup in reverse order
    upstream_contexts: list[tuple[Any, ClientSession]] = []

    upstreams_cfg: list[dict[str, Any]] = []
    raw = os.environ.get("KSWITCH_PROXY_UPSTREAMS", "[]")
    try:
        upstreams_cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.error("KSWITCH_PROXY_UPSTREAMS is not valid JSON: %s", exc)

    # When there are multiple upstreams, always prefix tool names with the
    # upstream ID to avoid conflicts.  With a single upstream, use plain names
    # unless a duplicate is detected (which would be a bug in that upstream).
    need_prefix = len(upstreams_cfg) > 1
    tool_name_counts: dict[str, int] = defaultdict(int)

    for upstream_cfg in upstreams_cfg:
        upstream_id: str = upstream_cfg.get("id", "unknown")
        log.info("Connecting to upstream MCP: %s", upstream_id)
        try:
            if "command" in upstream_cfg:
                params = StdioServerParameters(
                    command=upstream_cfg["command"],
                    args=upstream_cfg.get("args", []),
                    env=upstream_cfg.get("env"),
                )
                ctx = stdio_client(params)
            elif "url" in upstream_cfg:
                ctx = sse_client(url=upstream_cfg["url"])
            else:
                log.error(
                    "Upstream %s has neither 'command' nor 'url' — skipping",
                    upstream_id,
                )
                continue

            read, write = await ctx.__aenter__()
            session = ClientSession(read, write)
            await session.__aenter__()
            await session.initialize()

            tools_result = await session.list_tools()
            tools = tools_result.tools if tools_result else []

            # ── BL-047 T9 — startup tool-descriptor drift check ──────────
            #
            # Fail-closed: if the control plane is unreachable, returns
            # a 5xx, returns a 4xx, or returns malformed JSON, we register
            # ZERO tools from this upstream.  The upstream may still be
            # connected (session is open) but every tool is unreachable
            # until the next refresh re-baselines.  This is the
            # bank-grade contract — better to lose tool availability
            # than to serve an unverified descriptor surface (TC-135).
            #
            # The ``client_hash`` field added to each spec is a wire-
            # tampering canary: the control plane recomputes the hash
            # server-side and logs a mismatch (see
            # ``app/routes/mcp_tool_descriptors.py:210-223``).  Server
            # hash is always authoritative; the canary just surfaces
            # in-transit corruption / proxy bugs.
            actions = await _drift_check_upstream(enf_client, upstream_id, tools)
            if actions is None:
                log.warning(
                    "Tool-descriptor drift check unavailable for upstream %s "
                    "— registering 0 tools (fail-closed per BL-047)",
                    upstream_id,
                )
                # Still record the upstream context so teardown works,
                # but skip all tool registration for this upstream.
                upstream_contexts.append((ctx, session))
                continue

            for tool in tools:
                bare_name: str = tool.name
                action = actions.get(bare_name)
                if action is None:
                    # Tool present locally but missing from control-plane
                    # response — fail closed for this tool only.
                    log.warning(
                        "Upstream %s tool %s missing from drift-check response "
                        "— not registering",
                        upstream_id,
                        bare_name,
                    )
                    continue
                if action == "block":
                    log.warning(
                        "Upstream %s tool %s blocked by tool-descriptor drift "
                        "policy — not registering (refresh to re-baseline)",
                        upstream_id,
                        bare_name,
                    )
                    continue
                if action == "alert":
                    log.warning(
                        "Upstream %s tool %s registered with drift ALERT — "
                        "governance event was emitted by control plane; "
                        "review required",
                        upstream_id,
                        bare_name,
                    )

                tool_name_counts[bare_name] += 1

                registered_name = (
                    f"{upstream_id}__{bare_name}" if need_prefix else bare_name
                )

                description = tool.description or f"Forwarded from {upstream_id}"

                wrapper = _make_tool_wrapper(
                    upstream_id,
                    bare_name,
                    session,
                    enf_client,
                    policy_cache=policy_cache,
                    base_url=base_url,
                    token=token,
                    verify_ssl=verify_ssl,
                )
                server.add_tool(
                    wrapper,
                    name=registered_name,
                    description=f"[{upstream_id}] {description}",
                )
                log.debug(
                    "Registered tool %s (from upstream %s, action=%s)",
                    registered_name,
                    upstream_id,
                    action,
                )

            # Register the upstream MCP server in KSwitch (best-effort)
            await enf_client.register_mcp(
                upstream_id,
                upstream_id,
                url=upstream_cfg.get("url", ""),
            )

            upstream_contexts.append((ctx, session))
            log.info(
                "Upstream %s connected — %d tools registered",
                upstream_id,
                len(tools),
            )

        except Exception as exc:  # noqa: BLE001
            log.error(
                "Failed to connect to upstream %s: %s — continuing without it",
                upstream_id,
                exc,
            )
            # Never crash the proxy; continue to next upstream

    # In single-upstream mode, warn about any duplicate tool names the upstream
    # itself returned (should not happen but catch it defensively).
    if not need_prefix:
        conflicts = [n for n, c in tool_name_counts.items() if c > 1]
        if conflicts:
            log.warning(
                "Tool name duplicates detected in single-upstream mode: %s",
                conflicts,
            )

    yield

    # ── Teardown (reverse order to respect dependency chains) ──
    for ctx, session in reversed(upstream_contexts):
        try:
            await session.__aexit__(None, None, None)
        except Exception as exc:  # noqa: BLE001
            log.warning("Error closing upstream session: %s", exc)
        try:
            await ctx.__aexit__(None, None, None)
        except Exception as exc:  # noqa: BLE001
            log.warning("Error closing upstream context: %s", exc)

    await enf_client.aclose()


# ── FastMCP proxy server (lifespan wired at construction) ─────────────────

mcp_proxy = FastMCP(
    "kswitch-proxy",
    instructions=(
        "KSwitch.ai Governing Proxy — all tool calls pass through local floor "
        "rules, PIJ inspection, and remote enforcement before being forwarded "
        "to upstream MCP servers. Blocked calls return a '[KSwitch] Blocked' "
        "message."
    ),
    lifespan=_proxy_lifespan,
)


# ── Entry point ───────────────────────────────────────────────────────────


def main() -> None:
    """Run the kswitch-proxy over stdio transport."""
    upstreams_raw = os.environ.get("KSWITCH_PROXY_UPSTREAMS", "[]")
    try:
        upstreams_list = json.loads(upstreams_raw)
    except json.JSONDecodeError:
        upstreams_list = []

    if not upstreams_list:
        print(
            "WARNING: KSWITCH_PROXY_UPSTREAMS not configured. "
            "Proxy will start with no upstream tools.",
            file=sys.stderr,
        )

    mcp_proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
