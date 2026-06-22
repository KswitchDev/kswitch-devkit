"""Thin async HTTP client for KSwitch enforcement APIs.

NEVER raises from public methods — all exceptions are caught, a safe default is
returned, and a warning is emitted via the standard logging module.

Vendor docs assumed:
  - POST /api/v1/enforce/mcp-call  (class: vendor-documented, KSwitch control-plane API)
  - POST /api/v1/enforcement/mcp/inspect-response (class: vendor-documented, EP-069)
  - POST /api/v1/mcp/register  (class: vendor-documented, KSwitch registration API)
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from kswitch_mcp.tls_utils import resolve_tls_verify  # noqa: F401 — re-exported for proxy.py

log = logging.getLogger(__name__)


class KSwitchEnforcementClient:
    """Thin async HTTP client for KSwitch enforcement APIs.

    Designed to be instantiated once and shared across a proxy session.
    All public methods swallow exceptions and return safe defaults so that a
    degraded or unreachable KSwitch control plane NEVER stops AI tool traffic.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool | str = True,
    ) -> None:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            verify=resolve_tls_verify(verify_ssl),
            timeout=httpx.Timeout(10.0, connect=5.0),
        )

    # ── Public API ────────────────────────────────────────────────────────

    async def check_access(
        self,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        context: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        """Check whether an agent is allowed to invoke a tool on an MCP server.

        POST /api/v1/enforce/mcp-call

        Body::

            {
              "agent_id": agent_id,
              "mcp_server_id": mcp_server_id,
              "tool_name": tool_name,
              "context": context,
              "event_id": event_id   # optional — UUID4 for cross-layer deduplication
            }

        Returns the enforcement decision dict from KSwitch::

            {"allowed": bool, "reason": str, "obligations": list, "violations": list}

        On any error (network, HTTP ≥ 400, parse), returns the safe-allow default::

            {"allowed": True, "reason": "enforcement_unavailable", "obligations": [], "violations": []}

        and logs a warning. NEVER raises.

        Parameters
        ----------
        event_id:
            Optional UUID4 string.  When provided it is included in the
            POST body so the server can correlate this call with the
            corresponding local audit entry (EP-072 cross-layer dedup).
        """
        _safe = {
            "allowed": True,
            "reason": "enforcement_unavailable",
            "obligations": [],
            "violations": [],
        }
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "mcp_server_id": mcp_server_id,
            "tool_name": tool_name,
            "context": context or {},
        }
        if event_id is not None:
            payload["event_id"] = event_id
        try:
            r = await self._client.post("/api/v1/enforce/mcp-call", json=payload)
            if r.status_code >= 400:
                log.warning(
                    "KSwitch check_access returned HTTP %d for agent=%s tool=%s — failing open",
                    r.status_code,
                    agent_id,
                    tool_name,
                )
                return _safe
            data = r.json()
            return {
                "allowed": bool(data.get("allowed", True)),
                "reason": str(data.get("reason", "")),
                "obligations": list(data.get("obligations", [])),
                "violations": list(data.get("violations", [])),
            }
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "KSwitch check_access error for agent=%s tool=%s: %s — failing open",
                agent_id,
                tool_name,
                exc,
            )
            return _safe

    async def inspect_response(
        self,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        content: str,
    ) -> dict[str, Any]:
        """Inspect a tool response for injection or policy violations.

        POST /api/v1/enforcement/mcp/inspect-response

        Returns::

            {"allowed": bool, "reason": str, ...}

        On 404 (EP-069 not yet deployed):
            {"allowed": True, "reason": "inspection_not_available"}

        On any other error:
            {"allowed": True, "reason": "inspection_unavailable"}

        NEVER raises.
        """
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "mcp_server_id": mcp_server_id,
            "tool_name": tool_name,
            "content": content,
        }
        try:
            r = await self._client.post(
                "/api/v1/enforcement/mcp/inspect-response", json=payload
            )
            if r.status_code == 404:
                # EP-069 not deployed yet — allow through silently
                return {"allowed": True, "reason": "inspection_not_available"}
            if r.status_code >= 400:
                log.warning(
                    "KSwitch inspect_response returned HTTP %d for agent=%s tool=%s — failing open",
                    r.status_code,
                    agent_id,
                    tool_name,
                )
                return {"allowed": True, "reason": "inspection_unavailable"}
            return r.json()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "KSwitch inspect_response error for agent=%s tool=%s: %s — failing open",
                agent_id,
                tool_name,
                exc,
            )
            return {"allowed": True, "reason": "inspection_unavailable"}

    async def check_tool_descriptors(
        self,
        mcp_server_id: str,
        tool_specs: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Drift-check a batch of tool descriptors against the recorded baseline.

        BL-047 T9/T10. Called at proxy startup (and on refresh) — NOT per call.
        The descriptions in MCP tools flow only through ``list_tools()`` at
        connection time, so this hook fires once at startup, not on every
        invocation.  Tampering with tool descriptions BETWEEN baseline and
        startup is the threat the BL-047 control mitigates (TC-135 supply
        chain tool-description drift).

        POST /api/v1/mcp/<mcp_server_id>/tool-descriptors/check  (T10)

        Body::

            {"tools": [
              {"name": str, "description": str, "inputSchema": dict,
               "annotations": dict|null, "version": str|null,
               "client_hash": "<hex>"},
              ...
            ]}

        Returns the server's response dict on HTTP 200::

            {"checks": [
              {"tool_name": str, "version": str,
               "action": "block"|"alert"|"allow",
               "has_drift": bool,
               "current_hash": str,
               "baseline_hash": str|null,
               "baseline_status": str|null},
              ...
            ]}

        **Fail-closed contract.** Unlike ``check_access`` and
        ``inspect_response`` (which fail OPEN to keep AI tool traffic moving
        when the control plane is degraded), this endpoint **fails CLOSED**
        — on timeout, connection error, or HTTP >= 400 the method returns
        ``None`` and the proxy MUST refuse to register any of the upstream's
        tools.  Rationale (per BL-047 EP and bank-app-sec review): tool
        descriptors gate prompt-injection-via-description supply-chain
        attacks; serving an unverified tool surface defeats the control.

        Uses a tight 5-second timeout (not the 10-second default of the
        shared client) because this runs in the startup critical path —
        we'd rather move on without that upstream than block the whole
        proxy on a stuck connection.

        NEVER raises.
        """
        payload: dict[str, Any] = {"tools": tool_specs}
        try:
            r = await self._client.post(
                f"/api/v1/mcp/{mcp_server_id}/tool-descriptors/check",
                json=payload,
                timeout=httpx.Timeout(5.0, connect=5.0),
            )
            if r.status_code >= 500:
                log.warning(
                    "KSwitch check_tool_descriptors returned HTTP %d for "
                    "mcp_server_id=%s — failing CLOSED (no tools will be "
                    "registered from this upstream)",
                    r.status_code,
                    mcp_server_id,
                )
                return None
            if r.status_code >= 400:
                # 4xx is a contract violation (bad mcp_id, malformed payload,
                # auth failure).  Still fail-closed: we cannot prove the
                # descriptors are safe to serve.
                log.warning(
                    "KSwitch check_tool_descriptors returned HTTP %d for "
                    "mcp_server_id=%s — failing CLOSED",
                    r.status_code,
                    mcp_server_id,
                )
                return None
            return r.json()
        except httpx.TimeoutException as exc:
            log.warning(
                "KSwitch check_tool_descriptors timed out for "
                "mcp_server_id=%s: %s — failing CLOSED",
                mcp_server_id,
                exc,
            )
            return None
        except Exception as exc:  # noqa: BLE001 — fail-closed catch-all
            log.warning(
                "KSwitch check_tool_descriptors error for mcp_server_id=%s: "
                "%s — failing CLOSED",
                mcp_server_id,
                exc,
            )
            return None

    async def register_mcp(
        self,
        mcp_id: str,
        display_name: str,
        url: str = "",
    ) -> dict[str, Any]:
        """Register an upstream MCP server in the KSwitch control plane.

        POST /api/v1/mcp/register

        Body::

            {"display_name": display_name, "record_type": "MCP_SERVER", "risk_tier": "tier_3"}

        On 409 Conflict (already registered): treated as success, returns {}.
        On any other error: logs a warning and returns {}.
        NEVER raises.
        """
        payload: dict[str, Any] = {
            "display_name": display_name,
            "record_type": "MCP_SERVER",
            "risk_tier": "tier_3",
        }
        if url:
            payload["url"] = url
        try:
            r = await self._client.post("/api/v1/mcp/register", json=payload)
            if r.status_code == 409:
                # Already registered — not an error
                log.debug("KSwitch register_mcp: %s already registered (409)", mcp_id)
                return {}
            if r.status_code >= 400:
                log.warning(
                    "KSwitch register_mcp returned HTTP %d for mcp_id=%s",
                    r.status_code,
                    mcp_id,
                )
                return {}
            return r.json()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "KSwitch register_mcp error for mcp_id=%s: %s", mcp_id, exc
            )
            return {}

    async def aclose(self) -> None:
        """Close the underlying httpx.AsyncClient."""
        try:
            await self._client.aclose()
        except Exception as exc:  # noqa: BLE001
            log.warning("Error closing KSwitchEnforcementClient: %s", exc)
