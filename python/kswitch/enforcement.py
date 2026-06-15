"""Enforcement API — MCP call enforcement for runtime authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .client import sanitize_path_param
from .models import EnforcementDecision, FleetAgent, FleetHealth, BlastRadius, Obligation

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class EnforcementAPI:
    """Synchronous enforcement and fleet operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- MCP Enforcement ------------------------------------------------

    def enforce_mcp_call(
        self,
        *,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        context: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> EnforcementDecision:
        """Enforce an MCP tool call (runtime authorization check).

        This is the endpoint MCP servers call before executing a tool
        invocation to verify the calling agent is authorized.

        .. deprecated:: PR-10
            Call ``enforce_mcp_call()`` directly only for low-level control.
            Prefer ``KSwitchInterceptor.check_and_invoke()`` which wraps this
            call with bypass prevention, pre-invoke obligation blocking,
            output filtering, and obligation reporting in a single safe path.
        """
        import warnings
        warnings.warn(
            "enforce_mcp_call() called directly — use KSwitchInterceptor.check_and_invoke() "
            "to ensure bypass prevention, output filtering, and obligation reporting. "
            "Direct calls bypass the full enforcement contract (PR-10).",
            DeprecationWarning,
            stacklevel=2,
        )
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "mcp_server_id": mcp_server_id,
            "tool_name": tool_name,
            **kwargs,
        }
        if context:
            payload["context"] = context
        return EnforcementDecision(**self._c._post("/api/v1/enforce/mcp-call", json=payload))

    def report_obligations(
        self,
        enforcement_id: str,
        obligations_met: list[str],
    ) -> dict[str, Any]:
        """Report fulfilled obligations for a prior ALLOW decision (PR-05).

        Args:
            enforcement_id: The ID returned in the enforcement decision.
            obligations_met: List of obligation type strings fulfilled.

        Returns:
            Server validation result with ``valid``, ``unknown_obligations``,
            ``missing_obligations``, and ``message`` fields.
        """
        return self._c._post(
            "/api/v1/enforce/obligation-report",
            json={"enforcement_id": enforcement_id, "obligations_met": obligations_met},
        )

    # -- Fleet ----------------------------------------------------------

    def list_fleet_agents(self, **params: Any) -> list[FleetAgent]:
        """List fleet agents."""
        resp = self._c._get("/api/v1/fleet/agents", params=params)
        items = resp.get("data", resp.get("agents", []))
        return [FleetAgent(**a) for a in items]

    def get_fleet_health(self) -> FleetHealth:
        """Get fleet health summary."""
        return FleetHealth(**self._c._get("/api/v1/fleet/health"))

    def get_fleet_blast_radius(self, **params: Any) -> BlastRadius:
        """Get fleet blast radius analysis."""
        return BlastRadius(**self._c._get("/api/v1/fleet/blast-radius", params=params))

    def get_fleet_activity(self, **params: Any) -> dict[str, Any]:
        """Get fleet activity summary."""
        return self._c._get("/api/v1/fleet/activity", params=params)

    # -- Graph ----------------------------------------------------------

    def get_graph_status(self) -> dict[str, Any]:
        """Get governance graph status."""
        return self._c._get("/api/v1/graph/status")

    def rebuild_graph(self) -> dict[str, Any]:
        """Rebuild the governance graph."""
        return self._c._post("/api/v1/graph/rebuild")

    def get_agent_graph(self, agent_id: str) -> dict[str, Any]:
        """Get graph data for a specific agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/graph/agent/{safe_id}")

    def get_blast_radius(self, *, agent_ids: list[str]) -> BlastRadius:
        """Get blast radius analysis for specific agents."""
        return BlastRadius(**self._c._post("/api/v1/graph/blast-radius", json={"agent_ids": agent_ids}))

    def get_delegation_chain_graph(self, agent_id: str) -> dict[str, Any]:
        """Get delegation chain from graph."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/graph/delegation-chain/{safe_id}")

    def get_trust_paths(self, agent_id: str) -> dict[str, Any]:
        """Get trust paths for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/graph/trust-paths/{safe_id}")

    def get_boundary_crossings_graph(self, agent_id: str) -> dict[str, Any]:
        """Get boundary crossings from graph."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/graph/boundary-crossings/{safe_id}")

    def explore_graph(self, **kwargs: Any) -> dict[str, Any]:
        """Explore the governance graph."""
        return self._c._post("/api/v1/graph/explore", json=kwargs)

    def export_graph(self, fmt: str = "json") -> dict[str, Any]:
        """Export the governance graph."""
        safe_fmt = sanitize_path_param(fmt)
        return self._c._get(f"/api/v1/graph/export/{safe_fmt}")

    def get_graph_stats(self) -> dict[str, Any]:
        """Get governance graph statistics."""
        return self._c._get("/api/v1/graph/stats")

    # -- OPA / SPIRE Health ---------------------------------------------

    def get_opa_health(self) -> dict[str, Any]:
        """Get OPA health status."""
        return self._c._get("/api/v1/opa/health")

    def load_opa_policies(self, **kwargs: Any) -> dict[str, Any]:
        """Load policies into OPA."""
        return self._c._post("/api/v1/opa/load-policies", json=kwargs)

    def get_spire_health(self) -> dict[str, Any]:
        """Get SPIRE health status."""
        return self._c._get("/api/v1/spire/health")


class EnforcementAsyncAPI:
    """Asynchronous enforcement and fleet operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def enforce_mcp_call(self, *, agent_id: str, mcp_server_id: str, tool_name: str, context: dict[str, Any] | None = None, **kwargs: Any) -> EnforcementDecision:
        payload: dict[str, Any] = {"agent_id": agent_id, "mcp_server_id": mcp_server_id, "tool_name": tool_name, **kwargs}
        if context:
            payload["context"] = context
        return EnforcementDecision(**await self._c._post("/api/v1/enforce/mcp-call", json=payload))

    async def report_obligations(self, enforcement_id: str, obligations_met: list[str]) -> dict[str, Any]:
        """Report fulfilled obligations for a prior ALLOW decision (PR-05, async)."""
        return await self._c._post(
            "/api/v1/enforce/obligation-report",
            json={"enforcement_id": enforcement_id, "obligations_met": obligations_met},
        )

    async def list_fleet_agents(self, **params: Any) -> list[FleetAgent]:
        resp = await self._c._get("/api/v1/fleet/agents", params=params)
        items = resp.get("data", resp.get("agents", []))
        return [FleetAgent(**a) for a in items]

    async def get_fleet_health(self) -> FleetHealth:
        return FleetHealth(**await self._c._get("/api/v1/fleet/health"))

    async def get_fleet_blast_radius(self, **params: Any) -> BlastRadius:
        return BlastRadius(**await self._c._get("/api/v1/fleet/blast-radius", params=params))

    async def get_fleet_activity(self, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/fleet/activity", params=params)

    async def get_graph_status(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/graph/status")

    async def rebuild_graph(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/graph/rebuild")

    async def get_agent_graph(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/graph/agent/{safe_id}")

    async def get_blast_radius(self, *, agent_ids: list[str]) -> BlastRadius:
        return BlastRadius(**await self._c._post("/api/v1/graph/blast-radius", json={"agent_ids": agent_ids}))

    async def get_delegation_chain_graph(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/graph/delegation-chain/{safe_id}")

    async def get_trust_paths(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/graph/trust-paths/{safe_id}")

    async def get_boundary_crossings_graph(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/graph/boundary-crossings/{safe_id}")

    async def explore_graph(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/graph/explore", json=kwargs)

    async def export_graph(self, fmt: str = "json") -> dict[str, Any]:
        safe_fmt = sanitize_path_param(fmt)
        return await self._c._get(f"/api/v1/graph/export/{safe_fmt}")

    async def get_graph_stats(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/graph/stats")

    async def get_opa_health(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/opa/health")

    async def load_opa_policies(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/opa/load-policies", json=kwargs)

    async def get_spire_health(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/spire/health")
