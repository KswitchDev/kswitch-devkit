"""Governance API — agent/MCP lifecycle management.

Covers: register, list, get, patch, approve, suspend, reactivate,
decommission, gates, approval-criteria, delegation, tickets, skills,
connected-mcps, MCP registration, sandbox attestation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .client import sanitize_path_param
from .models import (
    Agent,
    ApprovalCriteria,
    DelegationChain,
    GateStatus,
    MCPServer,
    PaginatedResponse,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class GovernanceAPI:
    """Synchronous governance operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- Agents ---------------------------------------------------------

    def register_agent(
        self,
        *,
        display_name: str,
        record_type: str = "AGENT",
        **kwargs: Any,
    ) -> Agent:
        """Register a new agent or MCP server."""
        payload = {"display_name": display_name, "record_type": record_type, **kwargs}
        return Agent(**self._c._post("/api/v1/agents", json=payload))

    def list_agents(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        **filters: Any,
    ) -> PaginatedResponse[Agent]:
        """List agents with pagination and optional filters."""
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = self._c._get("/api/v1/agents", params=params)
        items = resp.get("data", [])
        return PaginatedResponse[Agent](
            data=[Agent(**a) for a in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    def get_agent(self, agent_id: str) -> Agent:
        """Get a single agent by ID."""
        safe_id = sanitize_path_param(agent_id)
        return Agent(**self._c._get(f"/api/v1/agents/{safe_id}"))

    def update_agent(self, agent_id: str, **fields: Any) -> Agent:
        """Patch an agent record (partial update)."""
        safe_id = sanitize_path_param(agent_id)
        return Agent(**self._c._patch(f"/api/v1/agents/{safe_id}", json=fields))

    def approve(
        self,
        agent_id: str,
        *,
        reviewed_by: str | None = None,
        jira_ticket: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Approve an agent."""
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {**kwargs}
        if reviewed_by:
            payload["reviewed_by"] = reviewed_by
        if jira_ticket:
            payload["jira_ticket"] = jira_ticket
        return self._c._post(f"/api/v1/agents/{safe_id}/approve", json=payload)

    def suspend(self, agent_id: str, *, reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Suspend an active agent."""
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {**kwargs}
        if reason:
            payload["reason"] = reason
        return self._c._post(f"/api/v1/agents/{safe_id}/suspend", json=payload)

    def reactivate(self, agent_id: str) -> dict[str, Any]:
        """Reactivate a suspended agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._post(f"/api/v1/agents/{safe_id}/reactivate")

    def decommission(self, agent_id: str) -> dict[str, Any]:
        """Permanently decommission an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._post(f"/api/v1/agents/{safe_id}/decommission")

    def get_approval_criteria(self, agent_id: str) -> ApprovalCriteria:
        """Get the approval criteria for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return ApprovalCriteria(**self._c._get(f"/api/v1/agents/{safe_id}/approval-criteria"))

    def get_audit(self, agent_id: str) -> dict[str, Any]:
        """Get the full audit trail for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/agents/{safe_id}/audit")

    def report_last_active(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
        """Report last-active heartbeat for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._post(f"/api/v1/agents/{safe_id}/last-active", json=kwargs)

    # -- Tickets --------------------------------------------------------

    def link_ticket(self, agent_id: str, *, ticket_id: str, system: str = "jira", **kwargs: Any) -> dict[str, Any]:
        """Link a ticket to an agent record."""
        safe_id = sanitize_path_param(agent_id)
        payload = {"ticket_id": ticket_id, "system": system, **kwargs}
        return self._c._post(f"/api/v1/agents/{safe_id}/tickets", json=payload)

    def validate_ticket(self, *, system: str, ticket_id: str) -> dict[str, Any]:
        """Validate a ticket exists."""
        safe_system = sanitize_path_param(system)
        safe_ticket = sanitize_path_param(ticket_id)
        return self._c._get(f"/api/v1/tickets/validate/{safe_system}/{safe_ticket}")

    def validate_ticket_post(self, **kwargs: Any) -> dict[str, Any]:
        """Validate a ticket via POST body."""
        return self._c._post("/api/v1/tickets/validate", json=kwargs)

    def get_ticket_audit(self) -> dict[str, Any]:
        """Get ticket audit log."""
        return self._c._get("/api/v1/tickets/audit")

    def clear_ticket_cache(self) -> dict[str, Any]:
        """Clear the ticket validation cache."""
        return self._c._post("/api/v1/tickets/cache/clear")

    # -- Skills on Agent ------------------------------------------------

    def list_agent_skills(self, agent_id: str) -> dict[str, Any]:
        """List skills assigned to an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/agents/{safe_id}/skills")

    def assign_skills(self, agent_id: str, *, skills: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        """Assign skills to an agent."""
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"skills": skills, **kwargs}
        return self._c._post(f"/api/v1/agents/{safe_id}/skills", json=payload)

    def remove_skill(self, agent_id: str, skill_id: str) -> dict[str, Any]:
        """Remove a skill assignment from an agent."""
        safe_agent = sanitize_path_param(agent_id)
        safe_skill = sanitize_path_param(skill_id)
        return self._c._delete(f"/api/v1/agents/{safe_agent}/skills/{safe_skill}")

    # -- Connected MCPs -------------------------------------------------

    def list_connected_mcps(self, agent_id: str) -> dict[str, Any]:
        """List MCP servers connected to an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/agents/{safe_id}/connected-mcps")

    def connect_mcps(self, agent_id: str, *, mcp_ids: list[str], **kwargs: Any) -> dict[str, Any]:
        """Connect an agent to MCP servers."""
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"mcp_ids": mcp_ids, **kwargs}
        return self._c._post(f"/api/v1/agents/{safe_id}/connected-mcps", json=payload)

    # -- Delegation -----------------------------------------------------

    def delegate(self, agent_id: str, *, delegate_to: str, **kwargs: Any) -> dict[str, Any]:
        """Create a delegation from one agent to another."""
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"delegate_to": delegate_to, **kwargs}
        return self._c._post(f"/api/v1/agents/{safe_id}/delegate", json=payload)

    def get_delegation_chain(self, agent_id: str) -> DelegationChain:
        """Get the delegation chain for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return DelegationChain(**self._c._get(f"/api/v1/agents/{safe_id}/delegation-chain"))

    def list_delegates(self, agent_id: str) -> dict[str, Any]:
        """List delegates for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._get(f"/api/v1/agents/{safe_id}/delegates")

    def revoke_delegation(self, agent_id: str) -> dict[str, Any]:
        """Revoke delegation for an agent."""
        safe_id = sanitize_path_param(agent_id)
        return self._c._delete(f"/api/v1/agents/{safe_id}/delegation")

    def validate_delegation(self, **kwargs: Any) -> dict[str, Any]:
        """Validate a delegation chain."""
        return self._c._post("/api/v1/delegation/validate", json=kwargs)

    # -- MCP Registration -----------------------------------------------

    def register_mcp(self, *, display_name: str, **kwargs: Any) -> MCPServer:
        """Register a new MCP server."""
        payload = {"display_name": display_name, "record_type": "MCP_SERVER", **kwargs}
        return MCPServer(**self._c._post("/api/v1/mcp/register", json=payload))

    def declare_mcp(self, **kwargs: Any) -> dict[str, Any]:
        """Submit an MCP declaration."""
        return self._c._post("/api/v1/mcp/declare", json=kwargs)

    def attest_sandbox(self, **kwargs: Any) -> dict[str, Any]:
        """Attest MCP sandbox environment."""
        return self._c._post("/api/v1/mcp/sandbox/attest", json=kwargs)

    def get_registration_tracks(self) -> dict[str, Any]:
        """Get available MCP registration tracks."""
        return self._c._get("/api/v1/mcp/registration-tracks")

    def refresh_consumer_counts(self) -> dict[str, Any]:
        """Refresh MCP consumer counts."""
        return self._c._post("/api/v1/mcp/refresh-consumer-counts")

    def list_mcp_consumers(self, mcp_id: str) -> dict[str, Any]:
        """List consumers of an MCP server."""
        safe_id = sanitize_path_param(mcp_id)
        return self._c._get(f"/api/v1/mcp/{safe_id}/consumers")

    def list_mcp_tools(self, mcp_id: str) -> dict[str, Any]:
        """List tools registered by an MCP server."""
        safe_id = sanitize_path_param(mcp_id)
        return self._c._get(f"/api/v1/mcp/{safe_id}/tools")

    # -- Gates ----------------------------------------------------------

    def update_gates(self, mcp_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update gate evaluation data for an MCP server."""
        safe_id = sanitize_path_param(mcp_id)
        return self._c._post(f"/api/v1/mcp/{safe_id}/gates", json=kwargs)

    def evaluate_gates(self, mcp_id: str) -> dict[str, Any]:
        """Run auto-gate evaluation for an MCP server."""
        safe_id = sanitize_path_param(mcp_id)
        return self._c._post(f"/api/v1/mcp/{safe_id}/gates/evaluate")

    def auto_apply_gates(self, mcp_id: str) -> dict[str, Any]:
        """Auto-apply passing gates for an MCP server."""
        safe_id = sanitize_path_param(mcp_id)
        return self._c._post(f"/api/v1/mcp/{safe_id}/gates/auto-apply")

    def get_gate_status(self, mcp_id: str) -> GateStatus:
        """Get current gate evaluation status."""
        safe_id = sanitize_path_param(mcp_id)
        return GateStatus(**self._c._get(f"/api/v1/mcp/{safe_id}/gates/status"))


# ---------------------------------------------------------------------------
# Async variant
# ---------------------------------------------------------------------------

class GovernanceAsyncAPI:
    """Asynchronous governance operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def register_agent(self, *, display_name: str, record_type: str = "AGENT", **kwargs: Any) -> Agent:
        payload = {"display_name": display_name, "record_type": record_type, **kwargs}
        return Agent(**await self._c._post("/api/v1/agents", json=payload))

    async def list_agents(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Agent]:
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = await self._c._get("/api/v1/agents", params=params)
        items = resp.get("data", [])
        return PaginatedResponse[Agent](
            data=[Agent(**a) for a in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    async def get_agent(self, agent_id: str) -> Agent:
        safe_id = sanitize_path_param(agent_id)
        return Agent(**await self._c._get(f"/api/v1/agents/{safe_id}"))

    async def update_agent(self, agent_id: str, **fields: Any) -> Agent:
        safe_id = sanitize_path_param(agent_id)
        return Agent(**await self._c._patch(f"/api/v1/agents/{safe_id}", json=fields))

    async def approve(self, agent_id: str, *, reviewed_by: str | None = None, jira_ticket: str | None = None, **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {**kwargs}
        if reviewed_by:
            payload["reviewed_by"] = reviewed_by
        if jira_ticket:
            payload["jira_ticket"] = jira_ticket
        return await self._c._post(f"/api/v1/agents/{safe_id}/approve", json=payload)

    async def suspend(self, agent_id: str, *, reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {**kwargs}
        if reason:
            payload["reason"] = reason
        return await self._c._post(f"/api/v1/agents/{safe_id}/suspend", json=payload)

    async def reactivate(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._post(f"/api/v1/agents/{safe_id}/reactivate")

    async def decommission(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._post(f"/api/v1/agents/{safe_id}/decommission")

    async def get_approval_criteria(self, agent_id: str) -> ApprovalCriteria:
        safe_id = sanitize_path_param(agent_id)
        return ApprovalCriteria(**await self._c._get(f"/api/v1/agents/{safe_id}/approval-criteria"))

    async def get_audit(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/agents/{safe_id}/audit")

    async def report_last_active(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._post(f"/api/v1/agents/{safe_id}/last-active", json=kwargs)

    async def link_ticket(self, agent_id: str, *, ticket_id: str, system: str = "jira", **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload = {"ticket_id": ticket_id, "system": system, **kwargs}
        return await self._c._post(f"/api/v1/agents/{safe_id}/tickets", json=payload)

    async def validate_ticket(self, *, system: str, ticket_id: str) -> dict[str, Any]:
        safe_system = sanitize_path_param(system)
        safe_ticket = sanitize_path_param(ticket_id)
        return await self._c._get(f"/api/v1/tickets/validate/{safe_system}/{safe_ticket}")

    async def validate_ticket_post(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/tickets/validate", json=kwargs)

    async def get_ticket_audit(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/tickets/audit")

    async def clear_ticket_cache(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/tickets/cache/clear")

    async def list_agent_skills(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/agents/{safe_id}/skills")

    async def assign_skills(self, agent_id: str, *, skills: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"skills": skills, **kwargs}
        return await self._c._post(f"/api/v1/agents/{safe_id}/skills", json=payload)

    async def remove_skill(self, agent_id: str, skill_id: str) -> dict[str, Any]:
        safe_agent = sanitize_path_param(agent_id)
        safe_skill = sanitize_path_param(skill_id)
        return await self._c._delete(f"/api/v1/agents/{safe_agent}/skills/{safe_skill}")

    async def list_connected_mcps(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/agents/{safe_id}/connected-mcps")

    async def connect_mcps(self, agent_id: str, *, mcp_ids: list[str], **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"mcp_ids": mcp_ids, **kwargs}
        return await self._c._post(f"/api/v1/agents/{safe_id}/connected-mcps", json=payload)

    async def delegate(self, agent_id: str, *, delegate_to: str, **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        payload: dict[str, Any] = {"delegate_to": delegate_to, **kwargs}
        return await self._c._post(f"/api/v1/agents/{safe_id}/delegate", json=payload)

    async def get_delegation_chain(self, agent_id: str) -> DelegationChain:
        safe_id = sanitize_path_param(agent_id)
        return DelegationChain(**await self._c._get(f"/api/v1/agents/{safe_id}/delegation-chain"))

    async def list_delegates(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._get(f"/api/v1/agents/{safe_id}/delegates")

    async def revoke_delegation(self, agent_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(agent_id)
        return await self._c._delete(f"/api/v1/agents/{safe_id}/delegation")

    async def validate_delegation(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/delegation/validate", json=kwargs)

    async def register_mcp(self, *, display_name: str, **kwargs: Any) -> MCPServer:
        payload = {"display_name": display_name, "record_type": "MCP_SERVER", **kwargs}
        return MCPServer(**await self._c._post("/api/v1/mcp/register", json=payload))

    async def declare_mcp(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/mcp/declare", json=kwargs)

    async def attest_sandbox(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/mcp/sandbox/attest", json=kwargs)

    async def get_registration_tracks(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/mcp/registration-tracks")

    async def refresh_consumer_counts(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/mcp/refresh-consumer-counts")

    async def list_mcp_consumers(self, mcp_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(mcp_id)
        return await self._c._get(f"/api/v1/mcp/{safe_id}/consumers")

    async def list_mcp_tools(self, mcp_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(mcp_id)
        return await self._c._get(f"/api/v1/mcp/{safe_id}/tools")

    async def update_gates(self, mcp_id: str, **kwargs: Any) -> dict[str, Any]:
        safe_id = sanitize_path_param(mcp_id)
        return await self._c._post(f"/api/v1/mcp/{safe_id}/gates", json=kwargs)

    async def evaluate_gates(self, mcp_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(mcp_id)
        return await self._c._post(f"/api/v1/mcp/{safe_id}/gates/evaluate")

    async def auto_apply_gates(self, mcp_id: str) -> dict[str, Any]:
        safe_id = sanitize_path_param(mcp_id)
        return await self._c._post(f"/api/v1/mcp/{safe_id}/gates/auto-apply")

    async def get_gate_status(self, mcp_id: str) -> GateStatus:
        safe_id = sanitize_path_param(mcp_id)
        return GateStatus(**await self._c._get(f"/api/v1/mcp/{safe_id}/gates/status"))
