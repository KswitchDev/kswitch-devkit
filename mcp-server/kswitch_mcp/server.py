"""KSwitch.ai Universal MCP Server.

Trust enforcement for autonomous systems — governs what AI agents are
trusted to do. Works with any MCP-compatible tool: Claude Code, Cursor,
Windsurf, OpenCode, OpenClaw, Cline, and more.

Install:  pip install kswitch-mcp
Run:      kswitch-mcp
Config:   Set KSWITCH_URL and authentication env vars.

26 tools organized across 7 categories:
  Governance (6)  | Compliance (5)  | Enforcement (2) | Identity (4)
  Kill Switch (3) | Policy (3)      | Audit (3)
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from kswitch_mcp.client import KSwitchAPIClient

# ── MCP Server ────────────────────────────────────────────────────────────

mcp = FastMCP(
    "kswitch",
    instructions=(
        "KSwitch.ai Agent Trust Control Plane — governs what AI agents, "
        "MCP servers, and agent-to-agent interactions are trusted to do. "
        "Use these tools to register agents, enforce policies, manage "
        "identities, evaluate compliance, and operate kill switches."
    ),
)

_api = KSwitchAPIClient()


# ═══════════════════════════════════════════════════════════════════════════
# GOVERNANCE (6 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def register_agent(
    display_name: str,
    record_type: str = "AGENT",
    risk_tier: str = "tier_3",
    owning_division: str = "",
    description: str = "",
    contact_email: str = "",
    skills: Optional[list[str]] = None,
    permissions: Optional[list[str]] = None,
) -> dict:
    """Register a new agent or MCP server in the KSwitch control plane.

    Args:
        display_name: Human-readable name for the agent.
        record_type: Type of record — AGENT or MCP_SERVER.
        risk_tier: Risk classification — tier_1 (low) through tier_4 (critical).
        owning_division: Business division that owns this agent.
        description: Purpose and capabilities of the agent.
        contact_email: Contact email for the agent owner.
        skills: List of skill identifiers the agent possesses.
        permissions: List of permission identifiers granted to the agent.

    Returns the created agent record with its assigned ID.
    """
    payload: dict = {
        "display_name": display_name,
        "record_type": record_type,
        "risk_tier": risk_tier,
    }
    if owning_division:
        payload["owning_division"] = owning_division
    if description:
        payload["description"] = description
    if contact_email:
        payload["contact_email"] = contact_email
    if skills:
        payload["skills"] = skills
    if permissions:
        payload["permissions"] = permissions
    return await _api.request("POST", "/api/v1/agents", json=payload)


@mcp.tool()
async def list_agents(
    page: int = 1,
    page_size: int = 25,
    status: Optional[str] = None,
    risk_tier: Optional[str] = None,
    division: Optional[str] = None,
) -> dict:
    """List registered agents with filtering and pagination.

    Args:
        page: Page number (1-indexed).
        page_size: Number of results per page (max 100).
        status: Filter by status — pending, active, suspended, decommissioned.
        risk_tier: Filter by risk tier — tier_1, tier_2, tier_3, tier_4.
        division: Filter by owning division.

    Returns paginated list of agent records.
    """
    params: dict = {"page": page, "page_size": min(page_size, 100)}
    if status:
        params["status"] = status
    if risk_tier:
        params["risk_tier"] = risk_tier
    if division:
        params["owning_division"] = division
    return await _api.request("GET", "/api/v1/agents", params=params)


@mcp.tool()
async def get_agent(agent_id: str) -> dict:
    """Get full details for a specific agent or MCP server.

    Args:
        agent_id: The agent record ID (e.g. 'agent:fraud-detector-v3@bank.internal').

    Returns the complete agent record including status, risk tier, skills,
    permissions, identity info, and connected MCP servers.
    """
    return await _api.request("GET", f"/api/v1/agents/{agent_id}")


@mcp.tool()
async def approve_agent(agent_id: str, reviewed_by: str = "") -> dict:
    """Approve a pending agent, moving it to active status.

    Args:
        agent_id: The agent record ID to approve.
        reviewed_by: Identity of the reviewer (e.g. email or user ID).

    The agent must be in 'pending' status. Approval triggers SPIFFE identity
    issuance and enables enforcement for this agent.
    """
    payload: dict = {}
    if reviewed_by:
        payload["reviewed_by"] = reviewed_by
    return await _api.request("POST", f"/api/v1/agents/{agent_id}/approve", json=payload)


@mcp.tool()
async def suspend_agent(agent_id: str, reason: str = "") -> dict:
    """Suspend an active agent, revoking its ability to operate.

    Args:
        agent_id: The agent record ID to suspend.
        reason: Reason for the suspension (recorded in audit trail).

    Suspension immediately revokes enforcement permissions. The agent's
    SPIFFE identity remains but enforcement calls will be denied.
    """
    payload: dict = {}
    if reason:
        payload["reason"] = reason
    return await _api.request("POST", f"/api/v1/agents/{agent_id}/suspend", json=payload)


@mcp.tool()
async def get_dashboard() -> dict:
    """Get the KSwitch system overview dashboard.

    Returns aggregate statistics including:
    - Agent counts by status (pending, active, suspended, decommissioned)
    - Agent counts by risk tier
    - Record type breakdown (AGENT vs MCP_SERVER)
    - Recent activity summary
    """
    return await _api.request("GET", "/api/v1/dashboard")


# ═══════════════════════════════════════════════════════════════════════════
# COMPLIANCE (5 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def evaluate_toxic_combos(agent_id: str) -> dict:
    """Evaluate an agent for toxic skill/permission combinations.

    Args:
        agent_id: The agent record ID to evaluate.

    Checks the agent's assigned skills and permissions against all active
    toxic combo rules (83 rules covering separation-of-duties, conflict-of-
    interest, and regulatory constraints). Returns any violations with
    severity and the specific rule triggered.
    """
    return await _api.request("POST", f"/api/v1/agents/{agent_id}/evaluate-toxic-combos")


@mcp.tool()
async def evaluate_all_toxic_combos() -> dict:
    """Run toxic combo evaluation across the entire fleet.

    Evaluates every registered agent against all active toxic combo rules.
    Returns a summary with total agents evaluated, violation count, clean
    agent count, and per-agent results for any violations found.
    """
    return await _api.request("POST", "/api/v1/toxic-combos/evaluate-all")


@mcp.tool()
async def analyze_boundaries(agent_id: str) -> dict:
    """Analyze boundary crossings for an agent.

    Args:
        agent_id: The agent record ID to analyze.

    Checks for violations across three boundary types:
    - Tier boundaries (e.g. tier_3 agent accessing tier_1 resources)
    - Division boundaries (e.g. cross-division data access)
    - Data classification boundaries (e.g. public agent accessing confidential data)
    """
    return await _api.request("GET", f"/api/v1/boundary-analysis/{agent_id}")


@mcp.tool()
async def assess_risk(agent_id: str) -> dict:
    """Comprehensive risk assessment for an agent.

    Args:
        agent_id: The agent record ID to assess.

    Combines toxic combo evaluation and boundary crossing analysis into a
    composite risk score (0-1000):
    - 0: Clean (no violations)
    - 1-49: Low risk
    - 50-149: Medium risk
    - 150-299: High risk
    - 300+: Critical risk

    Triggers fresh evaluations — does not use cached results.
    """
    # Run both evaluations server-side
    toxic = await _api.request("POST", f"/api/v1/agents/{agent_id}/evaluate-toxic-combos")
    boundary = await _api.request("GET", f"/api/v1/boundary-analysis/{agent_id}")

    # Calculate composite risk score
    score = 0
    violations = toxic.get("violations", [])
    if isinstance(violations, list):
        for v in violations:
            severity = v.get("severity", "medium")
            score += {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(severity, 50)

    if isinstance(boundary, dict):
        for key, weight in [
            ("tier_crossings", 30),
            ("division_crossings", 20),
            ("data_classification_crossings", 40),
        ]:
            crossings = boundary.get(key, [])
            if isinstance(crossings, list):
                score += len(crossings) * weight

    score = min(score, 1000)
    if score == 0:
        level = "clean"
    elif score < 50:
        level = "low"
    elif score < 150:
        level = "medium"
    elif score < 300:
        level = "high"
    else:
        level = "critical"

    return {
        "agent_id": agent_id,
        "risk_score": score,
        "risk_level": level,
        "toxic_combo_result": toxic,
        "boundary_analysis": boundary,
    }


@mcp.tool()
async def get_compliance_dashboard() -> dict:
    """Get the compliance overview dashboard.

    Returns:
    - Total toxic combo violation count
    - Clean agent count
    - Violation breakdown by severity
    - Error rate for evaluations
    - Last evaluation timestamp
    """
    return await _api.request("GET", "/api/v1/toxic-combos/dashboard")


# ═══════════════════════════════════════════════════════════════════════════
# ENFORCEMENT (2 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def enforce_mcp_call(
    agent_id: str,
    action: str,
    resource: str,
    context: Optional[dict] = None,
) -> dict:
    """Enforce a runtime MCP tool call — the core trust decision.

    Args:
        agent_id: The calling agent's record ID.
        action: The action being attempted (e.g. 'tools/call', 'data/read').
        resource: The target resource (e.g. MCP server name, tool name).
        context: Optional additional context for policy evaluation.

    Returns an enforcement decision:
    - decision: 'allow' or 'deny'
    - reason: Human-readable explanation
    - policies_evaluated: List of policies that were checked
    - data_masking: Any masking rules applied to the response

    This is the critical path for runtime trust enforcement. Every MCP tool
    call in a governed environment should pass through this endpoint.
    """
    payload: dict = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
    }
    if context:
        payload["context"] = context
    return await _api.request("POST", "/api/v1/enforce", json=payload)


@mcp.tool()
async def evaluate_authzen(
    subject_type: str,
    subject_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
) -> dict:
    """Evaluate an authorization request using the AuthZen PDP.

    Args:
        subject_type: Type of the requesting entity (e.g. 'agent', 'user').
        subject_id: ID of the requesting entity.
        action: The action being requested (e.g. 'can_invoke', 'can_read').
        resource_type: Type of the target resource (e.g. 'mcp_server', 'tool').
        resource_id: ID of the target resource.

    Returns a standards-compliant AuthZen evaluation response with
    allow/deny decision and the policies that contributed to it.
    Conforms to the OpenID AuthZen PDP specification.
    """
    payload = {
        "subject": {"type": subject_type, "id": subject_id},
        "action": {"name": action},
        "resource": {"type": resource_type, "id": resource_id},
    }
    return await _api.request("POST", "/access/v1/evaluation", json=payload)


# ═══════════════════════════════════════════════════════════════════════════
# IDENTITY (4 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def create_spiffe_identity(agent_id: str) -> dict:
    """Issue a SPIFFE workload identity for an agent.

    Args:
        agent_id: The agent record ID to issue identity for.

    Creates a SPIFFE SVID (X.509 or JWT) bound to the agent's trust domain.
    The SPIFFE ID follows the pattern:
    spiffe://{trust_domain}/env/{env}/team/{team}/{type}/{name}
    """
    return await _api.request("POST", f"/api/v1/agents/{agent_id}/spiffe", json={})


@mcp.tool()
async def get_identity(agent_id: str) -> dict:
    """Get SPIFFE and service identity details for an agent.

    Args:
        agent_id: The agent record ID.

    Returns the agent's SPIFFE SVID details, any service identities,
    trust domain membership, and credential expiry information.
    """
    return await _api.request("GET", f"/api/v1/agents/{agent_id}/spiffe")


@mcp.tool()
async def rotate_identity(agent_id: str) -> dict:
    """Rotate an agent's SPIFFE SVID.

    Args:
        agent_id: The agent record ID.

    Issues a new SVID while gracefully deprecating the old one.
    The rotation is recorded in the audit trail.
    """
    return await _api.request("PATCH", f"/api/v1/agents/{agent_id}/spiffe")


@mcp.tool()
async def list_expiring_identities(days: int = 30) -> dict:
    """Find identities expiring within a given timeframe.

    Args:
        days: Number of days to look ahead (default 30).

    Returns a list of agents whose SPIFFE SVIDs or service identities
    will expire within the specified window, sorted by expiry date.
    """
    return await _api.request(
        "GET", "/api/v1/identities/expiring", params={"days": days}
    )


# ═══════════════════════════════════════════════════════════════════════════
# KILL SWITCH (3 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def kill_switch(agent_ids: list[str], reason: str = "") -> dict:
    """Execute a targeted kill switch on specific agents.

    Args:
        agent_ids: List of agent record IDs to kill.
        reason: Reason for the kill switch activation.

    Immediately suspends the specified agents, revokes their SPIFFE
    identities, and revokes all service identities. This is an
    emergency action recorded in the kill switch history.
    """
    payload: dict = {"agent_ids": agent_ids}
    if reason:
        payload["reason"] = reason
    return await _api.request("POST", "/api/v1/kill-switch", json=payload)


@mcp.tool()
async def get_kill_switch_history() -> dict:
    """Get kill switch activation history.

    Returns a chronological list of all kill switch activations including:
    - Who activated the kill switch
    - Reason for activation
    - Scope (targeted agent IDs or blanket)
    - Timestamp and outcome
    """
    return await _api.request("GET", "/api/v1/kill-switch/history")


@mcp.tool()
async def get_blast_radius(agent_ids: list[str]) -> dict:
    """Analyze the blast radius before executing a kill switch.

    Args:
        agent_ids: List of agent record IDs to analyze.

    Shows the downstream impact of killing the specified agents:
    - Connected MCP servers that would lose access
    - Delegation chains that would break
    - Dependent agents that rely on these agents
    - Estimated service disruption scope

    Use this before kill_switch to understand the consequences.
    """
    return await _api.request(
        "POST", "/api/v1/graph/blast-radius", json={"agent_ids": agent_ids}
    )


# ═══════════════════════════════════════════════════════════════════════════
# POLICY (3 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def list_policies(
    page: int = 1,
    page_size: int = 25,
    category: Optional[str] = None,
    engine: Optional[str] = None,
) -> dict:
    """List governance policies with filtering and pagination.

    Args:
        page: Page number (1-indexed).
        page_size: Number of results per page (max 100).
        category: Filter by policy category (e.g. 'access_control', 'data_protection').
        engine: Filter by policy engine — 'cedar' or 'opa'.

    Returns paginated list of policies with their enforcement mode
    (enforce, shadow, disabled) and priority.
    """
    params: dict = {"page": page, "page_size": min(page_size, 100)}
    if category:
        params["category"] = category
    if engine:
        params["engine"] = engine
    return await _api.request("GET", "/api/v1/policies", params=params)


@mcp.tool()
async def evaluate_policy(record_id: str) -> dict:
    """Evaluate all applicable policies for a governance record.

    Args:
        record_id: The agent or MCP server record ID to evaluate against.

    Runs the record through all active Cedar and OPA policies, returning
    the evaluation results including which policies passed, failed, or
    triggered warnings.
    """
    return await _api.request(
        "POST",
        "/api/v1/policies/evaluate",
        json={"record_id": record_id},
    )


@mcp.tool()
async def get_policy(policy_id: str) -> dict:
    """Get full details for a specific governance policy.

    Args:
        policy_id: The policy ID.

    Returns the complete policy record including:
    - Cedar policy text (policy_text)
    - Rego policy text (rego_text)
    - Enforcement mode (enforce, shadow, disabled)
    - Priority and category
    - Applicable record types and conditions
    """
    return await _api.request("GET", f"/api/v1/policies/{policy_id}")


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT (3 tools)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def get_system_status() -> dict:
    """Get overall KSwitch system health and status.

    Returns:
    - API health check result
    - Dashboard data (agent counts by status, risk tier breakdown)
    - Event delivery statistics (pending, delivered, failed, dead letter)
    """
    dashboard = await _api.request("GET", "/api/v1/dashboard")
    events = await _api.request("GET", "/api/v1/events/stats")
    health = await _api.request("GET", "/api/v1/health")
    return {
        "health": health,
        "dashboard": dashboard,
        "event_stats": events,
    }


@mcp.tool()
async def get_audit_trail(agent_id: str) -> dict:
    """Get the full audit trail for a specific agent.

    Args:
        agent_id: The agent record ID.

    Returns all state changes, approvals, suspensions, configuration
    modifications, identity events, and policy evaluations for the agent,
    in chronological order.
    """
    return await _api.request("GET", f"/api/v1/agents/{agent_id}/audit")


@mcp.tool()
async def detect_anomalies() -> dict:
    """Analyze recent governance events for anomalous patterns.

    Checks for:
    - Burst registrations (>10 agents in the last hour)
    - Mass suspensions (>5 in the last hour)
    - Kill switch activations
    - Dead letter events (delivery failures)
    - Decommission spikes

    Returns a structured anomaly report with severity levels and
    recommended actions.
    """
    from collections import Counter
    from datetime import datetime, timezone, timedelta

    events_result = await _api.request("GET", "/api/v1/events", params={"limit": 200})
    event_stats = await _api.request("GET", "/api/v1/events/stats")

    anomalies: list[dict] = []
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    events = events_result.get("data", [])
    if isinstance(events_result, list):
        events = events_result

    recent_by_type: Counter = Counter()
    for evt in events:
        if not isinstance(evt, dict):
            continue
        created = evt.get("created_at", "")
        if not isinstance(created, str) or not created:
            continue
        try:
            evt_time = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if evt_time >= one_hour_ago:
                recent_by_type[evt.get("event_type", "unknown")] += 1
        except (ValueError, TypeError):
            pass

    reg_count = recent_by_type.get("agent.registered", 0)
    if reg_count > 10:
        anomalies.append({
            "type": "burst_registrations",
            "severity": "high",
            "detail": f"{reg_count} agent registrations in the last hour",
            "count": reg_count,
        })

    suspend_count = recent_by_type.get("agent.suspended", 0)
    if suspend_count > 5:
        anomalies.append({
            "type": "mass_suspensions",
            "severity": "critical",
            "detail": f"{suspend_count} agent suspensions in the last hour",
            "count": suspend_count,
        })

    ks_count = recent_by_type.get("kill_switch.activated", 0)
    if ks_count > 0:
        anomalies.append({
            "type": "kill_switch_activity",
            "severity": "critical",
            "detail": f"{ks_count} kill switch activations in the last hour",
            "count": ks_count,
        })

    dead_letters = event_stats.get("dead_letter", 0)
    if dead_letters and dead_letters > 0:
        anomalies.append({
            "type": "dead_letter_events",
            "severity": "high",
            "detail": f"{dead_letters} dead letter events detected",
            "count": dead_letters,
        })

    failed = event_stats.get("failed", 0)
    if failed and failed > 10:
        anomalies.append({
            "type": "event_delivery_failures",
            "severity": "medium",
            "detail": f"{failed} failed event deliveries",
            "count": failed,
        })

    decom_count = recent_by_type.get("agent.decommissioned", 0)
    if decom_count > 3:
        anomalies.append({
            "type": "decommission_spike",
            "severity": "medium",
            "detail": f"{decom_count} agent decommissions in the last hour",
            "count": decom_count,
        })

    return {
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "events_analyzed": len(events),
        "recent_event_counts": dict(recent_by_type),
        "checked_at": now.isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Run the KSwitch MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
