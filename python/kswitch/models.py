"""Pydantic models for KSwitch API request and response types.

All models use ``model_config = ConfigDict(extra="allow")`` so that new
fields returned by the API are captured without breaking existing code.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

class PaginatedResponse(_Base, Generic[T]):
    """Generic paginated list returned by list endpoints."""

    data: list[T] = Field(default_factory=list)
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


# ---------------------------------------------------------------------------
# Agent / Record
# ---------------------------------------------------------------------------

class Agent(_Base):
    """An agent or MCP server record in the governance registry."""

    id: str
    display_name: str
    record_type: Literal["AGENT", "MCP_SERVER"] = "AGENT"
    status: str = "pending_review"
    risk_tier: str | None = None
    owning_division: str | None = None
    owning_team: str | None = None
    description: str | None = None
    environment: str | None = None
    source_repo: str | None = None
    framework: str | None = None
    version: str | None = None
    contact_email: str | None = None
    data_classification: str | None = None
    deployment_model: str | None = None
    mcp_endpoint: str | None = None
    mcp_transport: str | None = None
    sandbox_status: str | None = None
    registration_track: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    approved_at: datetime | None = None
    approved_by: str | None = None
    jira_ticket: str | None = None
    metadata: dict[str, Any] | None = None


class ApprovalCriteria(_Base):
    """Criteria that must be met before an agent can be approved."""

    agent_id: str
    criteria: list[dict[str, Any]] = Field(default_factory=list)
    all_met: bool = False


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

class MCPServer(Agent):
    """An MCP server record (specialization of Agent with record_type=MCP_SERVER)."""

    record_type: Literal["MCP_SERVER"] = "MCP_SERVER"


class GateResult(_Base):
    """A single gate evaluation result."""

    gate_name: str | None = None
    status: str | None = None
    details: dict[str, Any] | None = None


class GateStatus(_Base):
    """Aggregate gate status for an MCP server."""

    mcp_id: str | None = None
    gates: list[GateResult] = Field(default_factory=list)
    all_passed: bool = False


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class Policy(_Base):
    """A Cedar/Rego governance policy."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    policy_type: str | None = None
    cedar_text: str | None = None
    rego_text: str | None = None
    mode: str | None = None  # "enforce" | "shadow" | "disabled"
    status: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    created_by: str | None = None


class PolicyValidation(_Base):
    """Result of validating a policy's syntax."""

    valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class PolicyDecision(_Base):
    """Result of a policy evaluation."""

    decision: bool = False
    context: dict[str, Any] | None = None
    policies_matched: list[str] = Field(default_factory=list)


class PolicyEvaluation(_Base):
    """A logged policy evaluation record."""

    id: str | None = None
    principal: str | None = None
    action: str | None = None
    resource: str | None = None
    decision: str | None = None
    policies_matched: list[str] = Field(default_factory=list)
    evaluated_at: datetime | None = None


# ---------------------------------------------------------------------------
# AuthZen
# ---------------------------------------------------------------------------

class AuthZenSubject(_Base):
    """AuthZen subject."""

    type: str
    id: str
    properties: dict[str, Any] | None = None


class AuthZenResource(_Base):
    """AuthZen resource."""

    type: str
    id: str
    properties: dict[str, Any] | None = None


class AuthZenAction(_Base):
    """AuthZen action."""

    name: str
    properties: dict[str, Any] | None = None


class AuthZenRequest(_Base):
    """AuthZen evaluation request body."""

    subject: AuthZenSubject
    resource: AuthZenResource
    action: AuthZenAction
    context: dict[str, Any] | None = None


class AuthZenDecision(_Base):
    """AuthZen evaluation decision."""

    decision: bool = False
    context: dict[str, Any] | None = None


class AuthZenBatchResponse(_Base):
    """AuthZen batch evaluation response."""

    evaluations: list[AuthZenDecision] = Field(default_factory=list)


class AuthZenSearchResult(_Base):
    """AuthZen search result."""

    results: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity / SPIFFE
# ---------------------------------------------------------------------------

class SpiffeIdentity(_Base):
    """A SPIFFE identity for an agent."""

    agent_id: str | None = None
    spiffe_id: str | None = None
    trust_domain: str | None = None
    svid_serial: str | None = None
    svid_expires_at: datetime | None = None
    svid_issued_at: datetime | None = None
    status: str | None = None
    x509_svid: str | None = None


class ServiceIdentity(_Base):
    """A service identity bound to an agent."""

    id: str | None = None
    agent_id: str | None = None
    identity_type: str | None = None
    identifier: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None


class TrustDomain(_Base):
    """A SPIFFE trust domain configuration."""

    name: str | None = None
    description: str | None = None
    endpoint: str | None = None
    status: str | None = None
    created_at: datetime | None = None
    metadata: dict[str, Any] | None = None


class IdentityStats(_Base):
    """Aggregate identity statistics."""

    total: int = 0
    active: int = 0
    revoked: int = 0
    expiring_soon: int = 0


# ---------------------------------------------------------------------------
# Compliance / Toxic Combos
# ---------------------------------------------------------------------------

class ToxicComboViolation(_Base):
    """A single toxic combination violation."""

    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    skills: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    details: str | None = None


class ToxicComboResult(_Base):
    """Result of evaluating an agent for toxic combinations."""

    agent_id: str | None = None
    violations: list[ToxicComboViolation] = Field(default_factory=list)
    clean: bool = True
    evaluated_at: datetime | None = None


class ToxicComboRule(_Base):
    """A toxic combination rule definition."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    waivable: bool = True
    status: str | None = None
    skill_pairs: list[dict[str, Any]] = Field(default_factory=list)
    permission_pairs: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime | None = None


class ToxicComboDashboard(_Base):
    """Toxic combo dashboard summary."""

    total_violations: int = 0
    clean_agents: int = 0
    violation_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    last_evaluation: datetime | None = None


class BoundaryAnalysis(_Base):
    """Boundary crossing analysis for an agent."""

    agent_id: str | None = None
    crossings: list[dict[str, Any]] = Field(default_factory=list)
    tier_violations: list[dict[str, Any]] = Field(default_factory=list)
    division_violations: list[dict[str, Any]] = Field(default_factory=list)
    data_classification_violations: list[dict[str, Any]] = Field(default_factory=list)


class RiskScore(_Base):
    """Composite risk score for an agent."""

    agent_id: str | None = None
    score: int = 0
    level: str = "clean"
    toxic_violations: int = 0
    boundary_crossings: int = 0


class FleetRiskSummary(_Base):
    """Fleet-wide risk summary."""

    total_agents: int = 0
    distribution: dict[str, int] = Field(default_factory=dict)
    top_risk_agents: list[RiskScore] = Field(default_factory=list)
    total_violations: int = 0


# ---------------------------------------------------------------------------
# Kill Switch
# ---------------------------------------------------------------------------

class KillSwitchResult(_Base):
    """Result of a targeted kill switch activation."""

    suspended: list[str] = Field(default_factory=list)
    spiffe_revoked: int = 0
    service_identities_revoked: int = 0
    message: str | None = None


class BlanketKillRequest(_Base):
    """A blanket kill switch request."""

    id: str | None = None
    initiated_by: str | None = None
    reason: str | None = None
    scope: str | None = None
    status: str | None = None
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime | None = None


class KillSwitchHistory(_Base):
    """Kill switch activation history entry."""

    id: str | None = None
    kill_type: str | None = None
    initiated_by: str | None = None
    reason: str | None = None
    scope: str | None = None
    affected_agents: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class AutoKillConfig(_Base):
    """Auto kill switch configuration."""

    enabled: bool = False
    threshold: int = 0
    evaluation_window_minutes: int = 60
    require_approval: bool = True
    notify_channels: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class Event(_Base):
    """A governance event from the outbox."""

    id: str | None = None
    event_type: str | None = None
    payload: dict[str, Any] | None = None
    status: str | None = None
    created_at: datetime | None = None
    delivered_at: datetime | None = None
    retry_count: int = 0


class EventStats(_Base):
    """Event delivery statistics."""

    pending: int = 0
    delivered: int = 0
    failed: int = 0
    dead_letter: int = 0
    delivery_rate: float = 0.0


# ---------------------------------------------------------------------------
# Catalog (Skills & Tools)
# ---------------------------------------------------------------------------

class Skill(_Base):
    """A skill catalog entry."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    category: str | None = None
    risk_level: str | None = None
    status: str | None = None
    source: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime | None = None


class Tool(_Base):
    """A tool catalog entry."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    mcp_server_id: str | None = None
    input_schema: dict[str, Any] | None = None
    risk_level: str | None = None
    status: str | None = None
    source: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime | None = None


class SyncSource(_Base):
    """A sync source configuration."""

    id: str | None = None
    name: str | None = None
    source_type: str | None = None
    url: str | None = None
    status: str | None = None
    last_synced: datetime | None = None
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

class EnforcementRequest(_Base):
    """MCP call enforcement request."""

    agent_id: str
    mcp_server_id: str
    tool_name: str
    context: dict[str, Any] | None = None


class Obligation(_Base):
    """A requirement the caller MUST fulfill after an ALLOW decision."""

    type: str | None = None                         # ObligationType value
    obligation_type: str | None = None               # Alias (new contract field)
    level: str | None = None                         # "critical"|"high"|"medium"|"low"
    detail: str | None = None


class SDKViolation(_Base):
    """An informational finding attached to ALLOW or DENY decisions."""

    type: str | None = None                          # ViolationType value
    violation_type: str | None = None                 # Alias (new contract field)
    detail: str | None = None
    severity: str | None = None


class OutputPolicy(_Base):
    """How the caller must handle tool output after an ALLOW decision."""

    mode: str | None = None                          # "allow_raw"|"mask_fields"|"summarize_only"|...
    masking_classifications: list[str] = Field(default_factory=list)
    max_output_bytes: int | None = None
    requires_human_release: bool = False


class PolicyContextSnapshot(_Base):
    """EP-221 policy-context evidence attached to a decision."""

    schema_version: str = "kswitch.policy_context.v1"
    context_snapshot_id: str | None = None
    decision_id: str | None = None
    tenant_id: str | None = None
    agent_id: str | None = None
    agent_session_id: str | None = None
    mode: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    identity: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)
    active_artefacts: list[dict[str, Any]] = Field(default_factory=list)
    tool_request: dict[str, Any] = Field(default_factory=dict)
    data_context: dict[str, Any] = Field(default_factory=dict)
    graph_context: dict[str, Any] = Field(default_factory=dict)
    source_status: dict[str, list[str]] = Field(default_factory=dict)
    replay: dict[str, Any] = Field(default_factory=dict)
    integrity: dict[str, Any] = Field(default_factory=dict)


class DecisionExplanation(_Base):
    """EP-221 deterministic explanation attached to a decision."""

    schema_version: str = "kswitch.decision_explanation.v1"
    decision_id: str | None = None
    context_snapshot_id: str | None = None
    outcome: str | None = None                       # "allow"|"deny"|"conditional"
    reason: str | None = None
    deny_reason: str | None = None
    escalation_hint: str | None = None
    evaluation_mode: str | None = None
    policy_enforcement_mode: str | None = None
    reason_summary: str | None = None
    policy_attribution: dict[str, Any] = Field(default_factory=dict)
    contributing_signals: list[str] = Field(default_factory=list)
    missing_required_signals: list[str] = Field(default_factory=list)
    stale_signals: list[str] = Field(default_factory=list)
    advisory_signals_ignored_for_allow: list[str] = Field(default_factory=list)
    next_safe_actions: list[str] = Field(default_factory=list)


class EnforcementDecision(_Base):
    """MCP call enforcement decision (universal decision contract v1.0)."""

    allowed: bool = False
    reason: str | None = None
    outcome: str | None = None                       # "allow"|"deny"|"conditional"
    decision_path: list[str] = Field(default_factory=list)
    obligations: list[Obligation] = Field(default_factory=list)
    violations: list[SDKViolation] = Field(default_factory=list)
    escalation_hint: str | None = None
    output_policy: OutputPolicy | None = None
    contract_version: str | None = None
    evaluation_mode: str | None = None               # "central"|"local_pdp"|"fallback"
    bundle_version: str | None = None
    context_pack_id: str | None = None
    policy_set_hash: str | None = None
    context_snapshot_id: str | None = None
    context_snapshot_digest: str | None = None
    context_snapshot: PolicyContextSnapshot | None = None
    decision_explanation: DecisionExplanation | None = None
    status_recheck: str | None = None
    enforcement_id: str | None = None               # PR-05: obligation tracking ID
    # Legacy fields (backward compat)
    policies_evaluated: list[str] = Field(default_factory=list)
    context: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------

class FleetAgent(_Base):
    """A fleet agent summary."""

    agent_id: str | None = None
    display_name: str | None = None
    status: str | None = None
    last_active: datetime | None = None
    health: str | None = None


class FleetHealth(_Base):
    """Fleet health summary."""

    total_agents: int = 0
    healthy: int = 0
    unhealthy: int = 0
    unknown: int = 0


class BlastRadius(_Base):
    """Blast radius analysis result."""

    agent_ids: list[str] = Field(default_factory=list)
    affected_agents: list[str] = Field(default_factory=list)
    affected_mcps: list[str] = Field(default_factory=list)
    total_impact: int = 0


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthStatus(_Base):
    """API health check response."""

    status: str = "ok"
    version: str | None = None
    database: str | None = None
    uptime: float | None = None


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard(_Base):
    """Main governance dashboard."""

    total_agents: int = 0
    total_mcp_servers: int = 0
    agents_by_status: dict[str, int] = Field(default_factory=dict)
    agents_by_risk_tier: dict[str, int] = Field(default_factory=dict)
    recent_events: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

class DelegationRequest(_Base):
    """Agent delegation request."""

    delegate_to: str
    scope: str | None = None
    expires_at: datetime | None = None
    reason: str | None = None


class DelegationChain(_Base):
    """Delegation chain for an agent."""

    agent_id: str | None = None
    chain: list[dict[str, Any]] = Field(default_factory=list)
