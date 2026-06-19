"""KSwitch.ai Python SDK — Agent governance, policy, and identity management.

Quick start::

    from kswitch import KSwitchClient

    client = KSwitchClient(
        base_url="https://localhost:5001",
        token="your-bearer-token",
    )

    # Register an agent
    agent = client.governance.register_agent(display_name="my-agent")

    # Evaluate toxic combos
    result = client.compliance.evaluate_toxic_combos(agent.id)

    # Check authorization
    decision = client.authzen.evaluate(
        subject={"type": "agent", "id": agent.id},
        resource={"type": "tool", "id": "read-database"},
        action={"name": "invoke"},
    )
"""

from .__version__ import __version__

from .client import KSwitchAsyncClient, KSwitchClient
from .service import ServiceAPI, ServiceAsyncAPI
from .interceptor import (
    KSwitchInterceptor,
    KSwitchAsyncInterceptor,
    KSwitchEnforcementError,
    KSwitchObligationError,
    OutputDeniedError,
)
from .invoke import KSwitchRuntime, GovernedTool
from .local_pdp.evaluator import LocalPDPEvaluator, LocalDecision
from .bundle.local_cache import LocalBundleCache, load_current_bundle, BundleNotAvailableError, get_bundle_cache
from .context.local_cache import LocalContextCache, load_context_pack, ContextNotAvailableError, LocalContextPack, get_context_cache
from .revocation.cache import LocalRevocationCache, get_revocation_cache
from .audit.emitter import AuditEmitter, emit_decision_event, get_audit_emitter
from .obo import (
    KSWITCH_ENFORCEMENT_DECISION_HEADER,
    KSWITCH_ENFORCEMENT_ID_HEADER,
    KSWITCH_POLICY_BUNDLE_HEADER,
    KSWITCH_POLICY_DECISION_HEADER,
    KSWITCH_POLICY_EVIDENCE_HEADER,
    OBO_ACTOR_CHAIN_HEADER,
    OBO_REQUESTED_SCOPE_HEADER,
    OBO_SENDER_CONSTRAINT_HEADER,
    PolicyEngineEvidence,
    PolicyEvidence,
    actor_chain_from_headers,
    build_actor_chain,
    build_obo_headers,
    build_sender_constraint,
    kswitch_decision_from_headers,
    policy_evidence_from_headers,
    sender_constraint_from_headers,
)
from .exceptions import (
    AuthError,
    ConflictError,
    ForbiddenError,
    KSwitchError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .models import (
    Agent,
    ApprovalCriteria,
    AuthZenBatchResponse,
    AuthZenDecision,
    AuthZenRequest,
    AuthZenSearchResult,
    AutoKillConfig,
    BlanketKillRequest,
    BlastRadius,
    BoundaryAnalysis,
    Dashboard,
    DelegationChain,
    DelegationRequest,
    DecisionExplanation,
    EnforcementDecision,
    EnforcementRequest,
    Event,
    EventStats,
    FleetAgent,
    FleetHealth,
    FleetRiskSummary,
    GateResult,
    GateStatus,
    HealthStatus,
    IdentityStats,
    KillSwitchHistory,
    KillSwitchResult,
    MCPServer,
    PaginatedResponse,
    Policy,
    PolicyContextSnapshot,
    PolicyDecision,
    PolicyEvaluation,
    PolicyValidation,
    RiskScore,
    ServiceIdentity,
    Skill,
    SpiffeIdentity,
    SyncSource,
    Tool,
    ToxicComboDashboard,
    ToxicComboResult,
    ToxicComboRule,
    ToxicComboViolation,
    TrustDomain,
)

__all__ = [
    "__version__",
    # Clients
    "KSwitchClient",
    "KSwitchAsyncClient",
    "ServiceAPI",
    "ServiceAsyncAPI",
    # Interceptors (PR-05/06)
    "KSwitchInterceptor",
    "KSwitchAsyncInterceptor",
    "KSwitchEnforcementError",
    "KSwitchObligationError",
    "OutputDeniedError",
    # Runtime (Phase 2 local PDP)
    "KSwitchRuntime",
    "GovernedTool",
    "LocalPDPEvaluator",
    "LocalDecision",
    "LocalBundleCache",
    "load_current_bundle",
    "BundleNotAvailableError",
    "get_bundle_cache",
    "LocalContextCache",
    "load_context_pack",
    "ContextNotAvailableError",
    "LocalContextPack",
    "get_context_cache",
    "LocalRevocationCache",
    "get_revocation_cache",
    "AuditEmitter",
    "emit_decision_event",
    "get_audit_emitter",
    "OBO_ACTOR_CHAIN_HEADER",
    "OBO_REQUESTED_SCOPE_HEADER",
    "OBO_SENDER_CONSTRAINT_HEADER",
    "KSWITCH_ENFORCEMENT_DECISION_HEADER",
    "KSWITCH_ENFORCEMENT_ID_HEADER",
    "KSWITCH_POLICY_DECISION_HEADER",
    "KSWITCH_POLICY_EVIDENCE_HEADER",
    "KSWITCH_POLICY_BUNDLE_HEADER",
    "PolicyEngineEvidence",
    "PolicyEvidence",
    "actor_chain_from_headers",
    "build_actor_chain",
    "build_obo_headers",
    "build_sender_constraint",
    "kswitch_decision_from_headers",
    "policy_evidence_from_headers",
    "sender_constraint_from_headers",
    # Exceptions
    "KSwitchError",
    "AuthError",
    "ForbiddenError",
    "NotFoundError",
    "ConflictError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
    # Models
    "Agent",
    "ApprovalCriteria",
    "AuthZenBatchResponse",
    "AuthZenDecision",
    "AuthZenRequest",
    "AuthZenSearchResult",
    "AutoKillConfig",
    "BlanketKillRequest",
    "BlastRadius",
    "BoundaryAnalysis",
    "Dashboard",
    "DelegationChain",
    "DelegationRequest",
    "DecisionExplanation",
    "EnforcementDecision",
    "EnforcementRequest",
    "Event",
    "EventStats",
    "FleetAgent",
    "FleetHealth",
    "FleetRiskSummary",
    "GateResult",
    "GateStatus",
    "HealthStatus",
    "IdentityStats",
    "KillSwitchHistory",
    "KillSwitchResult",
    "MCPServer",
    "PaginatedResponse",
    "Policy",
    "PolicyContextSnapshot",
    "PolicyDecision",
    "PolicyEvaluation",
    "PolicyValidation",
    "RiskScore",
    "ServiceIdentity",
    "Skill",
    "SpiffeIdentity",
    "SyncSource",
    "Tool",
    "ToxicComboDashboard",
    "ToxicComboResult",
    "ToxicComboRule",
    "ToxicComboViolation",
    "TrustDomain",
]
