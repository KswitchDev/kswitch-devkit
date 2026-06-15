// ── Main client ─────────────────────────────────────────────────────────────
export { KSwitchClient } from "./client.js";

// ── Auth ────────────────────────────────────────────────────────────────────
export { TokenManager } from "./auth.js";
export type { TokenConfig } from "./auth.js";

// ── Interceptor (PR-05/06 + Local Runtime) ───────────────────────────────────
// Governed invocation path — use KSwitchInterceptor.checkAndInvoke() as the
// primary public API. Raw helpers (enforcePreInvokeObligations, applyOutputPolicy)
// are intentionally NOT exported; they are internal to the interceptor pipeline.
// If you need them for advanced/test use, import directly from "./interceptor.js"
// and annotate the call site with: // kswitch: allow-unsafe
export {
  KSwitchInterceptor,
  KSwitchEnforcementError,
  KSwitchObligationError,
  OutputDeniedError,
  getActiveExecutionToken,
} from "./interceptor.js";
export type { CheckAndInvokeOptions } from "./interceptor.js";

// ── Execution Tokens (L2 Hardening Phase 1) ──────────────────────────────────
export { KSwitchTokenIssuer, KSwitchTokenValidator } from "./tokens/index.js";
export type { IssuerDecision, IssueOptions, ValidationResult } from "./tokens/index.js";

// ── Local PDP (TypeScript Local Runtime) ────────────────────────────────────
// LocalPDPEvaluator is the governed evaluation surface.
// getEvaluator() returns the module singleton for advanced/test usage.
// deriveOutputPolicy is an internal helper — NOT exported from public surface.
export { LocalPDPEvaluator, getEvaluator } from "./local_pdp/evaluator.js";
export type {
  LocalDecision,
  LocalDecisionOutcome,
  LocalObligation,
  LocalOutputPolicy,
} from "./local_pdp/types.js";

// ── Bundle cache ─────────────────────────────────────────────────────────────
export {
  LocalBundleCache,
  BundleNotAvailableError,
  loadCurrentBundle,
  getBundleCache,
  isBundleStale,
  bundleHasTool,
  bundleRequiresHumanApproval,
} from "./bundle/local_cache.js";
export type { LocalBundle } from "./bundle/local_cache.js";

// ── Context cache ────────────────────────────────────────────────────────────
export {
  LocalContextCache,
  ContextNotAvailableError,
  loadContextPack,
  getContextCache,
  isContextPackActive,
  isContextPackStale,
} from "./context/local_cache.js";
export type { LocalContextPack } from "./context/local_cache.js";

// ── Revocation cache + sync ──────────────────────────────────────────────────
export {
  LocalRevocationCache,
  getRevocationCache,
} from "./revocation/cache.js";
export {
  RevocationSyncWorker,
  startSyncWorker,
  stopSyncWorker,
  getSyncWorker,
} from "./revocation/sync.js";
export type { SyncWorkerConfig } from "./revocation/sync.js";

// ── Audit ────────────────────────────────────────────────────────────────────
export {
  AuditEmitter,
  getAuditEmitter,
  emitDecisionEvent,
  buildAuditEvent,
} from "./audit/emitter.js";
export type { AuditEvent } from "./audit/emitter.js";
export {
  AuditSender,
  getAuditSender,
  startAuditSender,
  stopAuditSender,
} from "./audit/sender.js";

// ── Sub-API classes ─────────────────────────────────────────────────────────
export { GovernanceAPI } from "./governance.js";
export { PolicyAPI } from "./policy.js";
export { IdentityAPI } from "./identity.js";
export { ComplianceAPI } from "./compliance.js";
export { KillSwitchAPI } from "./killswitch.js";
export { EventsAPI } from "./events.js";
export { CatalogAPI } from "./catalog.js";
export { EnforcementAPI } from "./enforcement.js";
export { AuthZenAPI } from "./authzen.js";
export { ServiceAPI, SERVICE_BASE } from "./service.js";
export type { FetchRequest, PolicyCheckRequest, SearchRequest } from "./service.js";

// ── WIMSE delegation chains ─────────────────────────────────────────────────
export {
  WIMSEAssertion,
  WIMSEChainBuilder,
  MAX_PURPOSE_LEN,
  MAX_RESOURCE_CONTEXT_LEN,
  MAX_WORKFLOW_ID_LEN,
  MAX_CHAIN_DEPTH,
  MAX_ASSERTION_TTL_SECONDS,
  MAX_CHAIN_HEADER_BYTES,
} from "./wimse.js";
export type { WIMSEAssertionFields, WIMSEHopOptions } from "./wimse.js";

// ── SPIRE workload identity ─────────────────────────────────────────────────
export { fetchSvid, SPIREUnavailableError } from "./spire.js";
export type { SVIDBundle } from "./spire.js";

// ── Errors ──────────────────────────────────────────────────────────────────
export {
  KSwitchError,
  AuthError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
  NetworkError,
} from "./errors.js";

// ── Types ───────────────────────────────────────────────────────────────────
export type {
  KSwitchConfig,
  RequestOptions,
  PaginatedResponse,
  RecordType,
  AgentStatus,
  RiskTier,
  Agent,
  MCPServer,
  MCPDeclaration,
  MCPTool,
  MCPResource,
  MCPPrompt,
  SandboxAttestation,
  GateResult,
  Skill,
  Tool,
  SyncSource,
  Policy,
  PolicyDecision,
  PolicyEvaluation,
  AuthZenSubject,
  AuthZenResource,
  AuthZenAction,
  AuthZenEvaluationRequest,
  AuthZenEvaluationResponse,
  AuthZenSearchRequest,
  KillSwitchRequest,
  BlanketKillRequest,
  KillSwitchRecord,
  KillSwitchViolation,
  ToxicComboRule,
  ToxicComboViolation,
  ToxicComboDashboard,
  BoundaryCrossing,
  BoundaryAnalysis,
  SpiffeIdentity,
  ServiceIdentity,
  TrustDomain,
  IdentityStats,
  GovernanceEvent,
  EventStats,
  AuditEntry,
  ScanRun,
  ScanFinding,
  GraphStatus,
  BlastRadius,
  FleetAgent,
  FleetHealth,
  HealthStatus,
  Dashboard,
  DelegationRequest,
  DelegationChain,
  MCPCallEnforcementRequest,
  MCPCallEnforcementResponse,
  EnforcementObligation,
  EnforcementViolation,
  OutputPolicy,
  DecisionExplanationOutcome,
  PolicyContextSnapshot,
  DecisionExplanation,
  DecisionContextEvidence,
  OnboardRepo,
  TicketLink,
} from "./types.js";
