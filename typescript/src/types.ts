// ── Configuration ───────────────────────────────────────────────────────────

export interface KSwitchConfig {
  /** Base URL of the KSwitch API (e.g. "https://kswitch.example.com") */
  baseUrl: string;

  /** Static Bearer token. Mutually exclusive with clientId/clientSecret. */
  token?: string;

  /** Keycloak / Logto client ID for M2M token exchange. */
  clientId?: string;

  /** Keycloak / Logto client secret for M2M token exchange. */
  clientSecret?: string;

  /** Keycloak / Logto token endpoint URL. Overrides keycloakRealm-based derivation. */
  tokenEndpoint?: string;

  /** Keycloak base URL (e.g. "https://keycloak.example.com"). */
  keycloakUrl?: string;

  /** Keycloak realm name. Defaults to "kswitch". */
  keycloakRealm?: string;

  /** OAuth2 resource / audience parameter. */
  resource?: string;

  /** Request timeout in milliseconds. Defaults to 30000. */
  timeout?: number;

  /** Number of retries on 503 / network error. Defaults to 3. */
  retries?: number;

  /** Base backoff in milliseconds for exponential retry. Defaults to 1000. */
  backoffMs?: number;
}

export interface RequestOptions {
  params?: Record<string, string | number | boolean | undefined>;
  json?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

// ── Paginated Response ──────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// ── Agent / MCP Server ──────────────────────────────────────────────────────

export type RecordType = "AGENT" | "MCP_SERVER";

export type AgentStatus =
  | "pending_review"
  | "approved"
  | "active"
  | "suspended"
  | "decommissioned";

export type RiskTier = "tier_1" | "tier_2" | "tier_3";

export interface Agent {
  id: string;
  display_name: string;
  record_type: RecordType;
  status: AgentStatus;
  risk_tier?: RiskTier;
  owning_division?: string;
  owning_team?: string;
  environment?: string;
  description?: string;
  connected_mcps?: string[];
  skills?: string[];
  permissions?: string[];
  data_classification?: string;
  hosting_provider?: string;
  framework?: string;
  repo_url?: string;
  approved_by?: string;
  approved_at?: string;
  created_at?: string;
  updated_at?: string;
  last_active_at?: string;
  jira_ticket?: string;
  snow_ticket?: string;
  metadata?: Record<string, unknown>;
}

export interface MCPServer extends Agent {
  record_type: "MCP_SERVER";
  declaration?: MCPDeclaration;
  gate_status?: Record<string, GateResult>;
  consumer_count?: number;
}

export interface MCPDeclaration {
  name: string;
  version?: string;
  tools?: MCPTool[];
  resources?: MCPResource[];
  prompts?: MCPPrompt[];
  sandbox?: SandboxAttestation;
}

export interface MCPTool {
  name: string;
  description?: string;
  input_schema?: Record<string, unknown>;
}

export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mime_type?: string;
}

export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: Record<string, unknown>[];
}

export interface SandboxAttestation {
  sandbox_type: string;
  isolation_level?: string;
  attested_at?: string;
}

export interface GateResult {
  gate: string;
  passed: boolean;
  details?: string;
  evaluated_at?: string;
}

// ── Skills & Tools Catalog ──────────────────────────────────────────────────

export interface Skill {
  id: string;
  name: string;
  display_name?: string;
  description?: string;
  category?: string;
  risk_level?: string;
  source?: string;
  status?: string;
  created_at?: string;
}

export interface Tool {
  id: string;
  name: string;
  display_name?: string;
  description?: string;
  mcp_server_id?: string;
  input_schema?: Record<string, unknown>;
  category?: string;
  risk_level?: string;
  status?: string;
  created_at?: string;
}

export interface SyncSource {
  id: string;
  name: string;
  source_type: string;
  url?: string;
  status?: string;
  last_synced_at?: string;
  created_at?: string;
}

// ── Policies ────────────────────────────────────────────────────────────────

export interface Policy {
  id: string;
  name: string;
  description?: string;
  cedar_text?: string;
  rego_text?: string;
  policy_type?: string;
  effect?: "permit" | "forbid";
  scope?: Record<string, unknown>;
  status?: string;
  created_at?: string;
  updated_at?: string;
}

export interface PolicyDecision {
  decision: boolean;
  context?: Record<string, unknown>;
}

export interface PolicyEvaluation {
  id?: string;
  principal?: string;
  action?: string;
  resource?: string;
  decision: boolean;
  policies_matched?: string[];
  evaluated_at?: string;
}

// ── AuthZen ─────────────────────────────────────────────────────────────────

export interface AuthZenSubject {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenResource {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenAction {
  name: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenEvaluationRequest {
  subject: AuthZenSubject;
  resource: AuthZenResource;
  action: AuthZenAction;
  context?: Record<string, unknown>;
}

export interface AuthZenEvaluationResponse {
  decision: boolean;
  context?: Record<string, unknown>;
}

export interface AuthZenSearchRequest {
  subject?: AuthZenSubject;
  resource?: AuthZenResource;
  action?: AuthZenAction;
}

// ── Kill Switch ─────────────────────────────────────────────────────────────

export interface KillSwitchRequest {
  agent_ids?: string[];
  scope?: string;
  reason: string;
  initiated_by: string;
}

export interface BlanketKillRequest {
  reason: string;
  initiated_by: string;
  scope?: string;
}

export interface KillSwitchRecord {
  id: string;
  agent_ids?: string[];
  scope?: string;
  reason?: string;
  initiated_by?: string;
  activated_at?: string;
  status?: string;
}

export interface KillSwitchViolation {
  id: string;
  agent_id: string;
  violation_type?: string;
  details?: string;
  detected_at?: string;
}

// ── Toxic Combos ────────────────────────────────────────────────────────────

export interface ToxicComboRule {
  id: string;
  name: string;
  description?: string;
  skill_a?: string;
  skill_b?: string;
  permission_a?: string;
  permission_b?: string;
  severity: "critical" | "high" | "medium" | "low";
  is_waivable?: boolean;
  status?: "active" | "disabled";
  created_at?: string;
}

export interface ToxicComboViolation {
  rule_id: string;
  rule_name: string;
  severity: string;
  details?: string;
}

export interface ToxicComboDashboard {
  total_violations: number;
  clean_agents: number;
  violation_breakdown?: Record<string, number>;
  last_evaluated_at?: string;
}

// ── Boundary Analysis ───────────────────────────────────────────────────────

export interface BoundaryCrossing {
  boundary_type: string;
  violation: string;
  details?: string;
  severity?: string;
}

export interface BoundaryAnalysis {
  agent_id: string;
  crossings: BoundaryCrossing[];
  analyzed_at?: string;
}

// ── Identity / SPIFFE ───────────────────────────────────────────────────────

export interface SpiffeIdentity {
  spiffe_id: string;
  trust_domain: string;
  svid_serial?: string;
  issued_at?: string;
  expires_at?: string;
  status?: string;
}

export interface ServiceIdentity {
  id: string;
  agent_id: string;
  identity_type: string;
  identity_value?: string;
  status?: string;
  expires_at?: string;
  created_at?: string;
}

export interface TrustDomain {
  name: string;
  description?: string;
  ca_bundle?: string;
  status?: string;
  created_at?: string;
}

export interface IdentityStats {
  total: number;
  active: number;
  expiring_soon: number;
  revoked: number;
}

// ── Events ──────────────────────────────────────────────────────────────────

export interface GovernanceEvent {
  id: string;
  event_type: string;
  agent_id?: string;
  payload?: Record<string, unknown>;
  status: "pending" | "delivered" | "failed" | "dead_letter";
  created_at?: string;
  delivered_at?: string;
}

export interface EventStats {
  pending: number;
  delivered: number;
  failed: number;
  dead_letter: number;
  delivery_rate?: number;
}

// ── Audit ───────────────────────────────────────────────────────────────────

export interface AuditEntry {
  id?: string;
  agent_id: string;
  action: string;
  actor?: string;
  details?: Record<string, unknown>;
  created_at?: string;
}

// ── Scanner ─────────────────────────────────────────────────────────────────

export interface ScanRun {
  id: string;
  repo_url?: string;
  status?: string;
  findings_count?: number;
  started_at?: string;
  completed_at?: string;
}

export interface ScanFinding {
  id: string;
  scan_id: string;
  finding_type?: string;
  severity?: string;
  file_path?: string;
  details?: string;
  status?: string;
}

// ── Graph ───────────────────────────────────────────────────────────────────

export interface GraphStatus {
  node_count: number;
  edge_count: number;
  last_rebuilt_at?: string;
}

export interface BlastRadius {
  affected_agents: string[];
  affected_mcps: string[];
  total_impact: number;
}

// ── Fleet ───────────────────────────────────────────────────────────────────

export interface FleetAgent {
  agent_id: string;
  status: string;
  last_heartbeat?: string;
  version?: string;
}

export interface FleetHealth {
  total_agents: number;
  healthy: number;
  unhealthy: number;
  agents: FleetAgent[];
}

// ── Health ───────────────────────────────────────────────────────────────────

export interface HealthStatus {
  status: string;
  version?: string;
  uptime?: number;
  database?: string;
}

// ── Dashboard ────────────────────────────────────────────────────────────────

export interface Dashboard {
  total_agents: number;
  total_mcps: number;
  agents_by_status: Record<string, number>;
  risk_tier_breakdown: Record<string, number>;
  recent_events?: GovernanceEvent[];
}

// ── Delegation ───────────────────────────────────────────────────────────────

export interface DelegationRequest {
  delegate_to: string;
  permissions: string[];
  expires_at?: string;
  reason?: string;
}

export interface DelegationChain {
  chain: Array<{
    from: string;
    to: string;
    permissions: string[];
    created_at?: string;
  }>;
}

// ── Enforcement ──────────────────────────────────────────────────────────────

export interface MCPCallEnforcementRequest {
  agent_id: string;
  mcp_server_id: string;
  tool_name: string;
  arguments?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

/** Typed obligation returned in enforcement decisions. */
export interface EnforcementObligation {
  type: string;
  obligation_type?: string;
  level?: string;
  detail?: string;
  [key: string]: unknown;  // Type-specific parameters (rate limits, classifications, etc.)
}

/** Typed violation returned in enforcement decisions. */
export interface EnforcementViolation {
  type: string;
  violation_type?: string;
  detail?: string;
  severity?: string;
  [key: string]: unknown;
}

/** Output policy telling caller how to handle tool response. */
export interface OutputPolicy {
  mode: string;  // "allow_raw"|"mask_fields"|"summarize_only"|"truncate"|"deny_export"|"require_release"
  masking_classifications?: string[];
  max_output_bytes?: number;
  requires_human_release?: boolean;
}

export type DecisionExplanationOutcome = "allow" | "deny" | "conditional";

export interface PolicyContextSnapshot {
  schema_version?: "kswitch.policy_context.v1" | string;
  context_snapshot_id?: string;
  decision_id?: string;
  tenant_id?: string;
  agent_id?: string;
  agent_session_id?: string | null;
  mode?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  identity?: Record<string, unknown>;
  runtime?: Record<string, unknown>;
  active_artefacts?: Array<Record<string, unknown>>;
  tool_request?: Record<string, unknown>;
  data_context?: Record<string, unknown>;
  graph_context?: Record<string, unknown>;
  source_status?: Record<string, string[]>;
  replay?: Record<string, unknown>;
  integrity?: Record<string, unknown>;
}

export interface DecisionExplanation {
  schema_version?: "kswitch.decision_explanation.v1" | string;
  decision_id?: string;
  context_snapshot_id?: string;
  outcome?: DecisionExplanationOutcome;
  reason?: string;
  deny_reason?: string;
  escalation_hint?: string;
  evaluation_mode?: string;
  policy_enforcement_mode?: string;
  reason_summary?: string;
  policy_attribution?: Record<string, unknown>;
  contributing_signals?: string[];
  missing_required_signals?: string[];
  stale_signals?: string[];
  advisory_signals_ignored_for_allow?: string[];
  next_safe_actions?: string[];
}

export interface DecisionContextEvidence {
  context_snapshot_id?: string;
  context_snapshot_digest?: string;
  context_snapshot?: PolicyContextSnapshot;
  decision_explanation?: DecisionExplanation;
}

/** Universal enforcement decision (decision contract v1.0). */
export interface MCPCallEnforcementResponse extends DecisionContextEvidence {
  allowed: boolean;
  reason?: string;
  outcome?: string;
  decision_path?: string[];
  obligations?: EnforcementObligation[];
  violations?: EnforcementViolation[];
  escalation_hint?: string;
  output_policy?: OutputPolicy;
  contract_version?: string;
  evaluation_mode?: string;
  bundle_version?: string;
  context_pack_id?: string;
  policy_set_hash?: string;
  status_recheck?: string;
  enforcement_id?: string;  // PR-05: obligation tracking ID
  _timing?: Record<string, number>;
  // Legacy fields
  policies_evaluated?: string[];
}

// ── Onboard ──────────────────────────────────────────────────────────────────

export interface OnboardRepo {
  id: string;
  url: string;
  branch?: string;
  status?: string;
  created_at?: string;
}

// ── Ticket ───────────────────────────────────────────────────────────────────

export interface TicketLink {
  system: string;
  ticket_id: string;
  url?: string;
  status?: string;
}
