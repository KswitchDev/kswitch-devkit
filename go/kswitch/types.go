package kswitch

import "time"

// ---------------------------------------------------------------------------
// Core domain types
// ---------------------------------------------------------------------------

// Agent represents a registered agent in the governance system.
type Agent struct {
	ID                 string         `json:"id"`
	DisplayName        string         `json:"display_name"`
	RecordType         string         `json:"record_type"`
	Status             string         `json:"status"`
	RiskTier           string         `json:"risk_tier,omitempty"`
	OwningDivision     string         `json:"owning_division,omitempty"`
	OwningTeam         string         `json:"owning_team,omitempty"`
	ConnectedMCPs      []string       `json:"connected_mcps,omitempty"`
	Skills             []string       `json:"skills,omitempty"`
	Permissions        []string       `json:"permissions,omitempty"`
	DataClassification string         `json:"data_classification,omitempty"`
	Description        string         `json:"description,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	CreatedAt          *time.Time     `json:"created_at,omitempty"`
	UpdatedAt          *time.Time     `json:"updated_at,omitempty"`
}

// MCPServer represents a registered MCP server.
type MCPServer struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	DisplayName   string         `json:"display_name,omitempty"`
	URL           string         `json:"url,omitempty"`
	Status        string         `json:"status"`
	RecordType    string         `json:"record_type"`
	Tools         []Tool         `json:"tools,omitempty"`
	ConsumerCount int            `json:"consumer_count,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     *time.Time     `json:"created_at,omitempty"`
	UpdatedAt     *time.Time     `json:"updated_at,omitempty"`
}

// Tool represents a tool provided by an MCP server.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema,omitempty"`
}

// Policy represents a Cedar governance policy.
type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	PolicyType  string     `json:"policy_type,omitempty"`
	Effect      string     `json:"effect,omitempty"`
	CedarText   string     `json:"cedar_text,omitempty"`
	RegoText    string     `json:"rego_text,omitempty"`
	Status      string     `json:"status,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// PolicyDecision is the result of a policy evaluation.
type PolicyDecision struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// EnforcementRequest is the input for MCP call enforcement.
type EnforcementRequest struct {
	AgentID     string         `json:"agent_id"`
	MCPServerID string         `json:"mcp_server_id"`
	ToolName    string         `json:"tool_name,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

// EnforcementObligation is a requirement the caller must fulfill after ALLOW.
type EnforcementObligation struct {
	Type           string         `json:"type"`
	ObligationType string         `json:"obligation_type,omitempty"`
	Level          string         `json:"level,omitempty"`
	Detail         string         `json:"detail,omitempty"`
	Parameters     map[string]any `json:"-"` // Flattened into top-level keys in JSON
}

// EnforcementViolation is an informational finding attached to decisions.
type EnforcementViolation struct {
	Type          string `json:"type"`
	ViolationType string `json:"violation_type,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Severity      string `json:"severity,omitempty"`
}

// OutputPolicy tells the caller how to handle tool output after ALLOW.
type OutputPolicy struct {
	Mode                   string   `json:"mode"`
	MaskingClassifications []string `json:"masking_classifications,omitempty"`
	MaxOutputBytes         *int     `json:"max_output_bytes,omitempty"`
	RequiresHumanRelease   bool     `json:"requires_human_release,omitempty"`
}

// EnforcementDecision is the universal decision contract (v1.0).
type EnforcementDecision struct {
	Allowed               bool                    `json:"allowed"`
	Reason                string                  `json:"reason,omitempty"`
	RiskTier              string                  `json:"risk_tier,omitempty"`
	Outcome               string                  `json:"outcome,omitempty"`
	DecisionPath          []string                `json:"decision_path,omitempty"`
	Obligations           []EnforcementObligation `json:"obligations,omitempty"`
	Violations            []EnforcementViolation  `json:"violations,omitempty"`
	EscalationHint        string                  `json:"escalation_hint,omitempty"`
	OutputPolicy          *OutputPolicy           `json:"output_policy,omitempty"`
	ContractVersion       string                  `json:"contract_version,omitempty"`
	EvaluationMode        string                  `json:"evaluation_mode,omitempty"`
	BundleVersion         string                  `json:"bundle_version,omitempty"`
	ContextPackID         string                  `json:"context_pack_id,omitempty"`
	ContextSnapshotID     string                  `json:"context_snapshot_id,omitempty"`
	ContextSnapshotDigest string                  `json:"context_snapshot_digest,omitempty"`
	ContextSnapshot       map[string]any          `json:"context_snapshot,omitempty"`
	DecisionExplanation   map[string]any          `json:"decision_explanation,omitempty"`
	PolicySetHash         string                  `json:"policy_set_hash,omitempty"`
	StatusRecheck         string                  `json:"status_recheck,omitempty"`
	EnforcementID         string                  `json:"enforcement_id,omitempty"` // PR-05: obligation tracking
	Timing                map[string]float64      `json:"_timing,omitempty"`
}

// PolicyEvaluation records a past policy evaluation.
type PolicyEvaluation struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id,omitempty"`
	Principal   string     `json:"principal,omitempty"`
	Action      string     `json:"action,omitempty"`
	Resource    string     `json:"resource,omitempty"`
	Decision    string     `json:"decision,omitempty"`
	Policies    []string   `json:"policies,omitempty"`
	EvaluatedAt *time.Time `json:"evaluated_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

// SPIFFEIdentity represents a SPIFFE identity for an agent.
type SPIFFEIdentity struct {
	SPIFFEID    string     `json:"spiffe_id"`
	AgentID     string     `json:"agent_id"`
	TrustDomain string     `json:"trust_domain,omitempty"`
	Status      string     `json:"status,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// TrustDomain represents a configured trust domain.
type TrustDomain struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
}

// IdentityStats contains identity system statistics.
type IdentityStats struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Expiring int `json:"expiring"`
	Revoked  int `json:"revoked"`
}

// RotationStatus contains identity rotation scheduler status.
type RotationStatus struct {
	Status       string     `json:"status"`
	LastRotation *time.Time `json:"last_rotation,omitempty"`
	NextRotation *time.Time `json:"next_rotation,omitempty"`
	PendingCount int        `json:"pending_count,omitempty"`
}

// ---------------------------------------------------------------------------
// Compliance / Toxic Combos
// ---------------------------------------------------------------------------

// ToxicComboRule defines a toxic skill/permission combination rule.
type ToxicComboRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Skills      []string `json:"skills,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Waivable    bool     `json:"waivable"`
	Status      string   `json:"status,omitempty"`
}

// ToxicComboViolation is a single violation found during evaluation.
type ToxicComboViolation struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Details  string `json:"details,omitempty"`
}

// ToxicComboDashboard summarises the fleet toxic combo status.
type ToxicComboDashboard struct {
	TotalViolations int            `json:"total_violations"`
	CleanAgents     int            `json:"clean_agents"`
	BySeverity      map[string]int `json:"by_severity,omitempty"`
	ErrorRate       float64        `json:"error_rate,omitempty"`
	LastEvaluation  *time.Time     `json:"last_evaluation,omitempty"`
}

// BoundaryAnalysis contains boundary crossing analysis results.
type BoundaryAnalysis struct {
	AgentID    string             `json:"agent_id"`
	Crossings  []BoundaryCrossing `json:"crossings,omitempty"`
	TotalCount int                `json:"total_count"`
}

// BoundaryCrossing is a single boundary violation.
type BoundaryCrossing struct {
	Type     string `json:"type"`
	From     string `json:"from"`
	To       string `json:"to"`
	Severity string `json:"severity,omitempty"`
	Details  string `json:"details,omitempty"`
}

// FleetRiskSummary is the aggregate risk view for the fleet.
type FleetRiskSummary struct {
	Distribution    map[string]int `json:"distribution,omitempty"`
	TopRisk         []AgentRisk    `json:"top_risk,omitempty"`
	TotalViolations int            `json:"total_violations"`
}

// AgentRisk is a risk assessment result for a single agent.
type AgentRisk struct {
	AgentID    string                `json:"agent_id"`
	RiskScore  int                   `json:"risk_score"`
	RiskLevel  string                `json:"risk_level"`
	Violations []ToxicComboViolation `json:"violations,omitempty"`
	Crossings  []BoundaryCrossing    `json:"crossings,omitempty"`
}

// ---------------------------------------------------------------------------
// Kill Switch
// ---------------------------------------------------------------------------

// KillSwitchRecord represents a kill switch activation.
type KillSwitchRecord struct {
	ID          string     `json:"id"`
	Scope       string     `json:"scope,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	ActivatedBy string     `json:"activated_by,omitempty"`
	AgentIDs    []string   `json:"agent_ids,omitempty"`
	Status      string     `json:"status,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// KillSwitchViolation records a violation of kill switch restrictions.
type KillSwitchViolation struct {
	ID        string     `json:"id"`
	AgentID   string     `json:"agent_id"`
	Details   string     `json:"details,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// BlanketKillRequest represents a pending blanket kill switch request.
type BlanketKillRequest struct {
	ID          string     `json:"id"`
	Reason      string     `json:"reason,omitempty"`
	InitiatedBy string     `json:"initiated_by,omitempty"`
	Approvals   int        `json:"approvals,omitempty"`
	Required    int        `json:"required,omitempty"`
	Status      string     `json:"status,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// GovernanceEvent is an event from the governance outbox.
type GovernanceEvent struct {
	ID        string         `json:"id"`
	EventType string         `json:"event_type"`
	Status    string         `json:"status,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt *time.Time     `json:"created_at,omitempty"`
}

// EventStats contains event outbox delivery statistics.
type EventStats struct {
	Pending      int     `json:"pending"`
	Delivered    int     `json:"delivered"`
	Failed       int     `json:"failed"`
	DeadLetter   int     `json:"dead_letter"`
	DeliveryRate float64 `json:"delivery_rate,omitempty"`
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

// Skill represents a skill catalog entry.
type Skill struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Category    string         `json:"category,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// ToolCatalogEntry represents a tool catalog entry.
type ToolCatalogEntry struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	MCPServerID string         `json:"mcp_server_id,omitempty"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// SyncSource represents a registry sync source.
type SyncSource struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Type   string         `json:"type,omitempty"`
	URL    string         `json:"url,omitempty"`
	Status string         `json:"status,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

// SyncStatus represents registry sync status.
type SyncStatus struct {
	Status   string     `json:"status"`
	LastSync *time.Time `json:"last_sync,omitempty"`
	NextSync *time.Time `json:"next_sync,omitempty"`
	ErrorMsg string     `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

// ScanRun represents a repository scan run.
type ScanRun struct {
	ID        string     `json:"id"`
	Status    string     `json:"status,omitempty"`
	Findings  int        `json:"findings,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// ScanFinding represents a finding from a scan run.
type ScanFinding struct {
	ID      string         `json:"id"`
	ScanID  string         `json:"scan_id"`
	Type    string         `json:"type,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// ScannerStats contains scanner statistics.
type ScannerStats struct {
	TotalScans    int        `json:"total_scans"`
	TotalFindings int        `json:"total_findings"`
	LastScanAt    *time.Time `json:"last_scan_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

// GraphStats contains governance graph statistics.
type GraphStats struct {
	Nodes int            `json:"nodes"`
	Edges int            `json:"edges"`
	Types map[string]int `json:"types,omitempty"`
}

// BlastRadius contains blast radius analysis results.
type BlastRadius struct {
	AgentIDs      []string       `json:"agent_ids"`
	AffectedNodes int            `json:"affected_nodes"`
	Details       map[string]any `json:"details,omitempty"`
}

// ---------------------------------------------------------------------------
// Gate Evaluation
// ---------------------------------------------------------------------------

// GateStatus contains gate evaluation status for an MCP.
type GateStatus struct {
	MCPID  string         `json:"mcp_id"`
	Gates  map[string]any `json:"gates,omitempty"`
	Status string         `json:"status,omitempty"`
}

// ---------------------------------------------------------------------------
// Dashboard / Health
// ---------------------------------------------------------------------------

// Dashboard is the main governance dashboard payload.
type Dashboard struct {
	AgentsByStatus map[string]int `json:"agents_by_status,omitempty"`
	RiskTiers      map[string]int `json:"risk_tiers,omitempty"`
	TotalAgents    int            `json:"total_agents,omitempty"`
	TotalMCPs      int            `json:"total_mcps,omitempty"`
}

// HealthStatus is the API health check response.
type HealthStatus struct {
	Status  string         `json:"status"`
	Version string         `json:"version,omitempty"`
	Uptime  float64        `json:"uptime,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// ---------------------------------------------------------------------------
// AuthZen
// ---------------------------------------------------------------------------

// AuthZenRequest is an authorization evaluation request (OpenID AuthZen PDP).
type AuthZenRequest struct {
	Subject  AuthZenEntity  `json:"subject"`
	Action   AuthZenEntity  `json:"action"`
	Resource AuthZenEntity  `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthZenEntity represents a subject, action, or resource in AuthZen.
type AuthZenEntity struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZenResponse is the AuthZen PDP evaluation response.
type AuthZenResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// AuditEntry is a single entry in an agent's audit trail.
type AuditEntry struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	Action    string         `json:"action"`
	Actor     string         `json:"actor,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	CreatedAt *time.Time     `json:"created_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Generic request / response types
// ---------------------------------------------------------------------------

// PaginatedResponse wraps paginated list results.
type PaginatedResponse[T any] struct {
	Data     []T `json:"data"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Pages    int `json:"pages"`
}

// ListOptions are common query parameters for list endpoints.
type ListOptions struct {
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Status   string `json:"status,omitempty"`
	Search   string `json:"search,omitempty"`
}

// ToParams converts ListOptions into a query parameter map.
func (o *ListOptions) ToParams() map[string]string {
	if o == nil {
		return nil
	}
	p := make(map[string]string)
	if o.Page > 0 {
		p["page"] = itoa(o.Page)
	}
	if o.PageSize > 0 {
		p["page_size"] = itoa(o.PageSize)
	}
	if o.Limit > 0 {
		p["limit"] = itoa(o.Limit)
	}
	if o.Status != "" {
		p["status"] = o.Status
	}
	if o.Search != "" {
		p["search"] = o.Search
	}
	return p
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

// RegisterAgentRequest is the body for registering a new agent.
type RegisterAgentRequest struct {
	DisplayName        string         `json:"display_name"`
	RecordType         string         `json:"record_type,omitempty"`
	RiskTier           string         `json:"risk_tier,omitempty"`
	OwningDivision     string         `json:"owning_division,omitempty"`
	OwningTeam         string         `json:"owning_team,omitempty"`
	Skills             []string       `json:"skills,omitempty"`
	ConnectedMCPs      []string       `json:"connected_mcps,omitempty"`
	DataClassification string         `json:"data_classification,omitempty"`
	Description        string         `json:"description,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// ApproveRequest is the body for approving an agent.
type ApproveRequest struct {
	ApprovedBy string         `json:"approved_by,omitempty"`
	Notes      string         `json:"notes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// SuspendRequest is the body for suspending an agent.
type SuspendRequest struct {
	Reason string `json:"reason,omitempty"`
}

// RegisterMCPRequest is the body for registering an MCP server.
type RegisterMCPRequest struct {
	Name        string         `json:"name"`
	DisplayName string         `json:"display_name,omitempty"`
	URL         string         `json:"url,omitempty"`
	Tools       []Tool         `json:"tools,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// CreatePolicyRequest is the body for creating a Cedar policy.
type CreatePolicyRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	PolicyType  string `json:"policy_type,omitempty"`
	Effect      string `json:"effect,omitempty"`
	CedarText   string `json:"cedar_text,omitempty"`
	RegoText    string `json:"rego_text,omitempty"`
}

// ValidatePolicyRequest validates Cedar policy syntax.
type ValidatePolicyRequest struct {
	CedarText string `json:"cedar_text"`
}

// DuplicatePolicyRequest duplicates an existing policy.
type DuplicatePolicyRequest struct {
	Name string `json:"name"`
}

// AssignSkillsRequest assigns skills to an agent.
type AssignSkillsRequest struct {
	Skills []string `json:"skills"`
}

// ConnectMCPsRequest connects an agent to MCP servers.
type ConnectMCPsRequest struct {
	MCPServerIDs []string `json:"mcp_server_ids"`
}

// LinkTicketRequest links a Jira ticket to an agent.
type LinkTicketRequest struct {
	TicketID  string `json:"ticket_id"`
	TicketURL string `json:"ticket_url,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

// TargetedKillRequest activates a targeted kill switch.
type TargetedKillRequest struct {
	AgentIDs []string `json:"agent_ids"`
	Reason   string   `json:"reason"`
}

// BlanketKillInitiateRequest initiates a blanket kill switch.
type BlanketKillInitiateRequest struct {
	Reason      string `json:"reason"`
	InitiatedBy string `json:"initiated_by,omitempty"`
}

// CreateSPIFFERequest creates a SPIFFE identity for an agent.
type CreateSPIFFERequest struct {
	TrustDomain string         `json:"trust_domain,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// CreateServiceIdentityRequest creates a service identity.
type CreateServiceIdentityRequest struct {
	ServiceName string         `json:"service_name"`
	Type        string         `json:"type,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// TriggerScanRequest triggers a repository scan.
type TriggerScanRequest struct {
	Repository string         `json:"repository,omitempty"`
	Branch     string         `json:"branch,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
}

// AddSyncSourceRequest adds a new sync source.
type AddSyncSourceRequest struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	URL    string         `json:"url,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

// BlastRadiusRequest requests a blast radius analysis.
type BlastRadiusRequest struct {
	AgentIDs []string `json:"agent_ids"`
}

// CleanupRequest triggers maintenance cleanup.
type CleanupRequest struct {
	OlderThanDays int `json:"older_than_days,omitempty"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func itoa(i int) string {
	// Minimal int-to-string without importing strconv in this file;
	// we keep it simple since ListOptions values are small ints.
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
