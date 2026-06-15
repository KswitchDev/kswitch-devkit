// Package localpdp provides in-process Cedar policy evaluation for the Go SDK.
//
// LocalDecision mirrors Python LocalDecision and TypeScript LocalDecision exactly.
// Outcome values: "allow" | "deny" | "conditional"
//   - allow / deny: resolved locally, no server call needed
//   - conditional:  must escalate to the server enforcement endpoint
package localpdp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const EvaluationMode = "LOCAL_RUNTIME_GO"

// LocalObligation is a typed obligation attached to a local decision.
// Mirrors Python/TypeScript obligation dict shape.
type LocalObligation struct {
	Type           string         `json:"type"`
	ObligationType string         `json:"obligation_type"`
	Level          string         `json:"level,omitempty"`
	Detail         string         `json:"detail,omitempty"`
	Parameters     map[string]any `json:"parameters,omitempty"`
}

// LocalOutputPolicy mirrors the OutputPolicy shape used by Python and TypeScript.
type LocalOutputPolicy struct {
	Mode                   string   `json:"mode"`
	MaskingClassifications []string `json:"masking_classifications"`
}

// LocalDecision is the result of a local PDP evaluation.
// Mirrors Python LocalDecision and TypeScript LocalDecision.
type LocalDecision struct {
	Outcome               string             `json:"outcome"` // "allow" | "deny" | "conditional"
	Reason                string             `json:"reason"`
	Allowed               bool               `json:"allowed"`
	DecisionPath          []string           `json:"decision_path"`
	Obligations           []LocalObligation  `json:"obligations"`
	OutputPolicy          *LocalOutputPolicy `json:"output_policy,omitempty"`
	EnforcementID         string             `json:"enforcement_id"`
	EvaluationMode        string             `json:"evaluation_mode"` // "LOCAL_RUNTIME_GO"
	BundleVersion         string             `json:"bundle_version"`
	ContextPackID         string             `json:"context_pack_id"`
	ContextSnapshotID     string             `json:"context_snapshot_id,omitempty"`
	ContextSnapshotDigest string             `json:"context_snapshot_digest,omitempty"`
	ContextSnapshot       map[string]any     `json:"context_snapshot,omitempty"`
	DecisionExplanation   map[string]any     `json:"decision_explanation,omitempty"`
	RiskTier              string             `json:"risk_tier"`
	AgentID               string             `json:"agent_id"`
	MCPServerID           string             `json:"mcp_server_id"`
	ToolName              string             `json:"tool_name"`
	EvaluatedAt           int64              `json:"evaluated_at"` // Unix timestamp
}

// IsLocal returns true if the outcome is allow or deny (no server call needed).
func (d *LocalDecision) IsLocal() bool {
	return d.Outcome == "allow" || d.Outcome == "deny"
}

// NeedsEscalation returns true if the outcome is conditional (server call required).
func (d *LocalDecision) NeedsEscalation() bool {
	return d.Outcome == "conditional"
}

// decisionOpts holds the fields for building a LocalDecision.
type decisionOpts struct {
	outcome       string
	reason        string
	allowed       bool
	decisionPath  []string
	obligations   []LocalObligation
	outputPolicy  *LocalOutputPolicy
	bundleVersion string
	contextPackID string
	riskTier      string
	agentID       string
	mcpServerID   string
	toolName      string
	extra         map[string]any
}

// makeDecision builds a LocalDecision with a fresh enforcement ID and timestamp.
func makeDecision(o decisionOpts) *LocalDecision {
	obligations := o.obligations
	if obligations == nil {
		obligations = []LocalObligation{}
	}
	riskTier := o.riskTier
	if riskTier == "" {
		riskTier = "medium"
	}
	o.riskTier = riskTier
	enforcementID := uuid.New().String()
	evaluatedAt := time.Now().Unix()
	contextSnapshotID, contextSnapshotDigest, contextSnapshot, decisionExplanation := buildDecisionEvidence(o, enforcementID, evaluatedAt)
	return &LocalDecision{
		Outcome:               o.outcome,
		Reason:                o.reason,
		Allowed:               o.allowed,
		DecisionPath:          o.decisionPath,
		Obligations:           obligations,
		OutputPolicy:          o.outputPolicy,
		EnforcementID:         enforcementID,
		EvaluationMode:        EvaluationMode,
		BundleVersion:         o.bundleVersion,
		ContextPackID:         o.contextPackID,
		ContextSnapshotID:     contextSnapshotID,
		ContextSnapshotDigest: contextSnapshotDigest,
		ContextSnapshot:       contextSnapshot,
		DecisionExplanation:   decisionExplanation,
		RiskTier:              riskTier,
		AgentID:               o.agentID,
		MCPServerID:           o.mcpServerID,
		ToolName:              o.toolName,
		EvaluatedAt:           evaluatedAt,
	}
}

const (
	policyContextSchemaVersion     = "kswitch.policy_context.v1"
	decisionExplanationSchema      = "kswitch.decision_explanation.v1"
	maxEvidenceDecisionPathEntries = 16
	maxEvidenceStringBytes         = 96
)

func buildDecisionEvidence(o decisionOpts, enforcementID string, evaluatedAt int64) (string, string, map[string]any, map[string]any) {
	decisionPath := boundedStrings(o.decisionPath, maxEvidenceDecisionPathEntries)
	toolRequest := map[string]any{
		"agent":      digestStatus(o.agentID),
		"mcp_server": digestStatus(o.mcpServerID),
		"tool":       digestStatus(o.toolName),
		"requester":  requesterDigestStatus(o.extra),
	}
	requestHash := sha256Digest(toolRequest)
	contextHash := sha256Digest(map[string]any{
		"bundle_version":  o.bundleVersion,
		"context_pack_id": o.contextPackID,
		"risk_tier":       boundedString(o.riskTier),
	})
	pdpInputHash := sha256Digest(map[string]any{
		"request_hash":  requestHash,
		"context_hash":  contextHash,
		"decision_path": decisionPath,
	})

	seedDigest := sha256Digest(map[string]any{
		"enforcement_id": enforcementID,
		"evaluated_at":   evaluatedAt,
		"outcome":        o.outcome,
		"reason":         o.reason,
		"request_hash":   requestHash,
		"pdp_input_hash": pdpInputHash,
	})
	contextSnapshotID := "pcs_local_" + digestSuffix(seedDigest, 16)

	unavailableOptional := unavailableOptionalSignals(toolRequest)
	sourceStatus := map[string]any{
		"unavailable_optional": unavailableOptional,
		"present_deterministic": []string{
			"identity.agent_id",
			"tool_request.mcp_server_id",
			"policy.decision_path",
			"runtime.risk_tier",
		},
	}
	if len(unavailableOptional) == 0 {
		sourceStatus["unavailable_optional"] = []string{}
	}

	snapshot := map[string]any{
		"schema_version":      policyContextSchemaVersion,
		"context_snapshot_id": contextSnapshotID,
		"evaluation_mode":     EvaluationMode,
		"policy": map[string]any{
			"bundle_version":  o.bundleVersion,
			"context_pack_id": o.contextPackID,
			"risk_tier":       boundedString(o.riskTier),
			"context_hash":    contextHash,
			"pdp_input_hash":  pdpInputHash,
		},
		"tool_request": mergeMaps(toolRequest, map[string]any{
			"request_hash": requestHash,
		}),
		"replay": map[string]any{
			"request_hash":   requestHash,
			"context_hash":   contextHash,
			"pdp_input_hash": pdpInputHash,
		},
		"source_status": sourceStatus,
		"integrity": map[string]any{
			"binding_state":         "digest_bound_no_append_only_record",
			"enforcement_id_digest": sha256String(enforcementID),
			"snapshot_binding_digest": sha256Digest(map[string]any{
				"context_snapshot_id": contextSnapshotID,
				"enforcement_id":      enforcementID,
				"request_hash":        requestHash,
				"pdp_input_hash":      pdpInputHash,
			}),
		},
	}
	contextSnapshotDigest := sha256Digest(snapshot)

	explanation := map[string]any{
		"schema_version":      decisionExplanationSchema,
		"context_snapshot_id": contextSnapshotID,
		"outcome":             boundedString(o.outcome),
		"reason":              boundedString(o.reason),
		"evaluation_mode":     EvaluationMode,
		"decision_path":       decisionPath,
		"policy_attribution": map[string]any{
			"bundle_version_digest":  digestOrUnavailable(o.bundleVersion),
			"context_pack_id_digest": digestOrUnavailable(o.contextPackID),
			"matched_policy_ids":     []string{},
			"attribution_state":      "unavailable_until_per_policy_eval",
			"attribution_method":     "local_pdp_aggregate_bundle_without_per_policy_eval",
		},
	}
	if o.outcome == "deny" {
		explanation["deny_reason"] = localDenyReason(o.reason)
	}
	if o.outcome == "conditional" {
		explanation["escalation_hint"] = "step_up_required"
	}
	if len(unavailableOptional) > 0 {
		explanation["unavailable_optional_signals"] = unavailableOptional
	}
	if o.reason == "context_pack_unavailable" || o.reason == "context_pack_miss" {
		explanation["missing_required_signals"] = []string{"context_pack"}
	}

	return contextSnapshotID, contextSnapshotDigest, snapshot, explanation
}

func digestStatus(value string) map[string]any {
	if value == "" {
		return map[string]any{"status": "unavailable_optional"}
	}
	return map[string]any{
		"status": "present_deterministic",
		"digest": sha256String(value),
	}
}

func digestOrUnavailable(value string) string {
	if value == "" {
		return "unavailable_optional"
	}
	return sha256String(value)
}

func requesterDigestStatus(extra map[string]any) map[string]any {
	if extra == nil {
		return map[string]any{"status": "unavailable_optional"}
	}
	for _, key := range []string{"requester", "requester_id", "requestor", "requestor_id", "user", "user_id", "actor", "actor_id", "subject", "subject_id"} {
		if value, ok := extra[key]; ok {
			return map[string]any{
				"status": "present_deterministic",
				"digest": sha256Digest(value),
			}
		}
	}
	return map[string]any{"status": "unavailable_optional"}
}

func unavailableOptionalSignals(toolRequest map[string]any) []string {
	signals := []string{}
	for _, key := range []string{"agent", "mcp_server", "tool", "requester"} {
		value, ok := toolRequest[key].(map[string]any)
		if ok && value["status"] == "unavailable_optional" {
			signals = append(signals, key)
		}
	}
	return signals
}

func localDenyReason(reason string) string {
	switch reason {
	case "agent_revoked", "revocation_sync_stale":
		return "GOVERNANCE"
	case "agent_inactive", "agent_suspended", "context_pack_unavailable":
		return "VALIDATION"
	case "policy_denied":
		return "POLICY"
	default:
		return "UNKNOWN"
	}
}

func boundedStrings(values []string, maxEntries int) []string {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if len(values) > maxEntries {
		values = values[:maxEntries]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, boundedString(value))
	}
	return out
}

func boundedString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxEvidenceStringBytes {
		return value
	}
	return value[:maxEvidenceStringBytes]
}

func mergeMaps(left, right map[string]any) map[string]any {
	out := make(map[string]any, len(left)+len(right))
	for k, v := range left {
		out[k] = v
	}
	for k, v := range right {
		out[k] = v
	}
	return out
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + fmt.Sprintf("%x", sum)
}

func sha256Digest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		data = []byte(fmt.Sprintf("%v", value))
	}
	sum := sha256.Sum256(data)
	return "sha256:" + fmt.Sprintf("%x", sum)
}

func digestSuffix(digest string, length int) string {
	suffix := strings.TrimPrefix(digest, "sha256:")
	if len(suffix) <= length {
		return suffix
	}
	return suffix[:length]
}
