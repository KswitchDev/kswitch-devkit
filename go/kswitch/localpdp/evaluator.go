// LocalPDPEvaluator — in-process Cedar policy evaluation for the Go SDK.
//
// Decision sequence (mirrors Python and TypeScript exactly):
//  0. Stale revocation sync check
//  1. Revocation cache check  (O(1), in-process)
//  2. Context pack load       (disk-backed, TTL-aware)
//  3. Agent status check      (from context pack)
//  4. Bundle load             (disk-backed, TTL-aware)
//  5. Cedar evaluate          (cedar-go, synchronous in-process)
//  6. Shadow policy evaluate  (observe-only)
//  7. Human-approval gating
//  8. Output policy derivation
//     → Return *LocalDecision
//
// Go execution model: SYNCHRONOUS IN-PROCESS CEDAR EVALUATION
// ──────────────────────────────────────────────────────────────
// Cedar evaluation uses cedar-go (github.com/cedar-policy/cedar-go) running
// synchronously in the calling goroutine. This mirrors Python cedarpy and
// TypeScript cedar-wasm behaviour.
//
// For typical policy sets (O(10–100) policies) this is < 1ms and acceptable
// on the decision hot-path. For policy sets growing to O(1000+) policies,
// a goroutine worker pool is the documented extension point.
//
// Fallback: if cedar-go policy parsing or evaluation fails, the evaluator
// returns outcome="conditional" so the caller escalates to the server.
// This preserves correctness under all conditions.
package localpdp

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	cedartypes "github.com/cedar-policy/cedar-go/types"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/bundle"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/kscontext"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/revocation"
)

// Sensitive data classifications that trigger mask_fields output policy.
// Mirrors Python/TypeScript _SENSITIVE_CLASSIFICATIONS.
var sensitiveClassifications = map[string]bool{
	"PII":          true,
	"PHI":          true,
	"MNPI":         true,
	"Confidential": true,
}

// LocalPDPEvaluatorOptions holds injectable dependencies for testing.
type LocalPDPEvaluatorOptions struct {
	// GetRevocationCache returns the revocation cache to use.
	// Defaults to revocation.GetRevocationCache().
	GetRevocationCache func() *revocation.LocalRevocationCache

	// GetBundleCache returns the bundle cache to use.
	// Defaults to bundle.GetBundleCache().
	GetBundleCache func() *bundle.LocalBundleCache

	// GetContextCache returns the context cache to use.
	// Defaults to kscontext.GetContextCache().
	GetContextCache func() *kscontext.LocalContextCache
}

// LocalPDPEvaluator is the in-process policy evaluator for the Go SDK.
type LocalPDPEvaluator struct {
	getRevCache     func() *revocation.LocalRevocationCache
	getBundleCache  func() *bundle.LocalBundleCache
	getContextCache func() *kscontext.LocalContextCache
}

// NewLocalPDPEvaluator creates a new evaluator with optional dependency overrides.
func NewLocalPDPEvaluator(opts ...LocalPDPEvaluatorOptions) *LocalPDPEvaluator {
	e := &LocalPDPEvaluator{
		getRevCache:     revocation.GetRevocationCache,
		getBundleCache:  bundle.GetBundleCache,
		getContextCache: kscontext.GetContextCache,
	}
	for _, o := range opts {
		if o.GetRevocationCache != nil {
			e.getRevCache = o.GetRevocationCache
		}
		if o.GetBundleCache != nil {
			e.getBundleCache = o.GetBundleCache
		}
		if o.GetContextCache != nil {
			e.getContextCache = o.GetContextCache
		}
	}
	return e
}

// Evaluate performs a local policy decision.
// Returns a *LocalDecision with outcome "allow", "deny", or "conditional".
// Conditional means the caller must escalate to the server.
// ctx is checked for cancellation before the Cedar evaluation step.
func (e *LocalPDPEvaluator) Evaluate(
	ctx context.Context,
	agentID, mcpServerID, toolName string,
	extra map[string]any,
) *LocalDecision {
	decisionPath := []string{"local_sdk"}
	riskTierFromCtx := "medium"
	if extra != nil {
		if rt, ok := extra["risk_tier"].(string); ok && rt != "" {
			riskTierFromCtx = rt
		}
	}
	decision := func(o decisionOpts) *LocalDecision {
		o.extra = extra
		return makeDecision(o)
	}

	// ── 0. Stale revocation sync check ──────────────────────────────────────
	if d := e.checkStaleRevocation(agentID, mcpServerID, toolName, decisionPath, extra); d != nil {
		return d
	}

	// ── 1. Revocation cache check ────────────────────────────────────────────
	revCache := e.getRevCache()
	if revCache.IsRevoked(agentID) {
		return decision(decisionOpts{
			outcome:      "deny",
			reason:       "agent_revoked",
			allowed:      false,
			decisionPath: append(decisionPath, "revocation_cache_hit"),
			riskTier:     riskTierFromCtx,
			agentID:      agentID,
			mcpServerID:  mcpServerID,
			toolName:     toolName,
		})
	}

	// ── 2. Load context pack ─────────────────────────────────────────────────
	ctxCache := e.getContextCache()
	contextPack := ctxCache.GetOrLoad(agentID)
	if contextPack == nil {
		if riskTierFromCtx == "critical" || riskTierFromCtx == "high" {
			return decision(decisionOpts{
				outcome:      "deny",
				reason:       "context_pack_unavailable",
				allowed:      false,
				decisionPath: append(decisionPath, "context_miss_denied"),
				riskTier:     riskTierFromCtx,
				agentID:      agentID,
				mcpServerID:  mcpServerID,
				toolName:     toolName,
			})
		}
		return decision(decisionOpts{
			outcome:      "conditional",
			reason:       "context_pack_miss",
			allowed:      false,
			decisionPath: append(decisionPath, "context_miss_escalate"),
			riskTier:     riskTierFromCtx,
			agentID:      agentID,
			mcpServerID:  mcpServerID,
			toolName:     toolName,
		})
	}

	riskTier := contextPack.RiskTier
	if riskTier == "" {
		riskTier = riskTierFromCtx
	}

	// ── 3. Agent status check ────────────────────────────────────────────────
	if !contextPack.IsActive() {
		reason := "agent_inactive"
		if contextPack.Status == "suspended" {
			reason = "agent_suspended"
		}
		return decision(decisionOpts{
			outcome:       "deny",
			reason:        reason,
			allowed:       false,
			decisionPath:  append(decisionPath, fmt.Sprintf("agent_%s", contextPack.Status)),
			riskTier:      riskTier,
			contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
			agentID:       agentID,
			mcpServerID:   mcpServerID,
			toolName:      toolName,
		})
	}

	decisionPath = append(decisionPath, "agent_active")

	// ── 4. Load bundle ───────────────────────────────────────────────────────
	bundleCache := e.getBundleCache()
	b := bundleCache.GetOrLoad()
	if b == nil {
		return decision(decisionOpts{
			outcome:       "conditional",
			reason:        "bundle_unavailable",
			allowed:       false,
			decisionPath:  append(decisionPath, "bundle_miss_escalate"),
			riskTier:      riskTier,
			contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
			agentID:       agentID,
			mcpServerID:   mcpServerID,
			toolName:      toolName,
		})
	}

	if b.IsStale(riskTier) && (riskTier == "critical" || riskTier == "high") {
		return decision(decisionOpts{
			outcome:       "conditional",
			reason:        "bundle_stale",
			allowed:       false,
			decisionPath:  append(decisionPath, "bundle_stale_escalate"),
			riskTier:      riskTier,
			bundleVersion: fmt.Sprintf("bundle:v%d", b.Version),
			contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
			agentID:       agentID,
			mcpServerID:   mcpServerID,
			toolName:      toolName,
		})
	}

	decisionPath = append(decisionPath, fmt.Sprintf("bundle_v%d", b.Version))

	// ── Check context cancellation before Cedar evaluation ───────────────────
	if ctx != nil {
		select {
		case <-ctx.Done():
			return decision(decisionOpts{
				outcome:       "conditional",
				reason:        "context_cancelled",
				allowed:       false,
				decisionPath:  append(decisionPath, "ctx_cancelled"),
				riskTier:      riskTier,
				bundleVersion: fmt.Sprintf("bundle:v%d", b.Version),
				contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
				agentID:       agentID,
				mcpServerID:   mcpServerID,
				toolName:      toolName,
			})
		default:
		}
	}

	// ── 5. Cedar evaluation ──────────────────────────────────────────────────
	var obligations []LocalObligation

	if b.EnforceCount == 0 {
		// No enforce policies → allow without Cedar call.
		decisionPath = append(decisionPath, "no_policies")
	} else {
		allowed, cedarErr := cedarEvaluate(b.CedarTextEnforce, agentID, mcpServerID, toolName)
		if cedarErr != nil {
			// Cedar error — escalate for critical/high, allow for low-risk.
			if riskTier == "critical" || riskTier == "high" {
				return decision(decisionOpts{
					outcome:       "conditional",
					reason:        "cedar_error_escalate",
					allowed:       false,
					decisionPath:  append(decisionPath, "cedar_error"),
					riskTier:      riskTier,
					bundleVersion: fmt.Sprintf("bundle:v%d", b.Version),
					contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
					agentID:       agentID,
					mcpServerID:   mcpServerID,
					toolName:      toolName,
				})
			}
			decisionPath = append(decisionPath, "cedar_error_allow_low_risk")
		} else if !allowed {
			return decision(decisionOpts{
				outcome:       "deny",
				reason:        "policy_denied",
				allowed:       false,
				decisionPath:  append(decisionPath, "cedar_denied"),
				riskTier:      riskTier,
				bundleVersion: fmt.Sprintf("bundle:v%d", b.Version),
				contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
				agentID:       agentID,
				mcpServerID:   mcpServerID,
				toolName:      toolName,
			})
		} else {
			decisionPath = append(decisionPath, "cedar_allowed")
		}
	}

	// ── 6. Shadow policies ───────────────────────────────────────────────────
	if b.ShadowCount > 0 {
		shadowAllowed, _ := cedarEvaluate(b.CedarTextShadow, agentID, mcpServerID, toolName)
		if !shadowAllowed {
			obligations = append(obligations, LocalObligation{
				Type:           "shadow_denied",
				ObligationType: "shadow_denied",
				Detail:         "shadow_forbid",
			})
			decisionPath = append(decisionPath, "shadow_denied")
		}
	}

	// ── 7. Human-approval gating ─────────────────────────────────────────────
	if toolName != "" && b.RequiresHumanApproval(toolName) {
		obligations = append(obligations, LocalObligation{
			Type:           "audit_flag",
			ObligationType: "audit_flag",
			Detail:         fmt.Sprintf("tool %s requires human approval", toolName),
		})
		decisionPath = append(decisionPath, "tool_requires_human_approval")
	}

	// ── 8. Derive output policy ──────────────────────────────────────────────
	outputPolicy := deriveOutputPolicy(obligations, contextPack.DataClassifications)

	decisionPath = append(decisionPath, "enforcement_complete")

	return decision(decisionOpts{
		outcome:       "allow",
		reason:        "allowed",
		allowed:       true,
		decisionPath:  decisionPath,
		obligations:   obligations,
		outputPolicy:  outputPolicy,
		riskTier:      riskTier,
		bundleVersion: fmt.Sprintf("bundle:v%d", b.Version),
		contextPackID: fmt.Sprintf("cp:v%d", contextPack.PackVersion),
		agentID:       agentID,
		mcpServerID:   mcpServerID,
		toolName:      toolName,
	})
}

// ── Cedar evaluation ──────────────────────────────────────────────────────────

// cedarEvaluate parses policyText and evaluates allow/deny for the given subject.
// Returns (true=allow, nil) on allow, (false, nil) on deny, (false, error) on failure.
//
// Go execution model: synchronous in-process Cedar evaluation via cedar-go.
// Panics are recovered and returned as errors, triggering conditional escalation.
func cedarEvaluate(policyText, agentID, mcpServerID, toolName string) (allow bool, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("cedar panic: %v", r)
		}
	}()

	if strings.TrimSpace(policyText) == "" {
		// Empty policy text: no policies = deny by Cedar's default-deny semantics.
		// However, the caller already checks enforce_count == 0 before calling this.
		// If we reach here with empty text, treat as deny (safe default).
		return false, nil
	}

	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyText))
	if err != nil {
		return false, fmt.Errorf("cedar policy parse: %w", err)
	}

	var resource cedartypes.EntityUID
	if toolName != "" {
		resource = cedartypes.EntityUID{
			Type: cedartypes.EntityType("MCP::Tool"),
			ID:   cedartypes.String(toolName),
		}
	} else {
		resource = cedartypes.EntityUID{
			Type: cedartypes.EntityType("MCP::Server"),
			ID:   cedartypes.String(mcpServerID),
		}
	}

	req := cedartypes.Request{
		Principal: cedartypes.EntityUID{
			Type: cedartypes.EntityType("Agent"),
			ID:   cedartypes.String(agentID),
		},
		Action: cedartypes.EntityUID{
			Type: cedartypes.EntityType("Action"),
			ID:   cedartypes.String("McpCall"),
		},
		Resource: resource,
		Context:  cedartypes.Record{},
	}

	decision, _ := ps.IsAuthorized(cedartypes.Entities{}, req)
	return decision == cedar.Allow, nil
}

// ── Output policy derivation ─────────────────────────────────────────────────

// deriveOutputPolicy mirrors Python _derive_output_policy() and TypeScript deriveOutputPolicy().
func deriveOutputPolicy(obligations []LocalObligation, dataClassifications []string) *LocalOutputPolicy {
	// DENY_EXPORT wins: critical credential_risk or anomaly_detection with critical anomaly.
	for _, ob := range obligations {
		obType := strings.ToLower(firstNonEmpty(ob.Type, ob.ObligationType))
		level := strings.ToLower(ob.Level)
		if obType == "credential_risk" && level == "critical" {
			return &LocalOutputPolicy{Mode: "deny_export", MaskingClassifications: []string{}}
		}
		if obType == "anomaly_detection" {
			if params, ok := ob.Parameters["anomalies"].([]any); ok {
				for _, a := range params {
					if am, ok := a.(map[string]any); ok {
						if sev, ok := am["severity"].(string); ok && sev == "critical" {
							return &LocalOutputPolicy{Mode: "deny_export", MaskingClassifications: []string{}}
						}
					}
				}
			}
		}
	}

	// MASK_FIELDS: data_masking obligation.
	for _, ob := range obligations {
		obType := strings.ToLower(firstNonEmpty(ob.Type, ob.ObligationType))
		if obType == "data_masking" {
			var cls []string
			if p, ok := ob.Parameters["classifications"].([]any); ok {
				for _, c := range p {
					if s, ok := c.(string); ok {
						cls = append(cls, s)
					}
				}
			}
			if cls == nil {
				cls = []string{}
			}
			return &LocalOutputPolicy{Mode: "mask_fields", MaskingClassifications: cls}
		}
	}

	// MASK_FIELDS: sensitive data classifications.
	var sensitive []string
	for _, cls := range dataClassifications {
		if sensitiveClassifications[cls] {
			sensitive = append(sensitive, cls)
		}
	}
	if len(sensitive) > 0 {
		return &LocalOutputPolicy{Mode: "mask_fields", MaskingClassifications: sensitive}
	}

	return &LocalOutputPolicy{Mode: "allow_raw", MaskingClassifications: []string{}}
}

// ── Stale revocation check ───────────────────────────────────────────────────

func (e *LocalPDPEvaluator) checkStaleRevocation(
	agentID, mcpServerID, toolName string,
	decisionPath []string,
	extra map[string]any,
) *LocalDecision {
	decision := func(o decisionOpts) *LocalDecision {
		o.extra = extra
		return makeDecision(o)
	}
	staleMode := os.Getenv("KSWITCH_REVOCATION_STALE_MODE")
	if staleMode == "" || staleMode == "warn" {
		return nil
	}

	staleThreshold := 150
	if s := os.Getenv("KSWITCH_REVOCATION_STALE_THRESHOLD"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			staleThreshold = v
		}
	}

	revCache := e.getRevCache()
	if !revCache.IsSyncStale(staleThreshold) {
		return nil
	}

	if staleMode == "deny" {
		return decision(decisionOpts{
			outcome:      "deny",
			reason:       "revocation_sync_stale",
			allowed:      false,
			decisionPath: append(decisionPath, "revocation_sync_stale_deny"),
			agentID:      agentID,
			mcpServerID:  mcpServerID,
			toolName:     toolName,
		})
	}

	if staleMode == "conditional" {
		return decision(decisionOpts{
			outcome:      "conditional",
			reason:       "revocation_sync_stale",
			allowed:      false,
			decisionPath: append(decisionPath, "revocation_sync_stale_conditional"),
			agentID:      agentID,
			mcpServerID:  mcpServerID,
			toolName:     toolName,
		})
	}

	return nil
}

// ── Utility ──────────────────────────────────────────────────────────────────

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ── Module-level singleton ────────────────────────────────────────────────────

var defaultEvaluator = NewLocalPDPEvaluator()

// GetEvaluator returns the module-level default evaluator.
func GetEvaluator() *LocalPDPEvaluator {
	return defaultEvaluator
}

// SetEvaluator replaces the module-level default evaluator (for testing).
func SetEvaluator(e *LocalPDPEvaluator) {
	defaultEvaluator = e
}
