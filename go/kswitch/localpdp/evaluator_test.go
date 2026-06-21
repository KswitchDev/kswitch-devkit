package localpdp_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/bundle"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/kscontext"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/localpdp"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/revocation"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-pdp-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// buildSignedBundle creates and stores a signed bundle in dir.
func buildSignedBundle(t *testing.T, dir string, version int, cedarText string, enforceCount int, tools map[string]any) *bundle.LocalBundleCache {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b := map[string]any{
		"version":            version,
		"bundle_id":          fmt.Sprintf("bundle:v%d", version),
		"compiled_at":        "2026-03-28T21:00:00Z",
		"cedar_text_enforce": cedarText,
		"cedar_text_shadow":  "",
		"enforce_count":      enforceCount,
		"shadow_count":       0,
		"tool_count":         len(tools),
		"tool_index":         tools,
	}
	content, _ := json.Marshal(b)
	b["signature"] = "sha256:" + fmt.Sprintf("%x", sha256.Sum256(content))

	data, _ := json.Marshal(b)
	os.WriteFile(filepath.Join(dir, "current.bundle"), data, 0o644)
	return bundle.NewLocalBundleCache(dir)
}

// buildContextPack writes a context pack to dir and returns the cache.
func buildContextPack(t *testing.T, dir string, agentID, status, riskTier string, revoked bool, classifications []string) *kscontext.LocalContextCache {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	c := kscontext.NewLocalContextCache(dir)
	packData := map[string]any{
		"status":               status,
		"risk_tier":            riskTier,
		"data_classifications": classifications,
		"is_revoked":           revoked,
		"compiled_at":          "2026-03-28T21:00:00Z",
		"pack_version":         1,
	}
	if err := c.Store(agentID, packData); err != nil {
		t.Fatal(err)
	}
	return c
}

// newEvaluator creates an evaluator with injected deps backed by temp dirs.
func newEvaluator(
	revCache *revocation.LocalRevocationCache,
	bundleCache *bundle.LocalBundleCache,
	ctxCache *kscontext.LocalContextCache,
) *localpdp.LocalPDPEvaluator {
	return localpdp.NewLocalPDPEvaluator(localpdp.LocalPDPEvaluatorOptions{
		GetRevocationCache: func() *revocation.LocalRevocationCache { return revCache },
		GetBundleCache:     func() *bundle.LocalBundleCache { return bundleCache },
		GetContextCache:    func() *kscontext.LocalContextCache { return ctxCache },
	})
}

// permitPolicy returns Cedar policy text that permits everything.
func permitPolicy() string {
	return `permit(principal, action, resource);`
}

// forbidPolicy returns Cedar policy text that forbids everything.
func forbidPolicy() string {
	return `forbid(principal, action, resource);`
}

// ── Revocation path ───────────────────────────────────────────────────────────

func TestEvaluate_RevokedAgent_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	revCache.Revoke("agent:bad@bank.internal", "compromised")
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:bad@bank.internal", "active", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:bad@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny", d.Outcome)
	}
	if d.Reason != "agent_revoked" {
		t.Errorf("Reason = %q, want agent_revoked", d.Reason)
	}
	if d.Allowed {
		t.Error("Allowed should be false for revoked agent")
	}
}

func TestEvaluate_BlanketKill_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	revCache.SetBlanketKill(true)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:any@bank.internal", "active", "low", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:any@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny (blanket kill)", d.Outcome)
	}
}

// ── Context pack paths ────────────────────────────────────────────────────────

func TestEvaluate_ContextPackMissing_HighRisk_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := kscontext.NewLocalContextCache(tmp + "/ctx-empty")

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:unknown@bank.internal", "mcp:server@bank.internal", "tool",
		map[string]any{"risk_tier": "high"})

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny for missing context pack + high risk", d.Outcome)
	}
	if d.Reason != "context_pack_unavailable" {
		t.Errorf("Reason = %q, want context_pack_unavailable", d.Reason)
	}
}

func TestEvaluate_ContextPackMissing_LowRisk_Conditional(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := kscontext.NewLocalContextCache(tmp + "/ctx-empty")

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:unknown@bank.internal", "mcp:server@bank.internal", "tool",
		map[string]any{"risk_tier": "low"})

	if d.Outcome != "conditional" {
		t.Errorf("Outcome = %q, want conditional for missing context pack + low risk", d.Outcome)
	}
}

func TestEvaluate_AgentSuspended_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "suspended", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny for suspended agent", d.Outcome)
	}
	if d.Reason != "agent_suspended" {
		t.Errorf("Reason = %q, want agent_suspended", d.Reason)
	}
}

func TestEvaluate_AgentInactive_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "terminated", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny for inactive agent", d.Outcome)
	}
}

// ── Bundle paths ──────────────────────────────────────────────────────────────

func TestEvaluate_BundleMissing_Conditional(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := bundle.NewLocalBundleCache(tmp + "/bundle-empty")
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "conditional" {
		t.Errorf("Outcome = %q, want conditional for missing bundle", d.Outcome)
	}
	if d.Reason != "bundle_unavailable" {
		t.Errorf("Reason = %q, want bundle_unavailable", d.Reason)
	}
}

// ── Cedar evaluation paths ────────────────────────────────────────────────────

func TestEvaluate_CedarPermit_Allow(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow for permit policy", d.Outcome)
	}
	if !d.Allowed {
		t.Error("Allowed should be true")
	}
	if d.EvaluationMode != localpdp.EvaluationMode {
		t.Errorf("EvaluationMode = %q, want %q", d.EvaluationMode, localpdp.EvaluationMode)
	}
	if d.EnforcementID == "" {
		t.Error("EnforcementID must not be empty")
	}
}

func TestEvaluate_CedarForbid_Deny(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, forbidPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny for forbid policy", d.Outcome)
	}
	if d.Reason != "policy_denied" {
		t.Errorf("Reason = %q, want policy_denied", d.Reason)
	}
}

func TestEvaluate_EP221Evidence_LocalAllowDenyConditional(t *testing.T) {
	const (
		agentID     = "agent:alice.sensitive@example.internal"
		mcpServerID = "mcp:payroll@example.internal"
		toolName    = "export_salary_records"
		requesterID = "requester:bob.sensitive@example.internal"
	)

	tests := []struct {
		name    string
		outcome string
		setup   func(t *testing.T, tmp string) (*bundle.LocalBundleCache, *kscontext.LocalContextCache)
	}{
		{
			name:    "allow",
			outcome: "allow",
			setup: func(t *testing.T, tmp string) (*bundle.LocalBundleCache, *kscontext.LocalContextCache) {
				return buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil),
					buildContextPack(t, tmp+"/ctx", agentID, "active", "medium", false, nil)
			},
		},
		{
			name:    "deny",
			outcome: "deny",
			setup: func(t *testing.T, tmp string) (*bundle.LocalBundleCache, *kscontext.LocalContextCache) {
				return buildSignedBundle(t, tmp+"/bundle", 1, forbidPolicy(), 1, nil),
					buildContextPack(t, tmp+"/ctx", agentID, "active", "medium", false, nil)
			},
		},
		{
			name:    "conditional",
			outcome: "conditional",
			setup: func(t *testing.T, tmp string) (*bundle.LocalBundleCache, *kscontext.LocalContextCache) {
				return bundle.NewLocalBundleCache(tmp + "/bundle-empty"),
					buildContextPack(t, tmp+"/ctx", agentID, "active", "medium", false, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := makeTmpDir(t)
			revCache := revocation.NewLocalRevocationCache(tmp)
			bundleCache, ctxCache := tt.setup(t, tmp)
			e := newEvaluator(revCache, bundleCache, ctxCache)

			d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName,
				map[string]any{"requester_id": requesterID})

			if d.Outcome != tt.outcome {
				t.Fatalf("Outcome = %q, want %q", d.Outcome, tt.outcome)
			}
			assertEP221LocalEvidence(t, d, []string{agentID, mcpServerID, toolName, requesterID})
		})
	}
}

func TestEvaluate_NoPolicies_Allow(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	// enforce_count=0: evaluator skips Cedar call and allows.
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, "", 0, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "low", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow when no policies (default-allow)", d.Outcome)
	}
}

func TestEvaluate_InvalidCedarPolicy_HighRisk_Conditional(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, "this is not valid cedar policy!!!!", 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "high", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "conditional" {
		t.Errorf("Outcome = %q, want conditional (Cedar parse error + high risk)", d.Outcome)
	}
}

func TestEvaluate_InvalidCedarPolicy_LowRisk_Allow(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, "not valid cedar!!", 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "low", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow (Cedar parse error + low risk)", d.Outcome)
	}
}

// ── Human approval obligation ─────────────────────────────────────────────────

func TestEvaluate_HumanApproval_Obligation(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	tools := map[string]any{
		"initiate_payment": map[string]any{"requires_human_approval": true},
	}
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, tools)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "initiate_payment", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow (human approval adds obligation, not deny)", d.Outcome)
	}
	found := false
	for _, ob := range d.Obligations {
		if ob.Type == "audit_flag" || ob.ObligationType == "audit_flag" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected audit_flag obligation for human-approval tool, got %v", d.Obligations)
	}
}

// ── Output policy derivation ──────────────────────────────────────────────────

func TestEvaluate_SensitiveClassification_MaskFields(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false,
		[]string{"PII"})

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow", d.Outcome)
	}
	if d.OutputPolicy == nil {
		t.Fatal("OutputPolicy must not be nil")
	}
	if d.OutputPolicy.Mode != "mask_fields" {
		t.Errorf("OutputPolicy.Mode = %q, want mask_fields", d.OutputPolicy.Mode)
	}
}

func TestEvaluate_NoSensitiveClassification_AllowRaw(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "low", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow", d.Outcome)
	}
	if d.OutputPolicy == nil || d.OutputPolicy.Mode != "allow_raw" {
		t.Errorf("OutputPolicy = %v, want mode=allow_raw", d.OutputPolicy)
	}
}

// ── Context cancellation ──────────────────────────────────────────────────────

func TestEvaluate_CancelledContext_Conditional(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "medium", false, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(ctx, "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if d.Outcome != "conditional" {
		t.Errorf("Outcome = %q, want conditional for cancelled context", d.Outcome)
	}
}

// ── LocalDecision helpers ─────────────────────────────────────────────────────

func TestLocalDecision_IsLocal_NeedsEscalation(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "low", false, nil)
	e := newEvaluator(revCache, bundleCache, ctxCache)

	dAllow := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)
	if !dAllow.IsLocal() {
		t.Error("allow decision should be IsLocal()=true")
	}
	if dAllow.NeedsEscalation() {
		t.Error("allow decision should not NeedsEscalation()")
	}

	revCache.Revoke("agent:test@bank.internal", "test")
	dDeny := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)
	if !dDeny.IsLocal() {
		t.Error("deny decision should be IsLocal()=true")
	}
}

// ── Decision path tracing ─────────────────────────────────────────────────────

func TestEvaluate_DecisionPath_Populated(t *testing.T) {
	tmp := makeTmpDir(t)
	revCache := revocation.NewLocalRevocationCache(tmp)
	bundleCache := buildSignedBundle(t, tmp+"/bundle", 1, permitPolicy(), 1, nil)
	ctxCache := buildContextPack(t, tmp+"/ctx", "agent:test@bank.internal", "active", "low", false, nil)

	e := newEvaluator(revCache, bundleCache, ctxCache)
	d := e.Evaluate(context.Background(), "agent:test@bank.internal", "mcp:server@bank.internal", "tool", nil)

	if len(d.DecisionPath) == 0 {
		t.Error("DecisionPath must not be empty")
	}
	// Should start with local_sdk.
	if d.DecisionPath[0] != "local_sdk" {
		t.Errorf("DecisionPath[0] = %q, want 'local_sdk'", d.DecisionPath[0])
	}
}

func assertEP221LocalEvidence(t *testing.T, d *localpdp.LocalDecision, rawValues []string) {
	t.Helper()
	if d.ContextSnapshotID == "" {
		t.Fatal("ContextSnapshotID must be set")
	}
	if !strings.HasPrefix(d.ContextSnapshotDigest, "sha256:") {
		t.Fatalf("ContextSnapshotDigest = %q, want sha256 digest", d.ContextSnapshotDigest)
	}
	if d.ContextSnapshot == nil {
		t.Fatal("ContextSnapshot must be set")
	}
	if d.DecisionExplanation == nil {
		t.Fatal("DecisionExplanation must be set")
	}
	if got := d.ContextSnapshot["schema_version"]; got != "kswitch.policy_context.v1" {
		t.Fatalf("context snapshot schema_version = %#v", got)
	}
	if got := d.DecisionExplanation["schema_version"]; got != "kswitch.decision_explanation.v1" {
		t.Fatalf("decision explanation schema_version = %#v", got)
	}
	if got := d.DecisionExplanation["outcome"]; got != d.Outcome {
		t.Fatalf("decision explanation outcome = %#v, want %q", got, d.Outcome)
	}
	attribution, ok := d.DecisionExplanation["policy_attribution"].(map[string]any)
	if !ok {
		t.Fatalf("policy_attribution = %#v, want object", d.DecisionExplanation["policy_attribution"])
	}
	matched, ok := attribution["matched_policy_ids"].([]string)
	if !ok {
		t.Fatalf("matched_policy_ids = %#v, want []string", attribution["matched_policy_ids"])
	}
	if len(matched) != 0 {
		t.Fatalf("matched_policy_ids = %#v, want empty local PDP attribution", matched)
	}
	if got := attribution["attribution_state"]; got != "unavailable_until_per_policy_eval" {
		t.Fatalf("attribution_state = %#v, want unavailable_until_per_policy_eval", got)
	}
	if got := attribution["attribution_method"]; got != "local_pdp_aggregate_bundle_without_per_policy_eval" {
		t.Fatalf("attribution_method = %#v, want aggregate bundle marker", got)
	}

	toolRequest, ok := d.ContextSnapshot["tool_request"].(map[string]any)
	if !ok {
		t.Fatalf("tool_request = %#v, want object", d.ContextSnapshot["tool_request"])
	}
	for _, key := range []string{"agent", "mcp_server", "tool", "requester"} {
		entry, ok := toolRequest[key].(map[string]any)
		if !ok {
			t.Fatalf("tool_request.%s = %#v, want object", key, toolRequest[key])
		}
		if entry["status"] != "present_deterministic" {
			t.Fatalf("tool_request.%s.status = %#v, want present_deterministic", key, entry["status"])
		}
		digest, ok := entry["digest"].(string)
		if !ok || !strings.HasPrefix(digest, "sha256:") {
			t.Fatalf("tool_request.%s.digest = %#v, want sha256 digest", key, entry["digest"])
		}
	}
	if len(d.ContextSnapshotDigest) > len("sha256:")+64 {
		t.Fatalf("ContextSnapshotDigest length = %d, want bounded sha256 digest", len(d.ContextSnapshotDigest))
	}

	snapshotJSON, err := json.Marshal(d.ContextSnapshot)
	if err != nil {
		t.Fatalf("marshal ContextSnapshot: %v", err)
	}
	explanationJSON, err := json.Marshal(d.DecisionExplanation)
	if err != nil {
		t.Fatalf("marshal DecisionExplanation: %v", err)
	}
	for _, raw := range rawValues {
		if strings.Contains(string(snapshotJSON), raw) {
			t.Fatalf("ContextSnapshot contains raw sensitive value %q: %s", raw, snapshotJSON)
		}
		if strings.Contains(string(explanationJSON), raw) {
			t.Fatalf("DecisionExplanation contains raw sensitive value %q: %s", raw, explanationJSON)
		}
	}
}
