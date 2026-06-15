// no_network_decision_test.go — Integration test: local PDP path exercises
// end-to-end allow/deny/conditional decisions entirely in-process with no
// network calls. This is the primary parity test for the Go SDK local runtime.
//
// Verified outcomes mirror Python and TypeScript local runtime tests:
//
//	ALLOW  — active agent, permit policy, no revocation
//	DENY   — revoked agent
//	DENY   — forbid policy
//	DENY   — inactive / suspended agent
//	COND   — missing bundle
//	COND   — missing context pack (low risk)
//	DENY   — missing context pack (high/critical risk)
//	COND   — stale revocation + stale mode=conditional
//	DENY   — stale revocation + stale mode=deny
//
// EvaluationMode must be "LOCAL_RUNTIME_GO" on every local decision.
package kswitch_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/KswitchDev/kswitch-sdks/go/kswitch/bundle"
	"github.com/KswitchDev/kswitch-sdks/go/kswitch/kscontext"
	"github.com/KswitchDev/kswitch-sdks/go/kswitch/localpdp"
	"github.com/KswitchDev/kswitch-sdks/go/kswitch/revocation"
)

// ── setup helpers ─────────────────────────────────────────────────────────────

func noNetTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-nonet-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func noNetBuildBundle(t *testing.T, dir, cedarText string, enforceCount int) *bundle.LocalBundleCache {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	b := map[string]any{
		"version":            1,
		"bundle_id":          "bundle:v1",
		"compiled_at":        "2026-03-28T21:00:00Z",
		"cedar_text_enforce": cedarText,
		"cedar_text_shadow":  "",
		"enforce_count":      enforceCount,
		"shadow_count":       0,
		"tool_count":         0,
		"tool_index":         map[string]any{},
	}
	content, _ := json.Marshal(b)
	b["signature"] = "sha256:" + fmt.Sprintf("%x", sha256.Sum256(content))
	data, _ := json.Marshal(b)
	os.WriteFile(dir+"/current.bundle", data, 0o644)
	return bundle.NewLocalBundleCache(dir)
}

func noNetBuildContextPack(t *testing.T, dir, agentID, status, riskTier string) *kscontext.LocalContextCache {
	t.Helper()
	c := kscontext.NewLocalContextCache(dir)
	c.Store(agentID, map[string]any{
		"status":               status,
		"risk_tier":            riskTier,
		"data_classifications": []string{},
		"is_revoked":           false,
		"compiled_at":          "2026-03-28T21:00:00Z",
		"pack_version":         1,
	})
	return c
}

func noNetEvaluator(
	rev *revocation.LocalRevocationCache,
	bnd *bundle.LocalBundleCache,
	ctx *kscontext.LocalContextCache,
) *localpdp.LocalPDPEvaluator {
	return localpdp.NewLocalPDPEvaluator(localpdp.LocalPDPEvaluatorOptions{
		GetRevocationCache: func() *revocation.LocalRevocationCache { return rev },
		GetBundleCache:     func() *bundle.LocalBundleCache { return bnd },
		GetContextCache:    func() *kscontext.LocalContextCache { return ctx },
	})
}

const (
	agentID     = "agent:fraud-detector@bank.internal"
	mcpServerID = "mcp:payments@bank.internal"
	toolName    = "initiate_payment"
)

// ── ALLOW path ────────────────────────────────────────────────────────────────

func TestNoNetwork_Allow_ActiveAgent_PermitPolicy(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "allow")
	assertEvaluationMode(t, d)
	if !d.Allowed {
		t.Error("Allowed must be true on allow path")
	}
	if d.EnforcementID == "" {
		t.Error("EnforcementID must be set")
	}
}

// ── DENY paths ────────────────────────────────────────────────────────────────

func TestNoNetwork_Deny_RevokedAgent(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	rev.Revoke(agentID, "compromised")
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "deny")
	assertReason(t, d, "agent_revoked")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_Deny_ForbidPolicy(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "forbid(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "deny")
	assertReason(t, d, "policy_denied")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_Deny_SuspendedAgent(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "suspended", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "deny")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_Deny_BlanketKill(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	rev.SetBlanketKill(true)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "low")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "deny")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_Deny_ContextPackMissing_HighRisk(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := kscontext.NewLocalContextCache(tmp + "/ctx-empty")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName,
		map[string]any{"risk_tier": "high"})

	assertOutcome(t, d, "deny")
	assertEvaluationMode(t, d)
}

// ── CONDITIONAL paths ─────────────────────────────────────────────────────────

func TestNoNetwork_Conditional_BundleMissing(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := bundle.NewLocalBundleCache(tmp + "/bundle-empty")
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "conditional")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_Conditional_ContextPackMissing_LowRisk(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := kscontext.NewLocalContextCache(tmp + "/ctx-empty")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName,
		map[string]any{"risk_tier": "low"})

	assertOutcome(t, d, "conditional")
	assertEvaluationMode(t, d)
}

// ── Stale revocation sync enforcement ────────────────────────────────────────

func TestNoNetwork_StaleRevocation_DenyMode(t *testing.T) {
	t.Setenv("KSWITCH_REVOCATION_STALE_MODE", "deny")
	t.Setenv("KSWITCH_REVOCATION_STALE_THRESHOLD", "1") // 1 second

	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	// Never synced → IsSyncStale(1) = true
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "deny")
	assertReason(t, d, "revocation_sync_stale")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_StaleRevocation_ConditionalMode(t *testing.T) {
	t.Setenv("KSWITCH_REVOCATION_STALE_MODE", "conditional")
	t.Setenv("KSWITCH_REVOCATION_STALE_THRESHOLD", "1")

	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	assertOutcome(t, d, "conditional")
	assertEvaluationMode(t, d)
}

func TestNoNetwork_StaleRevocation_WarnMode_ContinuesNormally(t *testing.T) {
	t.Setenv("KSWITCH_REVOCATION_STALE_MODE", "warn")
	t.Setenv("KSWITCH_REVOCATION_STALE_THRESHOLD", "1")

	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)

	// warn mode → decision continues normally
	assertOutcome(t, d, "allow")
	assertEvaluationMode(t, d)
}

// ── Decision path always populated ───────────────────────────────────────────

func TestNoNetwork_DecisionPathAlwaysSet(t *testing.T) {
	tmp := noNetTmpDir(t)
	rev := revocation.NewLocalRevocationCache(tmp)
	bnd := noNetBuildBundle(t, tmp+"/bundle", "permit(principal, action, resource);", 1)
	ctx := noNetBuildContextPack(t, tmp+"/ctx", agentID, "active", "medium")
	e := noNetEvaluator(rev, bnd, ctx)

	d := e.Evaluate(context.Background(), agentID, mcpServerID, toolName, nil)
	if len(d.DecisionPath) == 0 {
		t.Error("DecisionPath must always be populated")
	}
}

// ── Assertions ────────────────────────────────────────────────────────────────

func assertOutcome(t *testing.T, d *localpdp.LocalDecision, want string) {
	t.Helper()
	if d.Outcome != want {
		t.Errorf("Outcome = %q, want %q (reason=%q, path=%v)", d.Outcome, want, d.Reason, d.DecisionPath)
	}
}

func assertReason(t *testing.T, d *localpdp.LocalDecision, want string) {
	t.Helper()
	if d.Reason != want {
		t.Errorf("Reason = %q, want %q", d.Reason, want)
	}
}

func assertEvaluationMode(t *testing.T, d *localpdp.LocalDecision) {
	t.Helper()
	if d.EvaluationMode != localpdp.EvaluationMode {
		t.Errorf("EvaluationMode = %q, want %q", d.EvaluationMode, localpdp.EvaluationMode)
	}
}
