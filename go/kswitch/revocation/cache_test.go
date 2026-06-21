package revocation_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/revocation"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-rev-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// ── DefaultRevocationDir ──────────────────────────────────────────────────────

func TestDefaultRevocationDir_EnvVar(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_STATE_DIR", tmp)
	got := revocation.DefaultRevocationDir()
	want := filepath.Join(tmp, "revocation")
	if got != want {
		t.Errorf("DefaultRevocationDir() = %q, want %q", got, want)
	}
}

// ── IsRevoked ─────────────────────────────────────────────────────────────────

func TestIsRevoked_NotRevoked(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	if c.IsRevoked("agent:test@bank.internal") {
		t.Error("expected agent NOT revoked on empty cache")
	}
}

func TestIsRevoked_AfterRevoke(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	c.Revoke("agent:bad@bank.internal", "compromised")
	if !c.IsRevoked("agent:bad@bank.internal") {
		t.Error("expected agent to be revoked after Revoke()")
	}
}

func TestIsRevoked_BlanketKill(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	c.SetBlanketKill(true)
	if !c.IsRevoked("agent:any@bank.internal") {
		t.Error("expected all agents revoked under blanket kill")
	}
	c.SetBlanketKill(false)
	if c.IsRevoked("agent:any@bank.internal") {
		t.Error("expected blanket kill disabled")
	}
}

func TestIsRevoked_ClearAgent(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	c.Revoke("agent:bad@bank.internal", "test")
	c.ClearAgent("agent:bad@bank.internal")
	if c.IsRevoked("agent:bad@bank.internal") {
		t.Error("expected agent cleared after ClearAgent()")
	}
}

// ── ApplyServerState ──────────────────────────────────────────────────────────

func TestApplyServerState_BasicSync(t *testing.T) {
	tmp := makeTmpDir(t)
	c := revocation.NewLocalRevocationCache(tmp)

	v := 7
	state := map[string]any{
		"version":            v,
		"blanket_kill_active": false,
		"revoked_agents":     []any{"agent:revoked@bank.internal"},
	}
	c.ApplyServerState(state)

	if !c.IsRevoked("agent:revoked@bank.internal") {
		t.Error("expected revoked agent after ApplyServerState")
	}
	if c.IsRevoked("agent:clean@bank.internal") {
		t.Error("unexpected revocation for clean agent")
	}
	sv := c.GetServerVersion()
	if sv == nil || *sv != 7 {
		t.Errorf("GetServerVersion() = %v, want 7", sv)
	}
}

func TestApplyServerState_BlanketKill(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	state := map[string]any{
		"version":             1,
		"blanket_kill_active": true,
		"revoked_agents":      []any{},
	}
	c.ApplyServerState(state)
	if !c.IsRevoked("agent:anyone@bank.internal") {
		t.Error("expected blanket kill from server state")
	}
}

func TestApplyServerState_ClearsOldEntries(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	// First sync: revoke two agents.
	c.ApplyServerState(map[string]any{
		"version":             1,
		"blanket_kill_active": false,
		"revoked_agents":      []any{"agent:a@bank.internal", "agent:b@bank.internal"},
	})
	// Second sync: only revoke agent:a.
	c.ApplyServerState(map[string]any{
		"version":             2,
		"blanket_kill_active": false,
		"revoked_agents":      []any{"agent:a@bank.internal"},
	})
	if !c.IsRevoked("agent:a@bank.internal") {
		t.Error("agent:a should still be revoked")
	}
	if c.IsRevoked("agent:b@bank.internal") {
		t.Error("agent:b should be cleared by second sync")
	}
}

// ── IsSyncStale ───────────────────────────────────────────────────────────────

func TestIsSyncStale_NeverSynced(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	if !c.IsSyncStale(60) {
		t.Error("expected stale when never synced")
	}
}

func TestIsSyncStale_RecentSync(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	c.ApplyServerState(map[string]any{
		"version":             1,
		"blanket_kill_active": false,
		"revoked_agents":      []any{},
	})
	if c.IsSyncStale(3600) {
		t.Error("expected NOT stale after recent sync with 3600s threshold")
	}
}

func TestIsSyncStale_ZeroThreshold(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	// Never synced, but threshold=0 means disabled.
	if c.IsSyncStale(0) {
		t.Error("IsSyncStale(0) should always return false")
	}
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

func TestGetDiagnostics(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	d := c.GetDiagnostics()
	if d.RevokedCount != 0 {
		t.Errorf("RevokedCount = %d, want 0", d.RevokedCount)
	}
	if d.BlanketKillActive {
		t.Error("BlanketKillActive should be false")
	}

	c.Revoke("agent:a@bank.internal", "test")
	c.Revoke("agent:b@bank.internal", "test")
	d2 := c.GetDiagnostics()
	if d2.RevokedCount != 2 {
		t.Errorf("RevokedCount = %d, want 2", d2.RevokedCount)
	}
}

// ── RecordSyncFailure ─────────────────────────────────────────────────────────

func TestRecordSyncFailure(t *testing.T) {
	c := revocation.NewLocalRevocationCache(makeTmpDir(t))
	c.RecordSyncFailure("connection refused")
	c.RecordSyncFailure("timeout")
	d := c.GetDiagnostics()
	if d.SyncFailureCount != 2 {
		t.Errorf("SyncFailureCount = %d, want 2", d.SyncFailureCount)
	}
	if d.LastSyncFailure != "timeout" {
		t.Errorf("LastSyncFailure = %q, want 'timeout'", d.LastSyncFailure)
	}
}

// ── Disk persistence ──────────────────────────────────────────────────────────

func TestPersistAndReload(t *testing.T) {
	tmp := makeTmpDir(t)
	c1 := revocation.NewLocalRevocationCache(tmp)
	c1.Revoke("agent:persisted@bank.internal", "test")

	// Create a new cache instance from same dir; it should reload from disk.
	c2 := revocation.NewLocalRevocationCache(tmp)
	if !c2.IsRevoked("agent:persisted@bank.internal") {
		t.Error("revoked agent should survive process restart via disk reload")
	}
}

// ── ParseStateResponse ────────────────────────────────────────────────────────

func TestParseStateResponse_Valid(t *testing.T) {
	raw := []byte(`{"version":3,"blanket_kill_active":false,"revoked_agents":["agent:x@bank.internal"]}`)
	state, err := revocation.ParseStateResponse(raw)
	if err != nil {
		t.Fatalf("ParseStateResponse() error: %v", err)
	}
	if v, ok := state["version"].(float64); !ok || int(v) != 3 {
		t.Errorf("version = %v, want 3", state["version"])
	}
}

func TestParseStateResponse_InvalidJSON(t *testing.T) {
	_, err := revocation.ParseStateResponse([]byte("{bad json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// Ensure test file uses time package (avoid unused import).
var _ = time.Second
