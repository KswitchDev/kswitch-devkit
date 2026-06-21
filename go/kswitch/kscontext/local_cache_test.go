package kscontext_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/kscontext"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-ctx-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func writeContextPack(t *testing.T, dir, agentID, status, riskTier string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"agent_id":             agentID,
		"status":               status,
		"risk_tier":            riskTier,
		"data_classifications": []string{},
		"is_revoked":           false,
		"compiled_at":          "2026-03-28T21:00:00Z",
		"pack_version":         1,
	}
	b, _ := json.Marshal(data)
	// Sanitize agent ID as kscontext does: : → _, @ → _at_, . → _
	safe := agentID
	for _, r := range []struct{ old, new string }{{":", "_"}, {"@", "_at_"}, {".", "_"}, {"/", "_"}} {
		safe = replaceAll(safe, r.old, r.new)
	}
	os.WriteFile(filepath.Join(dir, safe+".contextpack"), b, 0o644)
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

// ── DefaultContextDir ─────────────────────────────────────────────────────────

func TestDefaultContextDir_EnvVar(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_STATE_DIR", tmp)
	got := kscontext.DefaultContextDir()
	want := filepath.Join(tmp, "context")
	if got != want {
		t.Errorf("DefaultContextDir() = %q, want %q", got, want)
	}
}

func TestDefaultContextDir_HomeDir(t *testing.T) {
	t.Setenv("KSWITCH_STATE_DIR", "")
	dir := kscontext.DefaultContextDir()
	if dir == "" {
		t.Skip("no home dir available")
	}
	if filepath.Base(dir) != "context" {
		t.Errorf("expected last segment to be 'context', got %q", dir)
	}
}

// ── IsActive ──────────────────────────────────────────────────────────────────

func TestIsActive_ActiveStates(t *testing.T) {
	cases := []struct {
		status  string
		revoked bool
		want    bool
	}{
		{"active", false, true},
		{"declared", false, true},
		{"pending", false, true},
		{"suspended", false, false},
		{"terminated", false, false},
		{"active", true, false},  // revoked even if status=active
		{"declared", true, false},
	}
	for _, tc := range cases {
		tmp := makeTmpDir(t)
		c := kscontext.NewLocalContextCache(tmp)
		agentID := "agent:test@bank.internal"
		packData := map[string]any{
			"status":               tc.status,
			"risk_tier":            "medium",
			"data_classifications": []string{},
			"is_revoked":           tc.revoked,
			"compiled_at":          "2026-03-28T21:00:00Z",
			"pack_version":         1,
		}
		if err := c.Store(agentID, packData); err != nil {
			t.Fatalf("Store() error: %v", err)
		}
		pack := c.GetOrLoad(agentID)
		if pack == nil {
			t.Fatalf("GetOrLoad() returned nil for status=%q", tc.status)
		}
		if got := pack.IsActive(); got != tc.want {
			t.Errorf("status=%q revoked=%v: IsActive()=%v, want %v", tc.status, tc.revoked, got, tc.want)
		}
	}
}

// ── Load ──────────────────────────────────────────────────────────────────────

func TestLoad_MissingFile(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	_, err := c.Load("agent:nonexistent@bank.internal")
	if err == nil {
		t.Fatal("expected error for missing context pack")
	}
}

func TestLoad_CorruptJSON(t *testing.T) {
	tmp := makeTmpDir(t)
	// Write a corrupt file with sanitized name.
	os.WriteFile(filepath.Join(tmp, "agent_corrupt_at_bank_internal.contextpack"), []byte("{bad"), 0o644)
	c := kscontext.NewLocalContextCache(tmp)
	_, err := c.Load("agent:corrupt@bank.internal")
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestLoad_Valid(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	agentID := "agent:test@bank.internal"
	packData := map[string]any{
		"status":               "active",
		"risk_tier":            "high",
		"data_classifications": []string{"PII"},
		"is_revoked":           false,
		"compiled_at":          "2026-03-28T21:00:00Z",
		"pack_version":         3,
	}
	if err := c.Store(agentID, packData); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
	pack, err := c.Load(agentID)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if pack.Status != "active" {
		t.Errorf("Status = %q, want active", pack.Status)
	}
	if pack.RiskTier != "high" {
		t.Errorf("RiskTier = %q, want high", pack.RiskTier)
	}
	if pack.PackVersion != 3 {
		t.Errorf("PackVersion = %d, want 3", pack.PackVersion)
	}
}

// ── GetOrLoad / Invalidate ────────────────────────────────────────────────────

func TestGetOrLoad_CachesResult(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	agentID := "agent:test@bank.internal"
	packData := map[string]any{
		"status": "active", "risk_tier": "low",
		"data_classifications": []string{}, "is_revoked": false,
		"compiled_at": "2026-03-28T21:00:00Z", "pack_version": 1,
	}
	c.Store(agentID, packData)

	p1 := c.GetOrLoad(agentID)
	p2 := c.GetOrLoad(agentID)
	if p1 == nil || p2 == nil {
		t.Fatal("GetOrLoad() returned nil")
	}
	if p1 != p2 {
		t.Error("expected same pointer from cache on second call")
	}
}

func TestGetOrLoad_ReturnsNilWhenMissing(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	if got := c.GetOrLoad("agent:missing@bank.internal"); got != nil {
		t.Errorf("expected nil for missing agent, got %v", got)
	}
}

func TestInvalidate_ClearsCache(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	agentID := "agent:test@bank.internal"
	packData := map[string]any{
		"status": "active", "risk_tier": "low",
		"data_classifications": []string{}, "is_revoked": false,
		"compiled_at": "2026-03-28T21:00:00Z", "pack_version": 1,
	}
	c.Store(agentID, packData)
	c.GetOrLoad(agentID) // prime cache

	c.Invalidate(agentID)
	// Remove the file so a reload returns nil.
	os.Remove(filepath.Join(tmp, "agent_test_at_bank_internal.contextpack"))
	got := c.GetOrLoad(agentID)
	if got != nil {
		t.Error("expected nil after Invalidate() and file removal")
	}
}

// ── Store ─────────────────────────────────────────────────────────────────────

func TestStore_AtomicWrite(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	agentID := "agent:store-test@bank.internal"
	packData := map[string]any{
		"status": "active", "risk_tier": "medium",
		"data_classifications": []string{"PHI"}, "is_revoked": false,
		"compiled_at": "2026-03-28T21:00:00Z", "pack_version": 5,
	}
	if err := c.Store(agentID, packData); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
	pack := c.GetOrLoad(agentID)
	if pack == nil {
		t.Fatal("GetOrLoad() returned nil after Store()")
	}
	if pack.PackVersion != 5 {
		t.Errorf("PackVersion = %d, want 5", pack.PackVersion)
	}
	if len(pack.DataClassifications) != 1 || pack.DataClassifications[0] != "PHI" {
		t.Errorf("DataClassifications = %v, want [PHI]", pack.DataClassifications)
	}
}

// ── Agent ID sanitization ─────────────────────────────────────────────────────

func TestStore_SanitizesAgentID(t *testing.T) {
	tmp := makeTmpDir(t)
	c := kscontext.NewLocalContextCache(tmp)
	agentID := "agent:fraud-detector-v3@bank.internal"
	packData := map[string]any{
		"status": "active", "risk_tier": "high",
		"data_classifications": []string{}, "is_revoked": false,
		"compiled_at": "2026-03-28T21:00:00Z", "pack_version": 1,
	}
	if err := c.Store(agentID, packData); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
	// Verify file was created (sanitized name).
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".contextpack" {
			found = true
			// Must not contain raw : or @ in filename.
			name := f.Name()
			for _, ch := range []string{":", "@"} {
				for _, r := range name {
					if string(r) == ch {
						t.Errorf("context pack filename %q contains unsanitized char %q", name, ch)
					}
				}
			}
		}
	}
	if !found {
		t.Error("no .contextpack file created")
	}
}
