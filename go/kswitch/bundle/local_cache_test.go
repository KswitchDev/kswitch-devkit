package bundle_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/bundle"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-bundle-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// buildBundle creates a well-formed bundle map with a valid sha256 signature.
func buildBundle(t *testing.T, version int, cedarText string) map[string]any {
	t.Helper()
	b := map[string]any{
		"version":            version,
		"bundle_id":          fmt.Sprintf("bundle:v%d", version),
		"compiled_at":        "2026-03-28T21:00:00Z",
		"cedar_text_enforce": cedarText,
		"cedar_text_shadow":  "",
		"enforce_count":      1,
		"shadow_count":       0,
		"tool_count":         0,
		"tool_index":         map[string]any{},
	}
	// Compute signature over content (no "signature" key).
	content, _ := json.Marshal(b)
	sig := "sha256:" + fmt.Sprintf("%x", sha256.Sum256(content))
	b["signature"] = sig
	return b
}

// writeBundleFile marshals b and writes it to dir/current.bundle.
func writeBundleFile(t *testing.T, dir string, b map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "current.bundle"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── DefaultBundleDir ──────────────────────────────────────────────────────────

func TestDefaultBundleDir_EnvVar(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_STATE_DIR", tmp)
	got := bundle.DefaultBundleDir()
	want := filepath.Join(tmp, "bundle")
	if got != want {
		t.Errorf("DefaultBundleDir() = %q, want %q", got, want)
	}
}

func TestDefaultBundleDir_HomeDir(t *testing.T) {
	t.Setenv("KSWITCH_STATE_DIR", "")
	dir := bundle.DefaultBundleDir()
	if dir == "" {
		t.Skip("no home dir available")
	}
	if filepath.Base(dir) != "bundle" {
		t.Errorf("expected last segment to be 'bundle', got %q", dir)
	}
}

// ── Load ──────────────────────────────────────────────────────────────────────

func TestLoad_MissingFile(t *testing.T) {
	tmp := makeTmpDir(t)
	c := bundle.NewLocalBundleCache(tmp)
	_, err := c.Load()
	if err == nil {
		t.Fatal("expected error for missing bundle, got nil")
	}
}

func TestLoad_CorruptJSON(t *testing.T) {
	tmp := makeTmpDir(t)
	if err := os.WriteFile(filepath.Join(tmp, "current.bundle"), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := bundle.NewLocalBundleCache(tmp)
	_, err := c.Load()
	if err == nil {
		t.Fatal("expected error for corrupt JSON, got nil")
	}
}

func TestLoad_NoSignature_DevMode(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_ENV", "")
	b := map[string]any{
		"version":            1,
		"bundle_id":          "bundle:v1",
		"compiled_at":        "2026-03-28T21:00:00Z",
		"cedar_text_enforce": "permit(principal, action, resource);",
		"cedar_text_shadow":  "",
		"enforce_count":      1,
		"shadow_count":       0,
		"tool_count":         0,
		"tool_index":         map[string]any{},
		"signature":          "",
	}
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	loaded, err := c.Load()
	if err != nil {
		t.Fatalf("Load() in dev mode with no signature: %v", err)
	}
	if loaded.Version != 1 {
		t.Errorf("Version = %d, want 1", loaded.Version)
	}
}

func TestLoad_NoSignature_ProductionMode(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_ENV", "production")
	b := map[string]any{
		"version":            1,
		"bundle_id":          "bundle:v1",
		"compiled_at":        "2026-03-28T21:00:00Z",
		"cedar_text_enforce": "permit(principal, action, resource);",
		"cedar_text_shadow":  "",
		"enforce_count":      1,
		"shadow_count":       0,
		"tool_count":         0,
		"tool_index":         map[string]any{},
		"signature":          "",
	}
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	_, err := c.Load()
	if err == nil {
		t.Fatal("expected signature verification failure in production, got nil")
	}
}

func TestLoad_ValidSignature(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 5, "permit(principal, action, resource);")
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	loaded, err := c.Load()
	if err != nil {
		t.Fatalf("Load() with valid signature: %v", err)
	}
	if loaded.Version != 5 {
		t.Errorf("Version = %d, want 5", loaded.Version)
	}
	if loaded.EnforceCount != 1 {
		t.Errorf("EnforceCount = %d, want 1", loaded.EnforceCount)
	}
}

func TestLoad_TamperedBundle(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 5, "permit(principal, action, resource);")
	// Tamper with cedar text after signing.
	b["cedar_text_enforce"] = "forbid(principal, action, resource);"
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	_, err := c.Load()
	if err == nil {
		t.Fatal("expected signature verification to fail on tampered bundle, got nil")
	}
}

// ── GetOrLoad / Invalidate ────────────────────────────────────────────────────

func TestGetOrLoad_CachesResult(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 3, "permit(principal, action, resource);")
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	got1 := c.GetOrLoad()
	got2 := c.GetOrLoad()
	if got1 == nil || got2 == nil {
		t.Fatal("GetOrLoad() returned nil")
	}
	if got1 != got2 {
		t.Error("expected GetOrLoad() to return same pointer on second call")
	}
}

func TestGetOrLoad_ReturnsNilWhenMissing(t *testing.T) {
	tmp := makeTmpDir(t)
	c := bundle.NewLocalBundleCache(tmp)
	if got := c.GetOrLoad(); got != nil {
		t.Errorf("GetOrLoad() = %v, want nil for missing bundle", got)
	}
}

func TestInvalidate_ClearsCache(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 2, "permit(principal, action, resource);")
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	c.GetOrLoad() // prime cache
	c.Invalidate()
	// Delete the file so if it tries to reload, it returns nil.
	os.Remove(filepath.Join(tmp, "current.bundle"))
	got := c.GetOrLoad()
	if got != nil {
		t.Error("expected nil after Invalidate() and file removal")
	}
}

// ── Store ─────────────────────────────────────────────────────────────────────

func TestStore_WritesAndInvalidates(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 7, "permit(principal, action, resource);")
	c := bundle.NewLocalBundleCache(tmp)
	if err := c.Store(b); err != nil {
		t.Fatalf("Store() error: %v", err)
	}
	loaded := c.GetOrLoad()
	if loaded == nil {
		t.Fatal("GetOrLoad() after Store() returned nil")
	}
	if loaded.Version != 7 {
		t.Errorf("Version = %d, want 7", loaded.Version)
	}
}

// ── RequiresHumanApproval / HasTool ───────────────────────────────────────────

func TestRequiresHumanApproval(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 1, "permit(principal, action, resource);")
	b["tool_index"] = map[string]any{
		"initiate_payment": map[string]any{"requires_human_approval": true},
		"read_data":        map[string]any{"requires_human_approval": false},
	}
	// Recompute signature after modifying tool_index.
	delete(b, "signature")
	content, _ := json.Marshal(b)
	b["signature"] = "sha256:" + fmt.Sprintf("%x", sha256.Sum256(content))
	writeBundleFile(t, tmp, b)

	c := bundle.NewLocalBundleCache(tmp)
	loaded := c.GetOrLoad()
	if loaded == nil {
		t.Fatal("bundle load failed")
	}
	if !loaded.RequiresHumanApproval("initiate_payment") {
		t.Error("expected initiate_payment to require human approval")
	}
	if loaded.RequiresHumanApproval("read_data") {
		t.Error("expected read_data NOT to require human approval")
	}
	if loaded.RequiresHumanApproval("unknown_tool") {
		t.Error("expected unknown_tool NOT to require human approval")
	}
}

// ── IsStale ───────────────────────────────────────────────────────────────────

func TestIsStale_FreshBundle(t *testing.T) {
	tmp := makeTmpDir(t)
	b := buildBundle(t, 1, "permit(principal, action, resource);")
	writeBundleFile(t, tmp, b)
	c := bundle.NewLocalBundleCache(tmp)
	loaded := c.GetOrLoad()
	if loaded == nil {
		t.Fatal("bundle load failed")
	}
	if loaded.IsStale("medium") {
		t.Error("freshly loaded bundle should not be stale")
	}
}

// ── GetVersion ────────────────────────────────────────────────────────────────

func TestGetVersion_ReturnsVersionOrZero(t *testing.T) {
	tmp := makeTmpDir(t)
	c := bundle.NewLocalBundleCache(tmp)
	if v := c.GetVersion(); v != 0 {
		t.Errorf("GetVersion() on empty cache = %d, want 0", v)
	}
	b := buildBundle(t, 9, "permit(principal, action, resource);")
	writeBundleFile(t, tmp, b)
	if v := c.GetVersion(); v != 9 {
		t.Errorf("GetVersion() = %d, want 9", v)
	}
}
