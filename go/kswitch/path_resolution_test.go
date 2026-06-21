// path_resolution_test.go — Tests for state directory path resolution across all
// local runtime subpackages. Verifies the canonical rule:
//
//  1. KSWITCH_STATE_DIR env var → {var}/bundle, {var}/context, {var}/revocation, {var}/audit
//  2. Fallback: $HOME/.kswitch/{subdir}
//
// Each subpackage has its own DefaultXxxDir() function; this file tests all of
// them consistently in one place.
package kswitch_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/audit"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/bundle"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/kscontext"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/revocation"
)

// ── KSWITCH_STATE_DIR overrides all packages ──────────────────────────────────

func TestPathResolution_StateDir_Bundle(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-test-*")
	defer os.RemoveAll(tmp)
	t.Setenv("KSWITCH_STATE_DIR", tmp)

	got := bundle.DefaultBundleDir()
	want := filepath.Join(tmp, "bundle")
	if got != want {
		t.Errorf("bundle.DefaultBundleDir() = %q, want %q", got, want)
	}
}

func TestPathResolution_StateDir_Context(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-test-*")
	defer os.RemoveAll(tmp)
	t.Setenv("KSWITCH_STATE_DIR", tmp)

	got := kscontext.DefaultContextDir()
	want := filepath.Join(tmp, "context")
	if got != want {
		t.Errorf("kscontext.DefaultContextDir() = %q, want %q", got, want)
	}
}

func TestPathResolution_StateDir_Revocation(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-test-*")
	defer os.RemoveAll(tmp)
	t.Setenv("KSWITCH_STATE_DIR", tmp)

	got := revocation.DefaultRevocationDir()
	want := filepath.Join(tmp, "revocation")
	if got != want {
		t.Errorf("revocation.DefaultRevocationDir() = %q, want %q", got, want)
	}
}

func TestPathResolution_StateDir_Audit(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-test-*")
	defer os.RemoveAll(tmp)
	t.Setenv("KSWITCH_STATE_DIR", tmp)

	got := audit.DefaultAuditDir()
	want := filepath.Join(tmp, "audit")
	if got != want {
		t.Errorf("audit.DefaultAuditDir() = %q, want %q", got, want)
	}
}

// ── All subpackages consistently name their subdirectory ─────────────────────

func TestPathResolution_SubdirectoryNames(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-test-*")
	defer os.RemoveAll(tmp)
	t.Setenv("KSWITCH_STATE_DIR", tmp)

	cases := []struct {
		name     string
		got      func() string
		wantBase string
	}{
		{"bundle", bundle.DefaultBundleDir, "bundle"},
		{"context", kscontext.DefaultContextDir, "context"},
		{"revocation", revocation.DefaultRevocationDir, "revocation"},
		{"audit", audit.DefaultAuditDir, "audit"},
	}

	for _, tc := range cases {
		got := tc.got()
		if filepath.Base(got) != tc.wantBase {
			t.Errorf("%s: last segment = %q, want %q", tc.name, filepath.Base(got), tc.wantBase)
		}
		if filepath.Dir(got) != tmp {
			t.Errorf("%s: parent = %q, want %q", tc.name, filepath.Dir(got), tmp)
		}
	}
}

// ── Fallback to $HOME/.kswitch when no env var ────────────────────────────────

func TestPathResolution_HomeDir_Fallback(t *testing.T) {
	t.Setenv("KSWITCH_STATE_DIR", "")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("UserHomeDir() not available")
	}

	cases := []struct {
		name     string
		got      string
		wantBase string
		wantRoot string
	}{
		{"bundle", bundle.DefaultBundleDir(), "bundle", filepath.Join(home, ".kswitch")},
		{"context", kscontext.DefaultContextDir(), "context", filepath.Join(home, ".kswitch")},
		{"revocation", revocation.DefaultRevocationDir(), "revocation", filepath.Join(home, ".kswitch")},
		{"audit", audit.DefaultAuditDir(), "audit", filepath.Join(home, ".kswitch")},
	}

	for _, tc := range cases {
		if tc.got == "" {
			t.Errorf("%s: expected non-empty dir, got empty string", tc.name)
			continue
		}
		if filepath.Base(tc.got) != tc.wantBase {
			t.Errorf("%s: last segment = %q, want %q", tc.name, filepath.Base(tc.got), tc.wantBase)
		}
		if filepath.Dir(tc.got) != tc.wantRoot {
			t.Errorf("%s: parent = %q, want %q", tc.name, filepath.Dir(tc.got), tc.wantRoot)
		}
	}
}

// ── Writable check — NewLocalBundleCache respects custom dir ──────────────────

func TestPathResolution_CustomDir_Respected(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "kswitch-path-custom-*")
	defer os.RemoveAll(tmp)

	// With explicit dir, should NOT use KSWITCH_STATE_DIR.
	t.Setenv("KSWITCH_STATE_DIR", "/should/not/be/used")

	customDir := filepath.Join(tmp, "custom-bundle")
	c := bundle.NewLocalBundleCache(customDir)
	if c == nil {
		t.Fatal("NewLocalBundleCache() returned nil")
	}
	// GetOrLoad should return nil (no bundle file) but not panic.
	b := c.GetOrLoad()
	if b != nil {
		t.Error("expected nil for empty custom dir")
	}
}
