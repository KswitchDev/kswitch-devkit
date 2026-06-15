// backcompat_test.go -- SDK one-version-back contract test scaffolding (Go).
//
// Closes the EP-050 §W4 acceptance-criterion gap:
//
//	"SDK contract tests pass against both current and one-version-back server"
//
//	-- docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md §W4
//	   (retrieved 2026-04-22)
//
// This file is scaffolding. The original Wave 1 Agent F version targeted
// v1.32/v1.34, but that became stale after the product advanced to
// v1.37.1-pg. This refresh retargeted the placeholders to the frozen fixture
// line: v1.37.1-pg fixture pin and v1.37.0-pg one-version-back. The real payload
// assertions are filled in by Round 2 once v1.37.0 schema fixtures under
// sdks/_schemas/v1.37.0/ are populated from the v1.37.0 OpenAPI spec -- see
// sdks/_schemas/v1.37.0/README.md for the retrieval plan.
//
// # Version target note
//
// The platform may now be newer than these fixtures. The frozen fixture pin is
// 1.37.1-pg, and the previous released tag is v1.37.0-pg. The active
// historical "one-version-back" scaffold is therefore v1.37.0.
//
// # Vendor citations
//
//   - Go testing.T.Skip semantics:
//     https://pkg.go.dev/testing#T.Skip (retrieved 2026-04-22). Go's
//     testing package has no first-class xfail marker; the closest
//     bank-grade equivalent is t.Skip with an explicit reason message.
//     The skip is reported under `go test -v`, will NOT silently pass if
//     the body is later populated incorrectly, and Round 2 removes the
//     Skip and adds a real round-trip assertion against the fixture bytes.
//
//   - EP-050 §W4 spec:
//     docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md
//     (retrieved 2026-04-22).
//
// # Assumption class (CLAUDE.md engineering principle 3)
//
// The v1.37.0 and v1.37.1 release pins are vendor-documented by git tags and
// their tagged root VERSION files. The concrete wire-contract payloads remain
// inferred / untested until Round 2 commits real schema exports into
// sdks/_schemas/v1.37.0/ and sdks/_schemas/v1.37.1/.
package kswitch_sdk_backcompat_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// SchemaVersions are the contract versions this file exercises.
//
//	v1.37.1 = frozen fixture pin.
//	v1.37.0 = one-version-back (previous release tag).
var SchemaVersions = [...]string{"v1.37.0", "v1.37.1"}

const xfailReason = "v1.37.0/v1.37.1 schema pins pending -- spec acceptance criterion " +
	"EP-050 §W4. Scaffolding leaves bodies unpopulated until Round 2 exports " +
	"the OpenAPI artefacts into sdks/_schemas/v1.37.0/ and " +
	"sdks/_schemas/v1.37.1/."

// schemasRoot returns the absolute path to sdks/_schemas/ relative to the
// location of this test file. Used by TestBackcompat_SchemaFixtureDirectoriesExist
// (the one non-skipped collection-time guard).
func schemasRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed -- cannot resolve schemas root")
	}
	// sdks/go/backcompat_test.go -> sdks/_schemas/
	return filepath.Join(filepath.Dir(thisFile), "..", "_schemas")
}

// TestBackcompat_SchemaFixtureDirectoriesExist is the one real (non-skipped)
// assertion in this scaffolding file: both schema version directories and
// their pin-reference READMEs must exist. Guards against a future refactor
// silently deleting the fixtures and making the skipped contract tests a
// green-lie.
func TestBackcompat_SchemaFixtureDirectoriesExist(t *testing.T) {
	root := schemasRoot(t)
	for _, version := range SchemaVersions {
		versionDir := filepath.Join(root, version)
		info, err := os.Stat(versionDir)
		if err != nil {
			t.Fatalf("expected schema fixture dir %s: %v "+
				"(see sdks/_schemas/%s/README.md for the pin reference)",
				versionDir, err, version)
		}
		if !info.IsDir() {
			t.Fatalf("expected %s to be a directory", versionDir)
		}
		readme := filepath.Join(versionDir, "README.md")
		if _, err := os.Stat(readme); err != nil {
			t.Fatalf("expected pin-reference README at %s: %v "+
				"(documents retrieval date, version, and assumption class "+
				"per CLAUDE.md engineering principles §3)",
				readme, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Contract placeholders. All skipped with xfailReason. Round 2 replaces each
// body with a real round-trip test against the v1.37.0 / v1.37.1 fixtures and
// removes the Skip call.
//
// All placeholder names are shared verbatim with the Python and TypeScript
// siblings (test_backcompat.py, backcompat.test.ts) -- CamelCased for Go.
// -----------------------------------------------------------------------------

func TestBackcompat_RegisterAgentRequestShapeV1_37_0Accepted(t *testing.T) {
	// TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
	//
	// Contract: POST /api/v1/agents request envelope produced by the current
	// SDK must remain accepted by a v1.37.0 server. The v1.37.1 SDK MUST NOT add
	// new REQUIRED fields. Additive optional fields are allowed; removing or
	// renaming required fields is breaking.
	t.Skipf("XFAIL: %s", xfailReason)
}

func TestBackcompat_EvaluateEnforcementV1_37_0ResponseShape(t *testing.T) {
	// TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
	//
	// Contract: POST /api/v1/enforcement/evaluate v1.37.0 response envelope
	// must still deserialise cleanly through the v1.37.1 SDK. Additive fields
	// in v1.37.1 must remain optional for older server payloads.
	t.Skipf("XFAIL: %s", xfailReason)
}

func TestBackcompat_WimseChainV1_37_0EnvelopeAccepted(t *testing.T) {
	// TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
	//
	// Contract: WIMSE delegation chain envelope produced at v1.37.0 must verify
	// under the current SDK's chain validator (sdks/go/kswitch/wimse/).
	// Per-hop ES256 signing, chain depth limit, TTL, and the WIMSE-Assertion
	// header encoding (space-separated JWTs, 8KB cap) are all frozen at D5.
	t.Skipf("XFAIL: %s", xfailReason)
}

func TestBackcompat_KillSwitchAckV1_37_0ShapeUnchanged(t *testing.T) {
	// TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
	//
	// Contract: kill-switch ack payload MUST be byte-for-byte compatible
	// between v1.37.0 and v1.37.1. Audit-critical surface under
	// .claude/rules/compliance.md.
	t.Skipf("XFAIL: %s", xfailReason)
}

func TestBackcompat_DenyReasonV1_37_0ForwardCompatUnknown(t *testing.T) {
	// TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
	//
	// Forward-compat: deny reason parsing must keep the UNKNOWN fallback:
	//   - response without deny_reason -> SDK parser returns DenyReason UNKNOWN
	//   - response with an unknown deny_reason value -> DenyReason UNKNOWN
	// Invariant lives in sdks/go/kswitch/deny_reason.go.
	t.Skipf("XFAIL: %s", xfailReason)
}
