// Package kswitch — DenyReason (EP-050 W4 parity with server).
//
// Wire parity: matches app/enforcement/reason_class.py::DenyReason (server),
// sdks/python/kswitch/deny_reason.py (Python), and
// sdks/typescript/src/denyReason.ts (TypeScript).
//
// Forward compatibility: ParseDenyReason returns DenyReasonUnknown for any
// value this SDK does not yet recognise — never panics.

package kswitch

import "strings"

// DenyReason is the semantic category of an enforcement deny decision.
type DenyReason string

const (
	DenyReasonPolicy      DenyReason = "POLICY"
	DenyReasonGovernance  DenyReason = "GOVERNANCE"
	DenyReasonUnavailable DenyReason = "UNAVAILABLE"
	DenyReasonValidation  DenyReason = "VALIDATION"
	DenyReasonUnknown     DenyReason = "UNKNOWN"
)

// denyReasonKnown is the set of values this SDK recognises.  Keep in sync
// with the constants above.
var denyReasonKnown = map[DenyReason]struct{}{
	DenyReasonPolicy:      {},
	DenyReasonGovernance:  {},
	DenyReasonUnavailable: {},
	DenyReasonValidation:  {},
	DenyReasonUnknown:     {},
}

// ParseDenyReason parses a string into a DenyReason.  Unknown values return
// DenyReasonUnknown rather than an error — enforcement callers should never
// fail-closed on a *category* mismatch (the wire-level `decision` field is
// the source of truth; this is metadata).
func ParseDenyReason(raw string) DenyReason {
	if raw == "" {
		return DenyReasonUnknown
	}
	v := DenyReason(strings.ToUpper(strings.TrimSpace(raw)))
	if _, ok := denyReasonKnown[v]; ok {
		return v
	}
	return DenyReasonUnknown
}

// String implements fmt.Stringer.
func (r DenyReason) String() string { return string(r) }
