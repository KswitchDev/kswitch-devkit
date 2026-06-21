package kswitch

import (
	"encoding/json"
	"testing"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/localpdp"
)

func TestEP221EnforcementDecisionUnmarshalOldPayload(t *testing.T) {
	payload := []byte(`{
		"allowed": true,
		"reason": "allowed",
		"outcome": "allow",
		"decision_path": ["server", "cedar_allowed"],
		"evaluation_mode": "central",
		"context_pack_id": "ctx_legacy"
	}`)

	var decision EnforcementDecision
	if err := json.Unmarshal(payload, &decision); err != nil {
		t.Fatalf("unmarshal legacy EnforcementDecision: %v", err)
	}

	if !decision.Allowed || decision.Outcome != "allow" {
		t.Fatalf("decision semantics changed: allowed=%v outcome=%q", decision.Allowed, decision.Outcome)
	}
	if decision.ContextSnapshotID != "" {
		t.Fatalf("ContextSnapshotID = %q, want empty for legacy payload", decision.ContextSnapshotID)
	}
	if decision.ContextSnapshot != nil {
		t.Fatalf("ContextSnapshot = %#v, want nil for legacy payload", decision.ContextSnapshot)
	}
	if decision.DecisionExplanation != nil {
		t.Fatalf("DecisionExplanation = %#v, want nil for legacy payload", decision.DecisionExplanation)
	}
}

func TestEP221EnforcementDecisionUnmarshalContextEvidence(t *testing.T) {
	payload := []byte(`{
		"allowed": false,
		"reason": "device_context_missing",
		"risk_tier": "high",
		"outcome": "deny",
		"decision_path": ["server", "context_missing", "cedar_denied"],
		"evaluation_mode": "central",
		"context_snapshot_id": "pcs_01JEP221",
		"context_snapshot_digest": "sha256:snapshot",
		"context_snapshot": {
			"schema_version": "kswitch.policy_context.v1",
			"context_snapshot_id": "pcs_01JEP221",
			"policy": {
				"context_hash": "sha256:ctx",
				"pdp_input_hash": "sha256:pdp"
			},
			"tool_request": {
				"request_hash": "sha256:req"
			},
			"replay": {
				"request_hash": "sha256:req",
				"context_hash": "sha256:ctx",
				"pdp_input_hash": "sha256:pdp"
			},
			"integrity": {
				"binding_state": "append_only_audit_record_bound",
				"snapshot_binding_digest": "sha256:binding",
				"audit_record_id": "audit_ep221"
			},
			"source_status": {
				"missing": ["identity.device_id"],
				"advisory": ["runtime.model_id"]
			}
		},
		"decision_explanation": {
			"schema_version": "kswitch.decision_explanation.v1",
			"context_snapshot_id": "pcs_01JEP221",
			"outcome": "deny",
			"reason": "device_context_missing",
			"deny_reason": "VALIDATION",
			"missing_required_signals": ["identity.device_id"],
			"advisory_signals_ignored_for_allow": ["runtime.model_id"]
		}
	}`)

	var decision EnforcementDecision
	if err := json.Unmarshal(payload, &decision); err != nil {
		t.Fatalf("unmarshal EP-221 EnforcementDecision: %v", err)
	}

	if decision.Allowed || decision.Outcome != "deny" {
		t.Fatalf("decision semantics changed: allowed=%v outcome=%q", decision.Allowed, decision.Outcome)
	}
	if decision.ContextSnapshotID != "pcs_01JEP221" {
		t.Fatalf("ContextSnapshotID = %q, want pcs_01JEP221", decision.ContextSnapshotID)
	}
	if decision.ContextSnapshotDigest != "sha256:snapshot" {
		t.Fatalf("ContextSnapshotDigest = %q, want sha256:snapshot", decision.ContextSnapshotDigest)
	}
	if got := decision.ContextSnapshot["schema_version"]; got != "kswitch.policy_context.v1" {
		t.Fatalf("context snapshot schema_version = %#v", got)
	}
	replay := decision.ContextSnapshot["replay"].(map[string]any)
	if got := replay["pdp_input_hash"]; got != "sha256:pdp" {
		t.Fatalf("context snapshot replay pdp_input_hash = %#v", got)
	}
	integrity := decision.ContextSnapshot["integrity"].(map[string]any)
	if got := integrity["audit_record_id"]; got != "audit_ep221" {
		t.Fatalf("context snapshot integrity audit_record_id = %#v", got)
	}
	if got := decision.DecisionExplanation["schema_version"]; got != "kswitch.decision_explanation.v1" {
		t.Fatalf("decision explanation schema_version = %#v", got)
	}
}

func TestEP221LocalDecisionUnmarshalOldPayload(t *testing.T) {
	payload := []byte(`{
		"outcome": "allow",
		"reason": "allowed",
		"allowed": true,
		"decision_path": ["local_sdk", "cedar_allowed"],
		"obligations": [],
		"enforcement_id": "enf_legacy",
		"evaluation_mode": "LOCAL_RUNTIME_GO",
		"bundle_version": "bundle_legacy",
		"context_pack_id": "ctx_legacy",
		"risk_tier": "low",
		"agent_id": "agent:test",
		"mcp_server_id": "mcp:test",
		"tool_name": "read",
		"evaluated_at": 1710000000
	}`)

	var decision localpdp.LocalDecision
	if err := json.Unmarshal(payload, &decision); err != nil {
		t.Fatalf("unmarshal legacy LocalDecision: %v", err)
	}

	if !decision.Allowed || decision.Outcome != "allow" {
		t.Fatalf("local decision semantics changed: allowed=%v outcome=%q", decision.Allowed, decision.Outcome)
	}
	if decision.ContextSnapshotID != "" {
		t.Fatalf("ContextSnapshotID = %q, want empty for legacy payload", decision.ContextSnapshotID)
	}
	if decision.ContextSnapshot != nil {
		t.Fatalf("ContextSnapshot = %#v, want nil for legacy payload", decision.ContextSnapshot)
	}
	if decision.DecisionExplanation != nil {
		t.Fatalf("DecisionExplanation = %#v, want nil for legacy payload", decision.DecisionExplanation)
	}
}

func TestEP221LocalDecisionUnmarshalContextEvidence(t *testing.T) {
	payload := []byte(`{
		"outcome": "conditional",
		"reason": "bundle_missing",
		"allowed": false,
		"decision_path": ["local_sdk", "bundle_missing"],
		"obligations": [],
		"enforcement_id": "enf_01JEP221",
		"evaluation_mode": "LOCAL_RUNTIME_GO",
		"bundle_version": "",
		"context_pack_id": "ctx_01JEP221",
		"risk_tier": "medium",
		"agent_id": "agent:test",
		"mcp_server_id": "mcp:test",
		"tool_name": "read",
		"evaluated_at": 1710000000,
		"context_snapshot_id": "pcs_local_01JEP221",
		"context_snapshot_digest": "sha256:local-snapshot",
		"context_snapshot": {
			"schema_version": "kswitch.policy_context.v1",
			"context_snapshot_id": "pcs_local_01JEP221"
		},
		"decision_explanation": {
			"schema_version": "kswitch.decision_explanation.v1",
			"context_snapshot_id": "pcs_local_01JEP221",
			"outcome": "conditional",
			"escalation_hint": "server_confirmation_required"
		}
	}`)

	var decision localpdp.LocalDecision
	if err := json.Unmarshal(payload, &decision); err != nil {
		t.Fatalf("unmarshal EP-221 LocalDecision: %v", err)
	}

	if decision.Allowed || decision.Outcome != "conditional" {
		t.Fatalf("local decision semantics changed: allowed=%v outcome=%q", decision.Allowed, decision.Outcome)
	}
	if decision.ContextSnapshotID != "pcs_local_01JEP221" {
		t.Fatalf("ContextSnapshotID = %q, want pcs_local_01JEP221", decision.ContextSnapshotID)
	}
	if decision.ContextSnapshotDigest != "sha256:local-snapshot" {
		t.Fatalf("ContextSnapshotDigest = %q, want sha256:local-snapshot", decision.ContextSnapshotDigest)
	}
	if got := decision.DecisionExplanation["outcome"]; got != "conditional" {
		t.Fatalf("decision explanation outcome = %#v", got)
	}
}
