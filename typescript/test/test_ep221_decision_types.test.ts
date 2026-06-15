import { describe, it } from "node:test";
import assert from "node:assert/strict";

import type {
  DecisionExplanation,
  MCPCallEnforcementResponse,
  PolicyContextSnapshot,
} from "../src/types.js";
import type { LocalDecision } from "../src/local_pdp/types.js";

describe("EP-221 TypeScript decision type propagation", () => {
  it("parses MCP enforcement responses with optional context evidence", () => {
    const snapshot: PolicyContextSnapshot = {
      schema_version: "kswitch.policy_context.v1",
      context_snapshot_id: "pcs_01JTS",
      decision_id: "dec_01JTS",
      agent_id: "agent:test",
      policy: {
        context_snapshot_digest: "sha256:ctx",
        policy_bundle_digest: "sha256:bundle",
        context_hash: "sha256:ctx-input",
        pdp_input_hash: "sha256:pdp",
      },
      tool_request: {
        request_hash: "sha256:req",
      },
      source_status: {
        missing: ["identity.device_id"],
        unavailable_optional: ["telemetry.agent_session_id"],
        advisory: ["runtime.model_id"],
      },
      replay: {
        request_hash: "sha256:req",
        context_hash: "sha256:ctx",
        pdp_input_hash: "sha256:pdp",
      },
      integrity: {
        binding_state: "append_only_audit_record_bound",
        snapshot_binding_digest: "sha256:binding",
        audit_record_id: "audit_ep221",
      },
    };

    const explanation: DecisionExplanation = {
      schema_version: "kswitch.decision_explanation.v1",
      decision_id: "dec_01JTS",
      context_snapshot_id: "pcs_01JTS",
      outcome: "deny",
      reason: "device_context_missing",
      deny_reason: "VALIDATION",
      escalation_hint: "none",
      evaluation_mode: "central",
      reason_summary: "Managed-mode policy requires device identity.",
      missing_required_signals: ["identity.device_id"],
      advisory_signals_ignored_for_allow: ["runtime.model_id"],
    };

    const parsed = JSON.parse(JSON.stringify({
      allowed: false,
      reason: "device_context_missing",
      outcome: "deny",
      decision_path: ["mcp_call", "policy_context"],
      context_snapshot_id: "pcs_01JTS",
      context_snapshot_digest: "sha256:ctx",
      context_snapshot: snapshot,
      decision_explanation: explanation,
    })) as MCPCallEnforcementResponse;

    assert.equal(parsed.allowed, false);
    assert.equal(parsed.outcome, "deny");
    assert.equal(parsed.context_snapshot_id, "pcs_01JTS");
    assert.equal(parsed.context_snapshot_digest, "sha256:ctx");
    assert.equal(parsed.context_snapshot?.source_status?.missing?.[0], "identity.device_id");
    assert.equal(parsed.context_snapshot?.policy?.pdp_input_hash, "sha256:pdp");
    assert.equal(parsed.context_snapshot?.tool_request?.request_hash, "sha256:req");
    assert.equal(parsed.context_snapshot?.replay?.pdp_input_hash, "sha256:pdp");
    assert.equal(parsed.context_snapshot?.integrity?.audit_record_id, "audit_ep221");
    assert.equal(parsed.decision_explanation?.outcome, "deny");
    assert.equal(
      parsed.decision_explanation?.advisory_signals_ignored_for_allow?.[0],
      "runtime.model_id",
    );
  });

  it("keeps legacy enforcement responses valid when EP-221 fields are absent", () => {
    const legacy: MCPCallEnforcementResponse = {
      allowed: true,
      reason: "allowed",
      outcome: "allow",
      decision_path: ["mcp_call", "policy_allow"],
    };

    assert.equal(legacy.allowed, true);
    assert.equal(legacy.context_snapshot_id, undefined);
    assert.equal(legacy.context_snapshot_digest, undefined);
    assert.equal(legacy.context_snapshot, undefined);
    assert.equal(legacy.decision_explanation, undefined);
  });

  it("allows LocalDecision to carry optional evidence without changing outcome values", () => {
    const localAllow: LocalDecision = {
      outcome: "allow",
      reason: "local_allow",
      allowed: true,
      decisionPath: ["local_pdp", "policy_allow"],
      obligations: [],
      outputPolicy: null,
      enforcementId: "dec_local",
      evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
      bundleVersion: "2026-06-03.1",
      contextPackId: "ctx_pack",
      riskTier: "medium",
      agentId: "agent:test",
      mcpServerId: "mcp:test",
      toolName: "tool.read",
      evaluatedAt: 0,
      context_snapshot_id: "pcs_local",
      context_snapshot_digest: "sha256:local",
      decision_explanation: {
        context_snapshot_id: "pcs_local",
        outcome: "allow",
        evaluation_mode: "local_pdp",
      },
    };

    const localConditional: LocalDecision = {
      ...localAllow,
      outcome: "conditional",
      reason: "bundle_unavailable",
      allowed: false,
    };

    assert.equal(localAllow.outcome, "allow");
    assert.equal(localAllow.allowed, true);
    assert.equal(localAllow.context_snapshot_id, "pcs_local");
    assert.equal(localConditional.outcome, "conditional");
    assert.equal(localConditional.allowed, false);
  });
});
