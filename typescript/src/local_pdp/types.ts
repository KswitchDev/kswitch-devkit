/**
 * Local PDP types — TypeScript equivalents of Python LocalDecision.
 *
 * These mirror the Python LocalDecision dataclass exactly.
 * evaluation_mode is "LOCAL_RUNTIME_TYPESCRIPT" for TypeScript SDK decisions.
 */

import type { DecisionContextEvidence } from "../types.js";
import * as crypto from "node:crypto";

// ── Output policy modes ───────────────────────────────────────────────────────

export type OutputMode =
  | "allow_raw"
  | "mask_fields"
  | "deny_export"
  | "truncate"
  | "summarize_only"
  | "require_release";

export interface LocalOutputPolicy {
  mode: OutputMode;
  masking_classifications: string[];
  max_output_bytes?: number;
}

// ── Obligation ────────────────────────────────────────────────────────────────

export interface LocalObligation {
  type: string;
  obligation_type: string;
  detail?: string;
  level?: string;
  parameters?: Record<string, unknown>;
  [key: string]: unknown;
}

// ── Decision outcome ──────────────────────────────────────────────────────────

export type LocalDecisionOutcome = "allow" | "deny" | "conditional";

// ── Local decision ────────────────────────────────────────────────────────────

/**
 * Result of a local PDP evaluation.
 * Mirrors Python LocalDecision dataclass for core decision fields.
 * EP-221 evidence references are optional and type-only; evaluators do not
 * derive them or change allow/deny/conditional semantics.
 */
export interface LocalDecision extends DecisionContextEvidence {
  /** Outcome: "allow" | "deny" | "conditional" */
  outcome: LocalDecisionOutcome;
  reason: string;
  allowed: boolean;
  decisionPath: string[];
  obligations: LocalObligation[];
  outputPolicy: LocalOutputPolicy | null;
  enforcementId: string;
  /** Always "LOCAL_RUNTIME_TYPESCRIPT" for TypeScript SDK local decisions */
  evaluationMode: string;
  bundleVersion: string;
  contextPackId: string;
  riskTier: string;
  agentId: string;
  mcpServerId: string;
  toolName: string;
  evaluatedAt: number;  // Unix timestamp ms
}

function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortForJson(v)]),
    );
  }
  return value;
}

function sha256(value: unknown): string {
  return "sha256:" + crypto
    .createHash("sha256")
    .update(JSON.stringify(sortForJson(value)), "utf-8")
    .digest("hex");
}

function digestText(value: string): string {
  return sha256(value);
}

function boundedDecisionPath(path: string[]): string[] {
  return path.map((segment) => (
    segment.startsWith("cedar_error:") ? "cedar_error" : segment
  ));
}

function ep221SourceStatus(partial: Omit<LocalDecision, "enforcementId" | "evaluatedAt" | "evaluationMode">) {
  const presentDeterministic = [
    "identity.agent_id",
    "tool_request.mcp_server_id",
    "policy.decision_path",
    "runtime.risk_tier",
  ];
  if (partial.toolName) {
    presentDeterministic.push("tool_request.tool_name");
  }
  if (partial.bundleVersion) {
    presentDeterministic.push("policy.bundle_version");
  }
  if (partial.contextPackId) {
    presentDeterministic.push("runtime.context_pack_id");
  }

  return {
    present_deterministic: presentDeterministic,
    unavailable_optional: [
      "tenant_id",
      "requester",
      "agent_session_id",
      "active_artefacts",
      "graph_context",
    ],
  };
}

function ep221MissingSignals(partial: Omit<LocalDecision, "enforcementId" | "evaluatedAt" | "evaluationMode">): string[] {
  const missing: string[] = [];
  if (partial.reason.includes("context_pack")) {
    missing.push("runtime.context_pack");
  }
  if (partial.reason.includes("bundle")) {
    missing.push("policy.bundle");
  }
  if (partial.reason.includes("cedar_wasm")) {
    missing.push("policy.cedar_runtime");
  }
  return missing;
}

function ep221StaleSignals(partial: Omit<LocalDecision, "enforcementId" | "evaluatedAt" | "evaluationMode">): string[] {
  return partial.reason.includes("stale") ? ["revocation_or_policy_freshness"] : [];
}

function buildEp221Evidence(
  partial: Omit<LocalDecision, "enforcementId" | "evaluatedAt" | "evaluationMode">,
  enforcementId: string,
  evaluatedAt: number,
): Required<DecisionContextEvidence> {
  const contextSnapshotId = `pcs_${sha256({
    decision_id: enforcementId,
    agent_id_digest: digestText(partial.agentId),
    mcp_server_id_digest: digestText(partial.mcpServerId),
    tool_name_digest: partial.toolName ? digestText(partial.toolName) : "",
    evaluated_at: evaluatedAt,
  }).slice("sha256:".length, "sha256:".length + 32)}`;

  const replayMaterial = {
    outcome: partial.outcome,
    reason: partial.reason,
    decision_path: boundedDecisionPath(partial.decisionPath),
    agent_id_digest: digestText(partial.agentId),
    mcp_server_id_digest: digestText(partial.mcpServerId),
    tool_name_digest: partial.toolName ? digestText(partial.toolName) : null,
    bundle_version_digest: partial.bundleVersion ? digestText(partial.bundleVersion) : null,
    context_pack_id_digest: partial.contextPackId ? digestText(partial.contextPackId) : null,
    risk_tier: partial.riskTier,
  };

  const sourceStatus = ep221SourceStatus(partial);
  const missingRequiredSignals = ep221MissingSignals(partial);
  const staleSignals = ep221StaleSignals(partial);

  const snapshot = {
    schema_version: "kswitch.policy_context.v1",
    context_snapshot_id: contextSnapshotId,
    decision_id: enforcementId,
    agent_id: digestText(partial.agentId),
    mode: {
      evaluation_mode: "local_pdp",
      sdk_runtime: "typescript",
      outcome: partial.outcome,
    },
    policy: {
      bundle_version_digest: partial.bundleVersion ? digestText(partial.bundleVersion) : "unavailable_optional",
      decision_path_digest: sha256(boundedDecisionPath(partial.decisionPath)),
      obligation_count: partial.obligations.length,
    },
    identity: {
      agent_id_digest: digestText(partial.agentId),
      agent_session_id: "unavailable_optional",
      requester: "unavailable_optional",
    },
    runtime: {
      risk_tier: partial.riskTier,
      context_pack_id_digest: partial.contextPackId ? digestText(partial.contextPackId) : "unavailable_optional",
      evaluated_at_ms: evaluatedAt,
      offline_local_pdp: true,
    },
    active_artefacts: [],
    tool_request: {
      mcp_server_id_digest: digestText(partial.mcpServerId),
      tool_name_digest: partial.toolName ? digestText(partial.toolName) : "unavailable_optional",
      request_hash: sha256(replayMaterial),
    },
    data_context: {
      output_policy_mode: partial.outputPolicy?.mode ?? "unavailable_optional",
      masking_classifications_count: partial.outputPolicy?.masking_classifications.length ?? 0,
    },
    graph_context: {},
    source_status: sourceStatus,
    replay: {
      request_hash: sha256(replayMaterial),
      context_hash: sha256({
        source_status: sourceStatus,
        risk_tier: partial.riskTier,
        context_pack_id_digest: partial.contextPackId ? digestText(partial.contextPackId) : null,
      }),
      pdp_input_hash: sha256(replayMaterial),
    },
    integrity: {
      binding_state: "digest_bound_no_append_only_record",
      digest_algorithm: "sha256",
    },
  };

  const contextSnapshotDigest = sha256(snapshot);

  return {
    context_snapshot_id: contextSnapshotId,
    context_snapshot_digest: contextSnapshotDigest,
    context_snapshot: {
      ...snapshot,
      integrity: {
        ...snapshot.integrity,
        context_snapshot_digest: contextSnapshotDigest,
      },
    },
    decision_explanation: {
      schema_version: "kswitch.decision_explanation.v1",
      decision_id: enforcementId,
      context_snapshot_id: contextSnapshotId,
      outcome: partial.outcome,
      reason: partial.reason,
      deny_reason: partial.outcome === "deny" ? partial.reason : "",
      escalation_hint: partial.outcome === "conditional" ? "step_up_required" : "none",
      evaluation_mode: "local_pdp",
      policy_enforcement_mode: "local_pdp",
      reason_summary: `TypeScript local PDP returned ${partial.outcome}: ${partial.reason}.`,
      policy_attribution: {
        bundle_version_digest: partial.bundleVersion ? digestText(partial.bundleVersion) : "unavailable_optional",
        context_pack_id_digest: partial.contextPackId ? digestText(partial.contextPackId) : "unavailable_optional",
        matched_policy_ids: [],
        attribution_state: "unavailable_until_per_policy_eval",
        attribution_method: "local_pdp_aggregate_bundle_without_per_policy_eval",
      },
      contributing_signals: boundedDecisionPath(partial.decisionPath),
      missing_required_signals: missingRequiredSignals,
      stale_signals: staleSignals,
      advisory_signals_ignored_for_allow: partial.outcome === "allow" && partial.obligations.length > 0
        ? ["local_obligations_present"]
        : [],
      next_safe_actions: partial.outcome === "conditional"
        ? ["escalate_to_central_pdp_or_refresh_local_context"]
        : [],
    },
  };
}

export function isLocalDecision(d: LocalDecision): boolean {
  return d.outcome === "allow" || d.outcome === "deny";
}

export function needsEscalation(d: LocalDecision): boolean {
  return d.outcome === "conditional";
}

/** Create a new decision with a unique enforcement ID and current timestamp. */
export function makeDecision(
  partial: Omit<LocalDecision, "enforcementId" | "evaluatedAt" | "evaluationMode">,
): LocalDecision {
  const enforcementId = crypto.randomUUID();
  const evaluatedAt = Date.now();
  const evidence = buildEp221Evidence(partial, enforcementId, evaluatedAt);

  return {
    ...partial,
    ...evidence,
    enforcementId,
    evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    evaluatedAt,
  };
}
