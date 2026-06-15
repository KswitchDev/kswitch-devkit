/**
 * LocalPDPEvaluator — in-process Cedar policy evaluation for the TypeScript SDK.
 *
 * Mirrors Python LocalPDPEvaluator 9-step decision sequence exactly.
 *
 * Decision sequence:
 *   0. Stale revocation sync check
 *   1. Revocation cache check  (O(1), in-process)
 *   2. Context pack load       (disk-backed, TTL-aware)
 *   3. Agent status check      (from context pack)
 *   4. Bundle load             (disk-backed, TTL-aware)
 *   5. Cedar evaluate          (@cedar-policy/cedar-wasm/nodejs, synchronous)
 *   6. Shadow policy evaluate  (observe-only)
 *   7. Human-approval gating
 *   8. Output policy derivation
 *   → Return LocalDecision
 *
 * Chosen Node.js evaluation model: SYNCHRONOUS IN-PROCESS CEDAR WASM
 * ─────────────────────────────────────────────────────────────────────
 * The @cedar-policy/cedar-wasm/nodejs variant loads WASM synchronously at
 * module init time. The isAuthorized() function is fully synchronous — no
 * async/await needed. This mirrors Python's cedarpy.is_authorized() behavior.
 *
 * No worker_threads are used. Cedar policy evaluation is CPU-bound but very
 * fast for typical policy sets (< 1ms for O(10) policies). The same trade-off
 * applies as Python: synchronous evaluation on the event loop is acceptable
 * for the decision hot-path. If policy sets grow to O(1000+) policies,
 * worker_threads should be considered (document as known extension point).
 *
 * Fallback: If @cedar-policy/cedar-wasm is not installed, returns
 * LocalDecision(outcome="conditional") → caller escalates to server.
 * This mirrors Python's cedarpy_unavailable path.
 */

import { getRevocationCache, LocalRevocationCache } from "../revocation/cache.js";
import {
  loadCurrentBundle, LocalBundle, isBundleStale,
  bundleHasTool, bundleRequiresHumanApproval,
} from "../bundle/local_cache.js";
import { loadContextPack, LocalContextPack, isContextPackActive } from "../context/local_cache.js";
import {
  LocalDecision, LocalObligation, LocalOutputPolicy,
  makeDecision, LocalDecisionOutcome,
} from "./types.js";

// ── Sensitive field patterns (mirrors Python) ─────────────────────────────────

const SENSITIVE_FIELD_PATTERNS = [
  "ssn", "social_security", "passport", "dob", "date_of_birth",
  "account_number", "card_number", "cvv", "routing_number",
  "tax_id", "ein", "phone", "email", "address", "zip", "postal",
  "salary", "income", "net_worth", "balance", "position", "trade",
  "ticker", "isin", "cusip", "mnpi", "insider",
  "password", "secret", "token", "api_key", "private_key", "credential",
  "health", "diagnosis", "medication", "prescription", "patient",
] as const;

const SENSITIVE_CLASSIFICATIONS = new Set(["PII", "PHI", "MNPI", "Confidential"]);

// ── Cedar WASM availability check ─────────────────────────────────────────────

// ── Cedar WASM types (matching @cedar-policy/cedar-wasm actual API) ───────────

interface CedarEntityUid {
  type: string;
  id: string;
}

interface CedarAuthorizationCall {
  principal: CedarEntityUid;
  action: CedarEntityUid;
  resource: CedarEntityUid;
  context: Record<string, unknown>;
  /** Cedar policy text string (StaticPolicySet shorthand) */
  policies: string;
  entities: unknown[];
}

type CedarDecision = "allow" | "deny";

interface CedarResponse {
  decision: CedarDecision;
}

type CedarAuthorizationAnswer =
  | { type: "success"; response: CedarResponse; warnings: unknown[] }
  | { type: "failure"; errors: unknown[]; warnings: unknown[] };

type CedarIsAuthorized = (call: CedarAuthorizationCall) => CedarAuthorizationAnswer;

/** Lazy-loaded Cedar isAuthorized function. null = not available. */
let _cedarIsAuthorized: CedarIsAuthorized | null | undefined = undefined;

async function getCedarIsAuthorized(): Promise<CedarIsAuthorized | null> {
  if (_cedarIsAuthorized !== undefined) return _cedarIsAuthorized;
  try {
    // Use the Node.js synchronous variant for in-process evaluation
    const mod = await import("@cedar-policy/cedar-wasm/nodejs") as {
      isAuthorized?: CedarIsAuthorized;
    };
    _cedarIsAuthorized = (mod.isAuthorized ?? null) as CedarIsAuthorized | null;
  } catch {
    _cedarIsAuthorized = null;
  }
  return _cedarIsAuthorized;
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

export class LocalPDPEvaluator {
  private readonly getRevCache: () => LocalRevocationCache;

  constructor(opts?: { getRevocationCache?: () => LocalRevocationCache }) {
    this.getRevCache = opts?.getRevocationCache ?? getRevocationCache;
  }

  async evaluate(
    agentId: string,
    mcpServerId: string,
    toolName = "",
    context?: Record<string, unknown>,
  ): Promise<LocalDecision> {
    const decisionPath: string[] = ["local_sdk"];
    const riskTierFromContext = (context?.risk_tier as string) ?? "medium";

    // ── 0. Stale revocation sync check ───────────────────────────────────────
    const staleOutcome = this.checkStaleRevocation(
      agentId, mcpServerId, toolName, decisionPath,
    );
    if (staleOutcome !== null) return staleOutcome;

    // ── 1. Revocation cache check ─────────────────────────────────────────────
    const revCache = this.getRevCache();
    if (revCache.isRevoked(agentId)) {
      return makeDecision({
        outcome: "deny",
        reason: "agent_revoked",
        allowed: false,
        decisionPath: [...decisionPath, "revocation_cache_hit"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: "",
        riskTier: riskTierFromContext,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    // ── 2. Load context pack ──────────────────────────────────────────────────
    const contextPack = loadContextPack(agentId);
    if (contextPack === null) {
      if (["critical", "high"].includes(riskTierFromContext)) {
        return makeDecision({
          outcome: "deny",
          reason: "context_pack_unavailable",
          allowed: false,
          decisionPath: [...decisionPath, "context_miss_denied"],
          obligations: [],
          outputPolicy: null,
          bundleVersion: "",
          contextPackId: "",
          riskTier: riskTierFromContext,
          agentId,
          mcpServerId,
          toolName,
        });
      }
      return makeDecision({
        outcome: "conditional",
        reason: "context_pack_miss",
        allowed: false,
        decisionPath: [...decisionPath, "context_miss_escalate"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: "",
        riskTier: riskTierFromContext,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    const riskTier = contextPack.riskTier || riskTierFromContext;

    // ── 3. Agent status check ─────────────────────────────────────────────────
    if (!isContextPackActive(contextPack)) {
      const reason =
        contextPack.status === "suspended" ? "agent_suspended" : "agent_inactive";
      return makeDecision({
        outcome: "deny",
        reason,
        allowed: false,
        decisionPath: [...decisionPath, `agent_${contextPack.status}`],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: `cp:v${contextPack.packVersion}`,
        riskTier,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    decisionPath.push("agent_active");

    // ── 4. Load bundle ────────────────────────────────────────────────────────
    const bundle = loadCurrentBundle();
    if (bundle === null) {
      return makeDecision({
        outcome: "conditional",
        reason: "bundle_unavailable",
        allowed: false,
        decisionPath: [...decisionPath, "bundle_miss_escalate"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: `cp:v${contextPack.packVersion}`,
        riskTier,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    if (isBundleStale(bundle, riskTier) && ["critical", "high"].includes(riskTier)) {
      return makeDecision({
        outcome: "conditional",
        reason: "bundle_stale",
        allowed: false,
        decisionPath: [...decisionPath, "bundle_stale_escalate"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: `bundle:v${bundle.version}`,
        contextPackId: `cp:v${contextPack.packVersion}`,
        riskTier,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    decisionPath.push(`bundle_v${bundle.version}`);

    // ── 5. Cedar availability check ───────────────────────────────────────────
    const cedarFn = await getCedarIsAuthorized();
    if (cedarFn === null) {
      return makeDecision({
        outcome: "conditional",
        reason: "cedar_wasm_unavailable",
        allowed: false,
        decisionPath: [...decisionPath, "cedar_wasm_missing_escalate"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: `bundle:v${bundle.version}`,
        contextPackId: `cp:v${contextPack.packVersion}`,
        riskTier,
        agentId,
        mcpServerId,
        toolName,
      });
    }

    // ── 6. Cedar evaluation ───────────────────────────────────────────────────
    const obligations: LocalObligation[] = [];

    if (bundle.enforceCount === 0) {
      // No enforce policies → allow
      decisionPath.push("no_policies");
    } else {
      // Build Cedar request — mirrors Python format
      const principal = { type: "Agent", id: agentId };
      const action = { type: "Action", id: "McpCall" };
      const resource = toolName
        ? { type: "MCP::Tool", id: toolName }
        : { type: "MCP::Server", id: mcpServerId };

      try {
        const authz = cedarFn({
          principal, action, resource,
          context: {},
          policies: bundle.cedarTextEnforce,
          entities: [],
        });
        const isDeny = authz.type === "success" && authz.response.decision === "deny";
        if (isDeny) {
          return makeDecision({
            outcome: "deny",
            reason: "policy_denied",
            allowed: false,
            decisionPath: [...decisionPath, "cedar_denied"],
            obligations: [],
            outputPolicy: null,
            bundleVersion: `bundle:v${bundle.version}`,
            contextPackId: `cp:v${contextPack.packVersion}`,
            riskTier,
            agentId,
            mcpServerId,
            toolName,
          });
        }
        decisionPath.push("cedar_allowed");
      } catch (e) {
        // Cedar error — escalate for critical/high, allow for low-risk
        if (["critical", "high"].includes(riskTier)) {
          return makeDecision({
            outcome: "conditional",
            reason: "cedar_error_escalate",
            allowed: false,
            decisionPath: [...decisionPath, "cedar_error"],
            obligations: [],
            outputPolicy: null,
            bundleVersion: `bundle:v${bundle.version}`,
            contextPackId: `cp:v${contextPack.packVersion}`,
            riskTier,
            agentId,
            mcpServerId,
            toolName,
          });
        }
        decisionPath.push("cedar_error_allow_low_risk");
      }
    }

    // ── 7. Shadow policies ────────────────────────────────────────────────────
    if (bundle.shadowCount > 0) {
      try {
        const principal = { type: "Agent", id: agentId };
        const action = { type: "Action", id: "McpCall" };
        const resource = toolName
          ? { type: "MCP::Tool", id: toolName }
          : { type: "MCP::Server", id: mcpServerId };
        const shadowAuthz = cedarFn({
          principal, action, resource,
          context: {},
          policies: bundle.cedarTextShadow,
          entities: [],
        });
        const isShadowDeny = shadowAuthz.type === "success" && shadowAuthz.response.decision === "deny";
        if (isShadowDeny) {
          obligations.push({
            type: "shadow_denied",
            obligation_type: "shadow_denied",
            detail: "shadow_forbid",
          });
          decisionPath.push("shadow_denied");
        }
      } catch {
        // Shadow evaluation errors are non-fatal
      }
    }

    // ── 8. Human-approval gating ──────────────────────────────────────────────
    if (toolName && bundleRequiresHumanApproval(bundle, toolName)) {
      obligations.push({
        type: "audit_flag",
        obligation_type: "audit_flag",
        detail: `tool ${toolName} requires human approval`,
      });
      decisionPath.push("tool_requires_human_approval");
    }

    // ── 9. Derive output policy ───────────────────────────────────────────────
    const outputPolicy = deriveOutputPolicy(obligations, contextPack.dataClassifications);

    decisionPath.push("enforcement_complete");

    return makeDecision({
      outcome: "allow",
      reason: "allowed",
      allowed: true,
      decisionPath,
      obligations,
      outputPolicy,
      bundleVersion: `bundle:v${bundle.version}`,
      contextPackId: `cp:v${contextPack.packVersion}`,
      riskTier,
      agentId,
      mcpServerId,
      toolName,
    });
  }

  private checkStaleRevocation(
    agentId: string,
    mcpServerId: string,
    toolName: string,
    decisionPath: string[],
  ): LocalDecision | null {
    let staleMode = "warn";
    let staleThreshold = 150;
    try {
      staleMode = process.env["KSWITCH_REVOCATION_STALE_MODE"] ?? "warn";
      staleThreshold = parseInt(
        process.env["KSWITCH_REVOCATION_STALE_THRESHOLD"] ?? "150",
        10,
      );
    } catch {
      return null;
    }

    if (staleMode === "warn") return null;

    const revCache = this.getRevCache();
    if (!revCache.isSyncStale(staleThreshold)) return null;

    if (staleMode === "deny") {
      return makeDecision({
        outcome: "deny",
        reason: "revocation_sync_stale",
        allowed: false,
        decisionPath: [...decisionPath, "revocation_sync_stale_deny"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: "",
        riskTier: "medium",
        agentId,
        mcpServerId,
        toolName,
      });
    }

    if (staleMode === "conditional") {
      return makeDecision({
        outcome: "conditional",
        reason: "revocation_sync_stale",
        allowed: false,
        decisionPath: [...decisionPath, "revocation_sync_stale_conditional"],
        obligations: [],
        outputPolicy: null,
        bundleVersion: "",
        contextPackId: "",
        riskTier: "medium",
        agentId,
        mcpServerId,
        toolName,
      });
    }

    return null;
  }
}

// ── Output policy derivation (mirrors Python _derive_output_policy) ───────────

export function deriveOutputPolicy(
  obligations: LocalObligation[],
  dataClassifications: string[],
): LocalOutputPolicy {
  // DENY_EXPORT wins: critical credential_risk or anomaly_detection
  for (const ob of obligations) {
    const obType = (ob.type ?? ob.obligation_type ?? "").toLowerCase();
    const level = (ob.level ?? "").toLowerCase();
    if (obType === "credential_risk" && level === "critical") {
      return { mode: "deny_export", masking_classifications: [] };
    }
    if (obType === "anomaly_detection") {
      const anomalies = ((ob.parameters as { anomalies?: { severity?: string }[] })?.anomalies) ?? [];
      if (anomalies.some((a) => a.severity === "critical")) {
        return { mode: "deny_export", masking_classifications: [] };
      }
    }
  }

  // MASK_FIELDS: data_masking obligation
  for (const ob of obligations) {
    const obType = (ob.type ?? ob.obligation_type ?? "").toLowerCase();
    if (obType === "data_masking") {
      const classifications =
        ((ob.parameters as { classifications?: string[] })?.classifications) ?? [];
      return { mode: "mask_fields", masking_classifications: classifications };
    }
  }

  // MASK_FIELDS: sensitive data classifications
  const sensitive = dataClassifications.filter((c) => SENSITIVE_CLASSIFICATIONS.has(c));
  if (sensitive.length > 0) {
    return { mode: "mask_fields", masking_classifications: sensitive };
  }

  return { mode: "allow_raw", masking_classifications: [] };
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _evaluator = new LocalPDPEvaluator();

export function getEvaluator(): LocalPDPEvaluator {
  return _evaluator;
}

/** Replace the singleton (for testing). */
export function _setEvaluator(evaluator: LocalPDPEvaluator): void {
  _evaluator = evaluator;
}

// Export cedar check for tests
export { getCedarIsAuthorized };
