/**
 * KSwitch SDK interceptor — mandatory safe execution path (PR-05/PR-06).
 *
 * KSwitchInterceptor wraps enforcement + pre-invoke obligation blocking +
 * tool invocation + output filtering + obligation reporting into a single
 * checkAndInvoke() call. Callers must not bypass this path.
 *
 * LOCAL RUNTIME PATH (TypeScript Local Runtime):
 *   If a LocalPDPEvaluator is registered, checkAndInvoke() attempts a local
 *   decision first. Only "conditional" outcomes escalate to the server.
 *   This eliminates the Flask network call for normal-path ALLOW/DENY.
 *
 *   Decision flow:
 *     1. Local PDP evaluate (no network)
 *        a. outcome == "allow"       → execute + output guard + audit (no Flask call)
 *        b. outcome == "deny"        → throw KSwitchEnforcementError (no Flask call)
 *        c. outcome == "conditional" → fall through to server enforcement
 *     2. Server enforcement (only for conditional)
 *        → normal server path unchanged
 *
 * Bypass prevention contract (unchanged):
 *   - If enforcement returns denied  → throws KSwitchEnforcementError  (tool never runs)
 *   - If credential_risk critical/high present → throws KSwitchObligationError (tool never runs)
 *   - If anomaly_detection critical present    → throws KSwitchObligationError (tool never runs)
 *   - If output_policy.mode == "deny_export"   → throws OutputDeniedError (output suppressed)
 *   - All other output_policy modes apply field masking / truncation
 *
 * Obligation reporting is best-effort (errors silently swallowed).
 */

import { AsyncLocalStorage } from "node:async_hooks";
import type { KSwitchClient } from "./client.js";
import type {
  MCPCallEnforcementResponse,
  EnforcementObligation,
  OutputPolicy,
} from "./types.js";
import type { LocalPDPEvaluator } from "./local_pdp/evaluator.js";
import type { LocalDecision } from "./local_pdp/types.js";
import { emitDecisionEvent } from "./audit/emitter.js";
import { KSwitchTokenIssuer } from "./tokens/issuer.js";
import type { IssuerDecision } from "./tokens/issuer.js";

// ── Optional OTEL tracing for Layer C (eBPF correlation) ─────────────────────
let _enforcementTracer: any = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { trace } = require("@opentelemetry/api");
  _enforcementTracer = trace.getTracer("kswitch.enforcement");
} catch {
  /* @opentelemetry/api not installed — span tagging disabled */
}

/** Extract JTI from a JWT execution token. Never throws. */
function _extractTokenJti(token: string | null): string {
  if (!token) return "";
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return "";
    const payload = JSON.parse(
      Buffer.from(parts[1]! + "=".repeat((-parts[1]!.length) & 3), "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    return (payload["jti"] as string | undefined) ?? "";
  } catch {
    return "";
  }
}

// ── Execution token propagation ───────────────────────────────────────────────

/**
 * AsyncLocalStorage that holds the execution token for the current governed
 * tool call. Downstream HTTP clients can call `getActiveExecutionToken()` to
 * attach it as a Bearer header without it being passed through every layer.
 */
const _activeExecutionToken = new AsyncLocalStorage<string | null>();

/**
 * Return the execution token for the current governed call, or null if none.
 * Safe to call from any code running inside `checkAndInvoke()`.
 */
export function getActiveExecutionToken(): string | null {
  return _activeExecutionToken.getStore() ?? null;
}

/** Attempt to issue an execution token for an ALLOW decision. Never throws. */
function _tryIssueToken(
  decision: IssuerDecision,
  agentId: string,
  mcpServerId: string,
  toolName: string,
  context?: Record<string, unknown>,
): string | null {
  const enabled =
    (process.env["KSWITCH_EXECUTION_TOKENS_ENABLED"] ?? "false").toLowerCase() === "true";
  if (!enabled) return null;

  try {
    const issuer = KSwitchTokenIssuer.fromEnv();
    return issuer.issue(decision, { agentId, mcpServerId, toolName, context });
  } catch {
    return null;
  }
}

/** Emit a best-effort audit event for token issuance. Never throws. */
function _emitTokenAuditEvent(
  token: string,
  agentId: string,
  mcpServerId: string,
  toolName: string,
): void {
  try {
    // Parse jti from token payload for audit
    const parts = token.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(
        Buffer.from(parts[1]! + "=".repeat((-parts[1]!.length) & 3), "base64url").toString("utf8"),
      ) as Record<string, unknown>;
      emitDecisionEvent({
        eventType: "execution_token_issued",
        agentId,
        mcpServerId,
        toolName,
        allowed: true,
        reason: "token_issued",
        decisionId: (payload["jti"] as string | undefined) ?? "",
        decisionPath: [],
        obligations: [],
        outputPolicy: null,
        evaluationMode: "sdk",
        bundleVersion: (payload["bundle_version"] as string | undefined) ?? "0",
        contextPackId: (payload["context_pack_id"] as string | undefined) ?? "default",
        riskTier: (payload["risk_tier"] as string | undefined) ?? "low",
        elapsedMs: 0,
      });
    }
  } catch {
    // Best effort
  }
}

// ── Interceptor exceptions ────────────────────────────────────────────────────

/** Thrown when the enforcement decision is DENY. The tool is never invoked. */
export class KSwitchEnforcementError extends Error {
  readonly reason: string;
  readonly decision: MCPCallEnforcementResponse;

  constructor(reason: string, decision: MCPCallEnforcementResponse) {
    super(`MCP call denied: ${reason}`);
    this.name = "KSwitchEnforcementError";
    this.reason = reason;
    this.decision = decision;
  }
}

/**
 * Thrown when a pre-invoke obligation mandates blocking.
 *
 * Triggered by:
 *   - credential_risk at level critical or high
 *   - anomaly_detection at level critical
 */
export class KSwitchObligationError extends Error {
  readonly reason: string;
  readonly obligation: EnforcementObligation;
  readonly decision: MCPCallEnforcementResponse;

  constructor(reason: string, obligation: EnforcementObligation, decision: MCPCallEnforcementResponse) {
    super(`Pre-invoke obligation blocked call: ${reason}`);
    this.name = "KSwitchObligationError";
    this.reason = reason;
    this.obligation = obligation;
    this.decision = decision;
  }
}

/** Thrown when output_policy.mode == "deny_export". Output must not be returned. */
export class OutputDeniedError extends Error {
  constructor(message = "Output export denied by governance policy") {
    super(message);
    this.name = "OutputDeniedError";
  }
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CRED_BLOCK_LEVELS = new Set(["critical", "high"]);

const SENSITIVE_FIELD_PATTERNS = [
  "ssn", "social_security", "passport", "dob", "date_of_birth",
  "account_number", "card_number", "cvv", "routing_number",
  "tax_id", "ein", "phone", "email", "address", "zip", "postal",
  "salary", "income", "net_worth", "balance", "position", "trade",
  "ticker", "isin", "cusip", "mnpi", "insider",
  "password", "secret", "token", "api_key", "private_key", "credential",
  "health", "diagnosis", "medication", "prescription", "patient",
];

// ── Interceptor options ───────────────────────────────────────────────────────

export interface CheckAndInvokeOptions<TArgs extends Record<string, unknown>, TResult> {
  agentId: string;
  mcpServerId: string;
  toolName: string;
  toolFn: (args: TArgs) => Promise<TResult> | TResult;
  toolArgs?: TArgs;
  context?: Record<string, unknown>;
}

// ── Interceptor ───────────────────────────────────────────────────────────────

/**
 * KSwitchInterceptor: enforce → block → invoke → filter → report.
 *
 * Optionally accepts a LocalPDPEvaluator for local-first enforcement.
 * When provided, normal-path ALLOW/DENY skip the Flask server entirely.
 *
 * @example
 * ```ts
 * // Server-only mode (existing behavior):
 * const interceptor = new KSwitchInterceptor(client);
 *
 * // Local-first mode (TypeScript local runtime):
 * const interceptor = new KSwitchInterceptor(client, { localPDP: evaluator });
 * ```
 */
export class KSwitchInterceptor {
  private readonly localPDP: LocalPDPEvaluator | null;

  constructor(
    private readonly client: KSwitchClient,
    opts?: { localPDP?: LocalPDPEvaluator | null },
  ) {
    this.localPDP = opts?.localPDP ?? null;
  }

  /**
   * Enforce, invoke, and filter in a single safe call.
   *
   * If a localPDP is configured:
   *   - "allow"/"deny" outcomes are resolved locally (no server call)
   *   - "conditional" outcomes escalate to the server
   *
   * @throws {KSwitchEnforcementError}  Decision was DENY.
   * @throws {KSwitchObligationError}   Critical pre-invoke obligation blocks call.
   * @throws {OutputDeniedError}        Output policy = deny_export.
   */
  async checkAndInvoke<TArgs extends Record<string, unknown>, TResult>(
    opts: CheckAndInvokeOptions<TArgs, TResult>,
  ): Promise<TResult | unknown> {
    if (_enforcementTracer) {
      return _enforcementTracer.startActiveSpan(
        "kswitch.check_and_invoke",
        async (span: any) => {
          try {
            return await this._checkAndInvokeInner(opts, span);
          } finally {
            span.end();
          }
        },
      );
    }
    return this._checkAndInvokeInner(opts, null);
  }

  /** @internal */
  private async _checkAndInvokeInner<TArgs extends Record<string, unknown>, TResult>(
    opts: CheckAndInvokeOptions<TArgs, TResult>,
    span: any,
  ): Promise<TResult | unknown> {
    const { agentId, mcpServerId, toolName, toolFn, toolArgs = {} as TArgs, context } = opts;
    const startMs = Date.now();

    // ── Local PDP path ─────────────────────────────────────────────────────────
    if (this.localPDP !== null) {
      const localDecision = await this.localPDP.evaluate(
        agentId, mcpServerId, toolName, context,
      );

      if (localDecision.outcome === "allow" || localDecision.outcome === "deny") {
        // Emit audit event for local decision
        emitDecisionEvent({
          eventType: localDecision.allowed
            ? "enforcement.allow"
            : (localDecision.reason === "agent_revoked"
              ? "enforcement.revocation_deny"
              : "enforcement.deny"),
          agentId,
          mcpServerId,
          toolName,
          allowed: localDecision.allowed,
          reason: localDecision.reason,
          decisionId: localDecision.enforcementId,
          decisionPath: localDecision.decisionPath,
          obligations: localDecision.obligations,
          outputPolicy: localDecision.outputPolicy,
          evaluationMode: localDecision.evaluationMode,
          bundleVersion: localDecision.bundleVersion,
          contextPackId: localDecision.contextPackId,
          riskTier: localDecision.riskTier,
          elapsedMs: Date.now() - startMs,
        });

        if (!localDecision.allowed) {
          if (span) {
            span.setAttribute("kswitch.tool_name", toolName);
            span.setAttribute("kswitch.governed", false);
            span.setAttribute("kswitch.deny_reason", localDecision.reason);
          }
          // Convert LocalDecision to MCPCallEnforcementResponse shape for the error
          throw new KSwitchEnforcementError(
            localDecision.reason,
            localDecisionToResponse(localDecision),
          );
        }

        // Local ALLOW path — issue token, apply obligations + output policy, no server call
        enforcePreInvokeObligations(localDecisionToResponse(localDecision));
        const localExecToken = _tryIssueToken(
          {
            risk_tier: localDecision.riskTier,
            bundle_version: localDecision.bundleVersion,
            context_pack_id: localDecision.contextPackId,
            id: localDecision.enforcementId,
          },
          agentId, mcpServerId, toolName, context,
        );
        if (localExecToken) _emitTokenAuditEvent(localExecToken, agentId, mcpServerId, toolName);
        if (span) {
          span.setAttribute("kswitch.token_id", _extractTokenJti(localExecToken));
          span.setAttribute("kswitch.tool_name", toolName);
          span.setAttribute("kswitch.governed", true);
        }
        let rawOutput: TResult | unknown;
        await _activeExecutionToken.run(localExecToken, async () => {
          rawOutput = await Promise.resolve(toolFn(toolArgs));
        });
        const filtered = applyOutputPolicy(rawOutput!, localDecision.outputPolicy ?? null);
        return filtered;
      }

      // outcome === "conditional" — fall through to server
      emitDecisionEvent({
        eventType: "enforcement.conditional",
        agentId,
        mcpServerId,
        toolName,
        allowed: false,
        reason: localDecision.reason,
        decisionId: localDecision.enforcementId,
        decisionPath: localDecision.decisionPath,
        obligations: [],
        outputPolicy: null,
        evaluationMode: localDecision.evaluationMode,
        bundleVersion: localDecision.bundleVersion,
        contextPackId: localDecision.contextPackId,
        riskTier: localDecision.riskTier,
        elapsedMs: Date.now() - startMs,
      });
    }

    // ── Server enforcement path (unchanged) ───────────────────────────────────
    const decision = await this.client.enforcement.enforceMCPCall({ // kswitch: allow-unsafe — sdk-internal: server fallback after local PDP conditional/miss
      agent_id: agentId,
      mcp_server_id: mcpServerId,
      tool_name: toolName,
      context,
    });

    if (!decision.allowed) {
      if (span) {
        span.setAttribute("kswitch.tool_name", toolName);
        span.setAttribute("kswitch.governed", false);
        span.setAttribute("kswitch.deny_reason", decision.reason ?? "denied");
      }
      throw new KSwitchEnforcementError(decision.reason ?? "denied", decision);
    }

    enforcePreInvokeObligations(decision);

    // Issue execution token for ALLOW (best-effort, never blocks invocation)
    const serverExecToken = _tryIssueToken(
      decision as unknown as IssuerDecision,
      agentId, mcpServerId, toolName, context,
    );
    if (serverExecToken) _emitTokenAuditEvent(serverExecToken, agentId, mcpServerId, toolName);
    if (span) {
      span.setAttribute("kswitch.token_id", _extractTokenJti(serverExecToken));
      span.setAttribute("kswitch.tool_name", toolName);
      span.setAttribute("kswitch.governed", true);
    }

    let rawOutput: TResult | unknown;
    await _activeExecutionToken.run(serverExecToken, async () => {
      rawOutput = await Promise.resolve(toolFn(toolArgs));
    });
    const filtered = applyOutputPolicy(rawOutput!, decision.output_policy ?? null);

    await reportObligationsBestEffort(this.client, decision);

    return filtered;
  }
}

// ── Convert LocalDecision to MCPCallEnforcementResponse ───────────────────────

function localDecisionToResponse(d: LocalDecision): MCPCallEnforcementResponse {
  return {
    allowed: d.allowed,
    reason: d.reason,
    outcome: d.outcome,
    decision_path: d.decisionPath,
    obligations: d.obligations.map((ob) => {
      const { type, obligation_type, level, detail, ...rest } = ob;
      return { type, obligation_type, level, detail, ...rest };
    }),
    output_policy: d.outputPolicy ?? undefined,
    evaluation_mode: d.evaluationMode,
    bundle_version: d.bundleVersion,
    context_pack_id: d.contextPackId,
    context_snapshot_id: d.context_snapshot_id,
    context_snapshot_digest: d.context_snapshot_digest,
    context_snapshot: d.context_snapshot,
    decision_explanation: d.decision_explanation,
    enforcement_id: d.enforcementId,
  };
}

// ── Shared helpers (exported for unit testing and advanced use) ───────────────

/** Throw KSwitchObligationError for any obligation that must block invocation. */
export function enforcePreInvokeObligations(decision: MCPCallEnforcementResponse): void {
  for (const ob of decision.obligations ?? []) {
    const obType = (ob.obligation_type ?? ob.type ?? "").toLowerCase();
    const level = (ob.level ?? "").toLowerCase();

    if (obType === "credential_risk" && CRED_BLOCK_LEVELS.has(level)) {
      throw new KSwitchObligationError(
        `credential_risk=${level} blocks tool invocation`,
        ob,
        decision,
      );
    }

    if (obType === "anomaly_detection" && level === "critical") {
      throw new KSwitchObligationError(
        "anomaly_detection=critical blocks tool invocation",
        ob,
        decision,
      );
    }
  }
}

/** Apply SDK-side output policy to raw tool output. */
export function applyOutputPolicy(output: unknown, policy: OutputPolicy | null): unknown {
  if (!policy) return output;

  const mode = (policy.mode ?? "allow_raw").toLowerCase();

  switch (mode) {
    case "allow_raw":
      return output;

    case "deny_export":
      throw new OutputDeniedError(
        `Output export denied by governance policy` +
        (policy.masking_classifications?.length
          ? ` (classifications: ${policy.masking_classifications.join(", ")})`
          : ""),
      );

    case "mask_fields":
      return maskOutput(output, policy.masking_classifications ?? []);

    case "truncate":
      return truncateOutput(output, policy.max_output_bytes ?? null);

    case "summarize_only":
      return {
        _output_mode: "summarize_only",
        _note: "Output summarization not yet implemented (PR-09)",
        _original_type: typeof output,
      };

    case "require_release":
      return { _output_mode: "require_release", _held: true };

    default:
      return output;
  }
}

function maskOutput(output: unknown, classifications: string[]): unknown {
  if (output !== null && typeof output === "object" && !Array.isArray(output)) {
    const obj = output as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, redactValue(k, v, classifications)]),
    );
  }
  if (Array.isArray(output)) {
    return output.map((item) => maskOutput(item, classifications));
  }
  return output;
}

function redactValue(key: string, value: unknown, classifications: string[]): unknown {
  const keyLower = key.toLowerCase().replace(/-/g, "_").replace(/ /g, "_");
  const clsPatterns = classifications.map((c) => c.toLowerCase());

  const isSensitive =
    SENSITIVE_FIELD_PATTERNS.some((pat) => keyLower.includes(pat)) ||
    clsPatterns.some((pat) => keyLower.includes(pat));

  if (isSensitive) {
    const label = classifications.length ? classifications.join(", ") : "sensitive";
    return `[REDACTED: ${label}]`;
  }
  if (value !== null && typeof value === "object") {
    return maskOutput(value, classifications);
  }
  return value;
}

function truncateOutput(
  output: unknown,
  maxBytes: number | null,
): unknown {
  if (maxBytes === null || maxBytes <= 0) return output;

  const encoder = new TextEncoder();

  if (typeof output === "string") {
    const raw = encoder.encode(output);
    if (raw.length <= maxBytes) return output;
    const truncated = new TextDecoder().decode(raw.slice(0, maxBytes));
    return truncated + "…[TRUNCATED]";
  }

  let serialized: string;
  try {
    serialized = JSON.stringify(output);
  } catch {
    serialized = String(output);
  }

  const raw = encoder.encode(serialized);
  if (raw.length <= maxBytes) return output;

  const truncated = new TextDecoder().decode(raw.slice(0, maxBytes));
  return { _truncated: true, _max_bytes: maxBytes, _content: truncated + "…" };
}

async function reportObligationsBestEffort(
  client: KSwitchClient,
  decision: MCPCallEnforcementResponse,
): Promise<void> {
  const enforcementId = (decision as MCPCallEnforcementResponse & { enforcement_id?: string }).enforcement_id ?? "";
  if (!enforcementId) return;

  const obTypes = (decision.obligations ?? []).map(
    (ob) => ob.obligation_type ?? ob.type ?? "",
  );

  try {
    await client.enforcement.reportObligations(enforcementId, obTypes);
  } catch {
    // Best-effort: reporting failure must never fail the tool call
  }
}
