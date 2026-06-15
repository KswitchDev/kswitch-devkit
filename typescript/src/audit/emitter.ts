/**
 * Local audit emitter — writes governed decision events to local JSONL file
 * and optionally forwards to the server's audit queue.
 *
 * Mirrors Python AuditEmitter exactly.
 *
 * Audit file: ~/.kswitch/audit/events.jsonl
 *
 * Event types:
 *   - enforcement.allow        — local or server ALLOW
 *   - enforcement.deny         — local or server DENY
 *   - enforcement.conditional  — escalated to server
 *   - enforcement.revocation_deny — agent in revocation cache
 *
 * Decision path is never blocked — emit() returns after JSONL write.
 * Central forwarding failures never affect the JSONL write.
 *
 * runtime_mode: "LOCAL_RUNTIME_TYPESCRIPT"
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { AuditSender } from "./sender.js";

const DEFAULT_AUDIT_DIR = path.join(os.homedir(), ".kswitch", "audit");
const AUDIT_FILE = "events.jsonl";
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB — rotate after this

// ── Event builder ─────────────────────────────────────────────────────────────

export interface AuditEvent {
  event_id: string;
  event_type: string;
  event_version: string;
  // Subject
  agent_id: string;
  mcp_server_id: string;
  tool_name: string;
  action: string;
  // Decision
  decision_id: string;
  allowed: boolean;
  outcome: string;
  reason: string;
  decision_path: string[];
  // Obligations
  obligations: unknown[];
  output_policy_mode: string;
  // Provenance
  bundle_version: string;
  context_pack_id: string;
  risk_tier: string;
  runtime_mode: string;
  // Timing
  elapsed_ms: number;
  evaluated_at: string;
}

export function buildAuditEvent(opts: {
  eventType: string;
  agentId: string;
  mcpServerId: string;
  toolName: string;
  allowed: boolean;
  reason: string;
  decisionId: string;
  decisionPath: string[];
  obligations: unknown[];
  outputPolicy: { mode: string } | null;
  evaluationMode: string;
  bundleVersion?: string;
  contextPackId?: string;
  riskTier?: string;
  elapsedMs?: number;
}): AuditEvent {
  const outcome = opts.allowed ? "allow" : "deny";
  return {
    event_id: crypto.randomUUID(),
    event_type: opts.eventType,
    event_version: "1.0",
    agent_id: opts.agentId,
    mcp_server_id: opts.mcpServerId,
    tool_name: opts.toolName ?? "",
    action: "mcp_call",
    decision_id: opts.decisionId,
    allowed: opts.allowed,
    outcome,
    reason: opts.reason,
    decision_path: opts.decisionPath,
    obligations: opts.obligations ?? [],
    output_policy_mode: opts.outputPolicy?.mode ?? "",
    bundle_version: opts.bundleVersion ?? "",
    context_pack_id: opts.contextPackId ?? "",
    risk_tier: opts.riskTier ?? "medium",
    runtime_mode: opts.evaluationMode,
    elapsed_ms: opts.elapsedMs ?? 0,
    evaluated_at: new Date().toISOString(),
  };
}

// ── Emitter ───────────────────────────────────────────────────────────────────

export class AuditEmitter {
  private readonly dir: string;
  private sender: AuditSender | null = null;

  constructor(auditDir = DEFAULT_AUDIT_DIR) {
    this.dir = auditDir;
  }

  private get filePath(): string {
    return path.join(this.dir, AUDIT_FILE);
  }

  /** Register a central audit sender. Called by runtime when configured. */
  setSender(sender: AuditSender): void {
    this.sender = sender;
  }

  /**
   * Write one event to the JSONL file and optionally forward to server.
   *
   * Step 1 (JSONL) is the first and always-present write.
   * Step 2 (central forwarding) is optional and non-blocking.
   * A failure in Step 2 never affects Step 1.
   * A failure in Step 1 never fails the governed call.
   */
  emit(event: AuditEvent): void {
    // Step 1: JSONL write (always, never skipped)
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const p = this.filePath;
      // Rotate if too large
      try {
        const stat = fs.statSync(p);
        if (stat.size > MAX_FILE_SIZE) {
          const rotated = p + `.${Math.floor(Date.now() / 1000)}`;
          try { fs.renameSync(p, rotated); } catch { /* non-fatal */ }
        }
      } catch { /* file doesn't exist yet — ok */ }

      const line = JSON.stringify(event, (_k, v) => {
        // Ensure undefined values are serialized as null
        return v === undefined ? null : v;
      }) + "\n";
      fs.appendFileSync(p, line, "utf-8");
    } catch {
      // Audit failure must never fail the governed call
    }

    // Step 2: Central forwarding (best-effort, non-blocking)
    try {
      if (this.sender !== null) {
        this.sender.enqueue(event);
      }
    } catch {
      // Forwarding failure is non-fatal
    }
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _emitter = new AuditEmitter();

export function emitDecisionEvent(opts: {
  eventType: string;
  agentId: string;
  mcpServerId: string;
  toolName: string;
  allowed: boolean;
  reason: string;
  decisionId?: string;
  decisionPath?: string[];
  obligations?: unknown[];
  outputPolicy?: { mode: string } | null;
  evaluationMode?: string;
  bundleVersion?: string;
  contextPackId?: string;
  riskTier?: string;
  elapsedMs?: number;
}): void {
  const event = buildAuditEvent({
    eventType: opts.eventType,
    agentId: opts.agentId,
    mcpServerId: opts.mcpServerId,
    toolName: opts.toolName,
    allowed: opts.allowed,
    reason: opts.reason,
    decisionId: opts.decisionId ?? crypto.randomUUID(),
    decisionPath: opts.decisionPath ?? [],
    obligations: opts.obligations ?? [],
    outputPolicy: opts.outputPolicy ?? null,
    evaluationMode: opts.evaluationMode ?? "LOCAL_RUNTIME_TYPESCRIPT",
    bundleVersion: opts.bundleVersion ?? "",
    contextPackId: opts.contextPackId ?? "",
    riskTier: opts.riskTier ?? "medium",
    elapsedMs: opts.elapsedMs ?? 0,
  });
  _emitter.emit(event);
}

export function getAuditEmitter(): AuditEmitter {
  return _emitter;
}

/** Replace the singleton (for testing). */
export function _setAuditEmitter(emitter: AuditEmitter): void {
  _emitter = emitter;
}
