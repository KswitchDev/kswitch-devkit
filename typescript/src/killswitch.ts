import type { KSwitchClient } from "./client.js";
import type {
  BlanketKillRequest,
  KillSwitchRecord,
  KillSwitchRequest,
  KillSwitchViolation,
} from "./types.js";

/**
 * Kill switch operations: targeted kills, blanket kills, auto-kill, history.
 */
export class KillSwitchAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── Targeted ─────────────────────────────────────────────────────────────

  /** Execute targeted kill switch on specific agents. */
  async targetedKill(data: KillSwitchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/kill-switch", { json: data });
  }

  // ── Blanket ──────────────────────────────────────────────────────────────

  /** Initiate blanket kill switch (requires 2 approvals). */
  async blanketInitiate(data: BlanketKillRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/kill-switch/blanket/initiate", { json: data });
  }

  /** Approve a pending blanket kill switch request. */
  async blanketApprove(blanketId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/kill-switch/blanket/${blanketId}/approve`);
  }

  /** Cancel a pending blanket kill switch request. */
  async blanketCancel(blanketId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/kill-switch/blanket/${blanketId}/cancel`);
  }

  /** List pending blanket kill switch requests. */
  async listPendingBlankets(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/kill-switch/blanket");
  }

  // ── Auto Kill Switch ─────────────────────────────────────────────────────

  /** Get auto kill switch configuration. */
  async getAutoConfig(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/kill-switch/auto/config");
  }

  /** Update auto kill switch configuration. */
  async updateAutoConfig(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("PATCH", "/api/v1/kill-switch/auto/config", { json: data });
  }

  /** Trigger auto kill switch evaluation. */
  async autoEvaluate(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/kill-switch/auto/evaluate");
  }

  /** List pending auto kill switch requests. */
  async listAutoPending(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/kill-switch/auto/pending");
  }

  /** Approve an auto kill switch request. */
  async autoApprove(requestId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/kill-switch/auto/approve/${requestId}`);
  }

  /** Reject an auto kill switch request. */
  async autoReject(requestId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/kill-switch/auto/reject/${requestId}`);
  }

  // ── History & Violations ─────────────────────────────────────────────────

  /** Get kill switch activation history. */
  async getHistory(): Promise<{ history: KillSwitchRecord[] }> {
    return this.client.request("GET", "/api/v1/kill-switch/history");
  }

  /** Get kill switch violation records. */
  async getViolations(): Promise<{ violations: KillSwitchViolation[] }> {
    return this.client.request("GET", "/api/v1/kill-switch/violations");
  }

  // ── Webhook ──────────────────────────────────────────────────────────────

  /** Handle ServiceNow webhook callback. */
  async snowWebhook(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/kill-switch/webhook/snow", { json: data });
  }
}
