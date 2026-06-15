import type { KSwitchClient } from "./client.js";
import type {
  BoundaryAnalysis,
  ToxicComboDashboard,
  ToxicComboRule,
  ToxicComboViolation,
} from "./types.js";

/**
 * Compliance: toxic combo evaluation, boundary analysis, and risk assessment.
 */
export class ComplianceAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── Toxic Combos ─────────────────────────────────────────────────────────

  /** Get toxic combo dashboard summary. */
  async getToxicDashboard(): Promise<ToxicComboDashboard> {
    return this.client.request("GET", "/api/v1/toxic-combos/dashboard");
  }

  /** List all toxic combo rules. */
  async listToxicRules(): Promise<{ rules: ToxicComboRule[] }> {
    return this.client.request("GET", "/api/v1/toxic-combos/rules");
  }

  /** Get a specific toxic combo rule. */
  async getToxicRule(ruleId: string): Promise<ToxicComboRule> {
    return this.client.request("GET", `/api/v1/toxic-combos/rules/${ruleId}`);
  }

  /** Create a new toxic combo rule. */
  async createToxicRule(data: Partial<ToxicComboRule>): Promise<ToxicComboRule> {
    return this.client.request("POST", "/api/v1/toxic-combos/rules", { json: data });
  }

  /** Update an existing toxic combo rule. */
  async updateToxicRule(ruleId: string, data: Partial<ToxicComboRule>): Promise<ToxicComboRule> {
    return this.client.request("PATCH", `/api/v1/toxic-combos/rules/${ruleId}`, { json: data });
  }

  /** Delete a toxic combo rule. */
  async deleteToxicRule(ruleId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/toxic-combos/rules/${ruleId}`);
  }

  /** Evaluate a specific agent for toxic skill/permission combinations. */
  async evaluateAgent(agentId: string): Promise<{ violations: ToxicComboViolation[] }> {
    return this.client.request("POST", `/api/v1/agents/${agentId}/evaluate-toxic-combos`);
  }

  /** Get toxic combo history for an agent. */
  async getAgentToxicHistory(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/agents/${agentId}/toxic-combo-history`);
  }

  /** Request a toxic combo waiver for an agent. */
  async requestWaiver(agentId: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${agentId}/toxic-combo-waiver`, { json: data });
  }

  /** Run toxic combo evaluation across all agents. */
  async evaluateAll(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/toxic-combos/evaluate-all");
  }

  // ── Boundary Analysis ────────────────────────────────────────────────────

  /** Analyze boundary crossings for an agent. */
  async analyzeBoundaries(agentId: string): Promise<BoundaryAnalysis> {
    return this.client.request("GET", `/api/v1/boundary-analysis/${agentId}`);
  }
}
