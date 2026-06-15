import type { KSwitchClient } from "./client.js";
import type { PaginatedResponse, Policy, PolicyDecision, PolicyEvaluation } from "./types.js";

/**
 * Policy management: Cedar/Rego policy CRUD, evaluation, and mode switching.
 */
export class PolicyAPI {
  constructor(private readonly client: KSwitchClient) {}

  /** List all governance policies with optional filtering. */
  async list(params?: {
    page?: number;
    page_size?: number;
    policy_type?: string;
    status?: string;
    search?: string;
  }): Promise<PaginatedResponse<Policy>> {
    return this.client.request("GET", "/api/v1/policies", { params });
  }

  /** Get a specific policy with full Cedar + Rego text. */
  async get(policyId: string): Promise<Policy> {
    return this.client.request("GET", `/api/v1/policies/${policyId}`);
  }

  /** Create a new governance policy. */
  async create(data: Partial<Policy>): Promise<Policy> {
    return this.client.request("POST", "/api/v1/policies", { json: data });
  }

  /** Update an existing policy. */
  async update(policyId: string, data: Partial<Policy>): Promise<Policy> {
    return this.client.request("PATCH", `/api/v1/policies/${policyId}`, { json: data });
  }

  /** Delete a policy. */
  async delete(policyId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/policies/${policyId}`);
  }

  /** Duplicate an existing policy. */
  async duplicate(policyId: string, data?: { name?: string }): Promise<Policy> {
    return this.client.request("POST", `/api/v1/policies/${policyId}/duplicate`, { json: data ?? {} });
  }

  /** Validate Cedar policy syntax without saving. */
  async validate(data: { cedar_text: string }): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/policies/validate", { json: data });
  }

  /** Evaluate a policy against a subject/action/resource. */
  async evaluate(data: {
    principal: string;
    action: string;
    resource: string;
    context?: Record<string, unknown>;
  }): Promise<PolicyDecision> {
    return this.client.request("POST", "/api/v1/policies/evaluate", { json: data });
  }

  /** Get recent policy evaluation results. */
  async getEvaluations(params?: { limit?: number }): Promise<{ evaluations: PolicyEvaluation[] }> {
    return this.client.request("GET", "/api/v1/policies/evaluations", { params });
  }

  /** Switch enforcement mode (e.g. "enforce" or "audit"). */
  async setMode(data: { mode: string }): Promise<Record<string, unknown>> {
    return this.client.request("PATCH", "/api/v1/policies/mode", { json: data });
  }
}
