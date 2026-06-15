import type { KSwitchClient } from "./client.js";
import type {
  AuthZenEvaluationRequest,
  AuthZenEvaluationResponse,
  AuthZenSearchRequest,
} from "./types.js";

/**
 * AuthZen PDP: OpenID AuthZen-compliant authorization evaluation.
 *
 * Implements the AuthZen Access Evaluation API (IETF draft).
 * Endpoints live under /access/v1/ per the specification.
 */
export class AuthZenAPI {
  constructor(private readonly client: KSwitchClient) {}

  /** Get AuthZen server configuration / well-known metadata. */
  async getConfiguration(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/.well-known/authzen-configuration");
  }

  /** Evaluate a single authorization request. */
  async evaluate(data: AuthZenEvaluationRequest): Promise<AuthZenEvaluationResponse> {
    return this.client.request("POST", "/access/v1/evaluation", { json: data });
  }

  /** Evaluate multiple authorization requests in batch. */
  async evaluateBatch(
    data: { evaluations: AuthZenEvaluationRequest[] },
  ): Promise<{ evaluations: AuthZenEvaluationResponse[] }> {
    return this.client.request("POST", "/access/v1/evaluations", { json: data });
  }

  /** Search for resources accessible to a subject. */
  async searchResources(data: AuthZenSearchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/access/v1/search/resource", { json: data });
  }

  /** Search for actions a subject can perform. */
  async searchActions(data: AuthZenSearchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/access/v1/search/action", { json: data });
  }

  /** Search for subjects that can access a resource. */
  async searchSubjects(data: AuthZenSearchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/access/v1/search/subject", { json: data });
  }
}
