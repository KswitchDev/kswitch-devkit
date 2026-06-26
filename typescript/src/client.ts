import { TokenManager, type TokenConfig } from "./auth.js";
import { AuthZenAPI } from "./authzen.js";
import { CatalogAPI } from "./catalog.js";
import { ComplianceAPI } from "./compliance.js";
import { EnforcementAPI } from "./enforcement.js";
import {
  AuthError,
  KSwitchError,
  NetworkError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
} from "./errors.js";
import { EventsAPI } from "./events.js";
import { GovernanceAPI } from "./governance.js";
import { IdentityAPI } from "./identity.js";
import { KillSwitchAPI } from "./killswitch.js";
import { PolicyAPI } from "./policy.js";
import { ServiceAPI } from "./service.js";
import type {
  BlastRadius,
  FleetHealth,
  GraphStatus,
  HealthStatus,
  KSwitchConfig,
  OnboardRepo,
  RequestOptions,
  ScanFinding,
  ScanRun,
} from "./types.js";

/**
 * Validate and encode a user-provided ID for safe use in URL paths.
 * Rejects values containing path traversal sequences or query injections.
 */
export function sanitizePathParam(value: string): string {
  if (!value) {
    throw new ValidationError("Path parameter must not be empty");
  }
  if (
    value.includes("/") ||
    value.includes("\\") ||
    value.includes("..") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("%2e") ||
    value.includes("%2f") ||
    value.includes("%5c")
  ) {
    throw new ValidationError("Invalid characters in path parameter");
  }
  return encodeURIComponent(value);
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) {
    end -= 1;
  }
  return value.slice(0, end);
}

/**
 * Main entry point for the KSwitch.ai SDK.
 *
 * ```ts
 * const client = new KSwitchClient({
 *   baseUrl: "https://kswitch.example.com",
 *   clientId: "my-agent",
 *   clientSecret: "secret",
 *   keycloakUrl: "https://keycloak.example.com",
 * });
 *
 * const agents = await client.governance.listAgents();
 * const decision = await client.authzen.evaluate({ ... });
 * ```
 */
export class KSwitchClient {
  // ── Sub-API namespaces ────────────────────────────────────────────────────
  readonly governance: GovernanceAPI;
  readonly policy: PolicyAPI;
  readonly identity: IdentityAPI;
  readonly compliance: ComplianceAPI;
  readonly killswitch: KillSwitchAPI;
  readonly events: EventsAPI;
  readonly catalog: CatalogAPI;
  readonly enforcement: EnforcementAPI;
  readonly authzen: AuthZenAPI;
  readonly service: ServiceAPI;

  // ── Internal state ────────────────────────────────────────────────────────
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly backoffMs: number;
  private token: string | undefined;
  private readonly tokenManager: TokenManager | null;

  constructor(config: KSwitchConfig) {
    this.baseUrl = trimTrailingSlashes(config.baseUrl);
    this.timeout = config.timeout ?? 30_000;
    this.retries = config.retries ?? 3;
    this.backoffMs = config.backoffMs ?? 1_000;
    this.token = config.token;

    // Set up M2M token manager if client credentials provided
    if (config.clientId && config.clientSecret) {
      const tokenConfig: TokenConfig = {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        tokenEndpoint: config.tokenEndpoint,
        keycloakUrl: config.keycloakUrl,
        keycloakRealm: config.keycloakRealm,
        resource: config.resource,
      };
      this.tokenManager = new TokenManager(tokenConfig);
    } else {
      this.tokenManager = null;
    }

    // Initialize sub-API namespaces
    this.governance = new GovernanceAPI(this);
    this.policy = new PolicyAPI(this);
    this.identity = new IdentityAPI(this);
    this.compliance = new ComplianceAPI(this);
    this.killswitch = new KillSwitchAPI(this);
    this.events = new EventsAPI(this);
    this.catalog = new CatalogAPI(this);
    this.enforcement = new EnforcementAPI(this);
    this.authzen = new AuthZenAPI(this);
    this.service = new ServiceAPI(this);
  }

  // ── Core HTTP request method ──────────────────────────────────────────────

  /**
   * Execute an authenticated HTTP request with retry logic.
   *
   * - Auto-attaches Bearer token (static or M2M)
   * - Retries on 503 Service Unavailable and network errors
   * - Refreshes token on 401 Unauthorized and retries
   * - Throws typed errors (AuthError, NotFoundError, etc.)
   */
  async request<T = Record<string, unknown>>(
    method: string,
    path: string,
    options?: RequestOptions,
  ): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        const result = await this.executeRequest<T>(method, path, options);
        return result;
      } catch (err) {
        lastError = err as Error;

        // On 401, try refreshing token once
        if (err instanceof AuthError && attempt < this.retries - 1 && this.tokenManager) {
          this.tokenManager.invalidate();
          this.token = undefined;
          continue;
        }

        // Retry on 429 with backoff
        if (err instanceof RateLimitError && attempt < this.retries - 1) {
          const retryAfterMs = (err as RateLimitError).retryAfter
            ? (err as RateLimitError).retryAfter! * 1000
            : this.backoffMs * 2 ** attempt;
          await this.sleep(retryAfterMs);
          continue;
        }

        // Retry on 503 or network errors
        const isRetryable =
          err instanceof ServerError && (err as ServerError).statusCode === 503 ||
          err instanceof NetworkError;

        if (isRetryable && attempt < this.retries - 1) {
          await this.sleep(this.backoffMs * 2 ** attempt);
          continue;
        }

        throw err;
      }
    }

    throw lastError ?? new KSwitchError("Request failed after retries");
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private async executeRequest<T>(
    method: string,
    path: string,
    options?: RequestOptions,
  ): Promise<T> {
    const url = this.buildUrl(path, options?.params);
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...options?.headers,
    };

    // Resolve bearer token
    const bearerToken = await this.resolveToken();
    if (bearerToken) {
      headers["Authorization"] = `Bearer ${bearerToken}`;
    }

    // Build fetch options
    const fetchOptions: globalThis.RequestInit = {
      method,
      headers,
      signal: options?.signal ?? AbortSignal.timeout(this.timeout),
    };

    if (options?.json !== undefined) {
      headers["Content-Type"] = "application/json";
      fetchOptions.body = JSON.stringify(options.json);
    }

    let resp: Response;
    try {
      resp = await fetch(url, fetchOptions);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new NetworkError("Request timed out");
      }
      throw new NetworkError(
        `Network error: ${(err as Error).message}`,
        err as Error,
      );
    }

    // Parse response body
    let body: unknown;
    const contentType = resp.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      body = await resp.json();
    } else {
      body = await resp.text();
    }

    // Handle error status codes
    if (!resp.ok) {
      this.throwForStatus(resp.status, body);
    }

    return body as T;
  }

  private async resolveToken(): Promise<string | undefined> {
    if (this.token) return this.token;
    if (this.tokenManager) {
      return this.tokenManager.getToken();
    }
    return undefined;
  }

  private buildUrl(
    path: string,
    params?: Record<string, string | number | boolean | undefined>,
  ): string {
    const url = new URL(path, this.baseUrl);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url.toString();
  }

  private throwForStatus(status: number, body: unknown): never {
    const message =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as Record<string, unknown>).error)
        : typeof body === "object" && body !== null && "message" in body
          ? String((body as Record<string, unknown>).message)
          : `HTTP ${status}`;

    switch (true) {
      case status === 401 || status === 403:
        throw new AuthError(message, status, body);
      case status === 404:
        throw new NotFoundError(message, body);
      case status === 422 || status === 400:
        throw new ValidationError(message, body);
      case status === 429: {
        const retryAfter = undefined; // Could parse Retry-After header
        throw new RateLimitError(message, retryAfter, body);
      }
      case status >= 500:
        throw new ServerError(message, status, body);
      default:
        throw new KSwitchError(message, status, body);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ── Health (top-level convenience) ────────────────────────────────────────

  /** Check KSwitch API health. */
  async healthCheck(): Promise<HealthStatus> {
    return this.request("GET", "/api/v1/health");
  }

  /** Liveness probe. */
  async healthLive(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/health/live");
  }

  /** Readiness probe. */
  async healthReady(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/health/ready");
  }

  // ── Scanner (top-level convenience) ───────────────────────────────────────

  /** Get scanner statistics. */
  async getScannerStats(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/scanner/stats");
  }

  /** Trigger a repository scan. */
  async triggerScan(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/scanner/scan", { json: data });
  }

  /** Get scan run history. */
  async getScanRuns(params?: { limit?: number }): Promise<{ runs: ScanRun[] }> {
    return this.request("GET", "/api/v1/scanner/runs", { params });
  }

  /** Get a specific scan run. */
  async getScanRun(scanId: string): Promise<ScanRun> {
    return this.request("GET", `/api/v1/scanner/runs/${sanitizePathParam(scanId)}`);
  }

  /** Get findings for a specific scan run. */
  async getScanFindings(scanId: string): Promise<{ findings: ScanFinding[] }> {
    return this.request("GET", `/api/v1/scanner/runs/${sanitizePathParam(scanId)}/findings`);
  }

  /** Update a scan finding status. */
  async updateScanFinding(findingId: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/api/v1/scanner/findings/${sanitizePathParam(findingId)}`, { json: data });
  }

  /** Link a scan finding to an agent. */
  async linkScanFinding(findingId: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", `/api/v1/scanner/findings/${sanitizePathParam(findingId)}/link`, { json: data });
  }

  // ── Graph (top-level convenience) ─────────────────────────────────────────

  /** Get governance graph status / statistics. */
  async getGraphStatus(): Promise<GraphStatus> {
    return this.request("GET", "/api/v1/graph/status");
  }

  /** Rebuild the governance graph. */
  async rebuildGraph(): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/graph/rebuild");
  }

  /** Get graph node for a specific agent. */
  async getGraphAgent(agentId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/api/v1/graph/agent/${sanitizePathParam(agentId)}`);
  }

  /** Get blast radius analysis for a set of agents. */
  async getBlastRadius(agentIds: string[]): Promise<BlastRadius> {
    return this.request("POST", "/api/v1/graph/blast-radius", { json: { agent_ids: agentIds } });
  }

  /** Get delegation chain via graph traversal. */
  async getGraphDelegationChain(agentId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/api/v1/graph/delegation-chain/${sanitizePathParam(agentId)}`);
  }

  /** Get trust paths for an agent. */
  async getGraphTrustPaths(agentId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/api/v1/graph/trust-paths/${sanitizePathParam(agentId)}`);
  }

  /** Get boundary crossings for an agent via graph. */
  async getGraphBoundaryCrossings(agentId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/api/v1/graph/boundary-crossings/${sanitizePathParam(agentId)}`);
  }

  /** Explore the governance graph. */
  async exploreGraph(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/graph/explore", { json: data });
  }

  /** Export the governance graph in a specific format. */
  async exportGraph(format: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/api/v1/graph/export/${sanitizePathParam(format)}`);
  }

  // ── Fleet (top-level convenience) ─────────────────────────────────────────

  /** List fleet agents. */
  async listFleetAgents(params?: Record<string, string | number | boolean | undefined>): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/fleet/agents", { params });
  }

  /** Get fleet health summary. */
  async getFleetHealth(): Promise<FleetHealth> {
    return this.request("GET", "/api/v1/fleet/health");
  }

  /** Get fleet blast radius analysis. */
  async getFleetBlastRadius(params?: Record<string, string | number | boolean | undefined>): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/fleet/blast-radius", { params });
  }

  /** Get fleet activity. */
  async getFleetActivity(params?: Record<string, string | number | boolean | undefined>): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/fleet/activity", { params });
  }

  // ── Onboard (top-level convenience) ───────────────────────────────────────

  /** Get onboard service status. */
  async getOnboardStatus(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/onboard/status");
  }

  /** Run onboard discovery scan. */
  async runOnboard(): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/onboard/run");
  }

  /** Get onboard results. */
  async getOnboardResults(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/onboard/results");
  }

  /** Start the onboard service. */
  async startOnboardService(): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/onboard/service/start");
  }

  /** Stop the onboard service. */
  async stopOnboardService(): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/v1/onboard/service/stop");
  }

  /** List onboard repos. */
  async listOnboardRepos(): Promise<{ repos: OnboardRepo[] }> {
    return this.request("GET", "/api/v1/onboard/repos");
  }

  /** Add an onboard repo. */
  async addOnboardRepo(data: Partial<OnboardRepo>): Promise<OnboardRepo> {
    return this.request("POST", "/api/v1/onboard/repos", { json: data });
  }

  /** Delete an onboard repo. */
  async deleteOnboardRepo(repoId: string): Promise<Record<string, unknown>> {
    return this.request("DELETE", `/api/v1/onboard/repos/${sanitizePathParam(repoId)}`);
  }

  /** Update an onboard repo. */
  async updateOnboardRepo(repoId: string, data: Partial<OnboardRepo>): Promise<OnboardRepo> {
    return this.request("PATCH", `/api/v1/onboard/repos/${sanitizePathParam(repoId)}`, { json: data });
  }

  // ── Auth Methods ──────────────────────────────────────────────────────────

  /** Get available authentication methods for the KSwitch instance. */
  async getAuthMethods(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/auth/methods");
  }
}
