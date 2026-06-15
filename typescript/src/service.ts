import { type KSwitchClient } from "./client.js";

export const SERVICE_BASE = "/api/v1/b005/service";

export interface FetchRequest {
  url: string;
  purpose: string;
  task_id: string;
  max_bytes?: number;
}

export interface SearchRequest {
  query: string;
  purpose: string;
  task_id: string;
  provider_id?: string;
  max_results?: number;
}

export interface PolicyCheckRequest {
  action: string;
  target: Record<string, unknown>;
  purpose: string;
  task_id: string;
  service_class?: string;
}

function compact(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined));
}

/**
 * B005.2 governed service operations.
 *
 * Mirrors the `kswitch_service` MCP surface. Server-side policy, identity,
 * audit persistence, and provider dispatch remain authoritative.
 */
export class ServiceAPI {
  constructor(private readonly client: KSwitchClient) {}

  async fetch(request: FetchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", `${SERVICE_BASE}/fetch`, {
      json: {
        url: request.url,
        purpose: request.purpose,
        task_id: request.task_id,
        max_bytes: request.max_bytes ?? 1048576,
      },
    });
  }

  async search(request: SearchRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", `${SERVICE_BASE}/search`, {
      json: {
        query: request.query,
        purpose: request.purpose,
        task_id: request.task_id,
        provider_id: request.provider_id ?? "customer_search_default",
        max_results: request.max_results ?? 10,
      },
    });
  }

  async policyCheck(request: PolicyCheckRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", `${SERVICE_BASE}/policy_check`, {
      json: compact({
        action: request.action,
        target: request.target,
        purpose: request.purpose,
        task_id: request.task_id,
        service_class: request.service_class,
      }),
    });
  }

  async getPolicy(): Promise<Record<string, unknown>> {
    return this.client.request("GET", `${SERVICE_BASE}/policy`);
  }

  async health(): Promise<Record<string, unknown>> {
    return this.client.request("GET", `${SERVICE_BASE}/health`);
  }
}
