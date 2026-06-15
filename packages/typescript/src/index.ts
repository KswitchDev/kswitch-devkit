export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  token?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface RegisterAgentRequest {
  display_name: string;
  record_type: string;
  risk_tier: string;
  owning_division: string;
  owning_team: string;
  skills?: string[];
  metadata?: JsonObject;
}

export interface ConnectMcpsRequest {
  mcp_ids: string[];
}

export class KSwitchError extends Error {
  readonly status?: number;
  readonly body?: unknown;

  constructor(message: string, options: { status?: number; body?: unknown } = {}) {
    super(message);
    this.name = "KSwitchError";
    this.status = options.status;
    this.body = options.body;
  }
}

export class KSwitchClient {
  readonly baseUrl: string;
  readonly governance: GovernanceClient;
  readonly policy: PolicyClient;
  readonly audit: AuditClient;
  readonly tools: ToolsClient;
  readonly killSwitch: KillSwitchClient;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: ClientOptions) {
    if (!options.baseUrl) {
      throw new Error("baseUrl is required");
    }
    const apiKey = options.apiKey ?? options.token;
    if (!apiKey) {
      throw new Error("apiKey or token is required");
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.governance = new GovernanceClient(this);
    this.policy = new PolicyClient(this);
    this.audit = new AuditClient(this);
    this.tools = new ToolsClient(this);
    this.killSwitch = new KillSwitchClient(this);
  }

  static fromEnv(): KSwitchClient {
    const apiKey = process.env.KSWITCH_API_KEY ?? process.env.KSWITCH_TOKEN;
    if (!apiKey) {
      throw new Error("KSWITCH_API_KEY or KSWITCH_TOKEN is required");
    }

    return new KSwitchClient({
      baseUrl: process.env.KSWITCH_BASE_URL ?? process.env.KSWITCH_URL ?? "https://api.kswitch.io",
      apiKey,
    });
  }

  async request<T = unknown>(
    method: string,
    path: string,
    options: { body?: JsonObject; query?: Record<string, string | number | boolean | undefined> } = {},
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(this.buildUrl(path, options.query), {
        method,
        body: options.body ? JSON.stringify(options.body) : undefined,
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          "user-agent": "kswitch-typescript/0.1.0",
        },
        signal: controller.signal,
      });

      const text = await response.text();
      const payload = text ? parseJson(text) : undefined;
      if (!response.ok) {
        throw new KSwitchError(`KSwitch API request failed with status ${response.status}`, {
          status: response.status,
          body: payload,
        });
      }

      return payload as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildUrl(path: string, query?: Record<string, string | number | boolean | undefined>): string {
    const url = new URL(path.startsWith("/") ? path : `/${path}`, `${this.baseUrl}/`);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }
}

export class GovernanceClient {
  constructor(private readonly client: KSwitchClient) {}

  registerAgent(request: RegisterAgentRequest): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", "/api/v1/agents/register", {
      body: {
        ...request,
        skills: request.skills ?? [],
        metadata: request.metadata ?? {},
      },
    });
  }

  connectMcps(agentId: string, request: ConnectMcpsRequest): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/mcps`, {
      body: { mcp_ids: request.mcp_ids },
    });
  }

  evaluateToxicCombos(agentId: string): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/evaluate-toxic-combos`);
  }

  approveAgent(agentId: string, request: { second_line_ref?: string } = {}): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/approve`, {
      body: { ...request },
    });
  }
}

export class PolicyClient {
  constructor(private readonly client: KSwitchClient) {}

  update(policyId: string, fields: JsonObject): Promise<JsonObject> {
    return this.client.request<JsonObject>("PATCH", `/api/v1/policies/${encodeURIComponent(policyId)}`, {
      body: fields,
    });
  }
}

export class AuditClient {
  constructor(private readonly client: KSwitchClient) {}

  events(filters: { agent_id?: string; event_type?: string; limit?: number } = {}): Promise<JsonObject> {
    return this.client.request<JsonObject>("GET", "/api/v1/audit/events", {
      query: filters,
    });
  }
}

export class ToolsClient {
  constructor(private readonly client: KSwitchClient) {}

  list(): Promise<JsonObject> {
    return this.client.request<JsonObject>("GET", "/api/v1/tools-catalog");
  }
}

export class KillSwitchClient {
  constructor(private readonly client: KSwitchClient) {}

  targetedKillSwitch(agentId: string, request: { reason: string }): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/kill-switch`, {
      body: { reason: request.reason },
    });
  }

  suspendAgent(agentId: string, request: { reason: string }): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/suspend`, {
      body: { reason: request.reason },
    });
  }

  reactivateAgent(agentId: string): Promise<JsonObject> {
    return this.client.request<JsonObject>("POST", `/api/v1/agents/${encodeURIComponent(agentId)}/reactivate`);
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
