# @kswitch/sdk

TypeScript SDK for the **KSwitch.ai Agent Governance Platform**.

Provides typed access to agent registration, policy evaluation, AuthZen authorization, identity management, compliance, kill switch operations, and more.

## Installation

```bash
npm install @kswitch/sdk
```

Requires Node.js 18+ (uses native `fetch`).

## Quick Start

```typescript
import { KSwitchClient } from "@kswitch/sdk";

// With static token
const client = new KSwitchClient({
  baseUrl: "https://kswitch.example.com",
  token: "your-bearer-token",
});

// Or with M2M client credentials (auto-refreshes)
const client = new KSwitchClient({
  baseUrl: "https://kswitch.example.com",
  clientId: "my-agent",
  clientSecret: "secret",
  keycloakUrl: "https://keycloak.example.com",
  keycloakRealm: "kswitch",
});

// Register an agent
const agent = await client.governance.registerAgent({
  display_name: "My Agent",
  record_type: "AGENT",
  risk_tier: "tier_2",
});

// Evaluate authorization (AuthZen)
const decision = await client.authzen.evaluate({
  subject: { type: "agent", id: agent.id },
  resource: { type: "mcp_tool", id: "postgres-query" },
  action: { name: "invoke" },
});

// Enforce MCP tool call
const result = await client.enforcement.enforceMCPCall({
  agent_id: agent.id,
  mcp_server_id: "mcp-postgres",
  tool_name: "query",
});
```

## API Namespaces

| Namespace | Description |
|---|---|
| `client.governance` | Agent CRUD, approval workflow, MCP registration, delegation, audit |
| `client.policy` | Cedar/Rego policy management, evaluation, mode switching |
| `client.authzen` | AuthZen PDP: evaluation, batch evaluation, search |
| `client.identity` | SPIFFE/SVID, service identities, trust domains, rotation |
| `client.compliance` | Toxic combo rules, evaluation, boundary analysis |
| `client.killswitch` | Targeted/blanket/auto kill switch, history, violations |
| `client.events` | Event outbox, fleet events, stats, replay |
| `client.catalog` | Skills catalog, tools catalog, sync sources |
| `client.enforcement` | Runtime MCP call gating |

Top-level convenience methods are also available for health, scanner, graph, fleet, and onboard operations.

## Error Handling

```typescript
import {
  KSwitchClient,
  AuthError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
  NetworkError,
} from "@kswitch/sdk";

try {
  await client.governance.getAgent("nonexistent");
} catch (err) {
  if (err instanceof NotFoundError) {
    console.log("Agent not found");
  } else if (err instanceof AuthError) {
    console.log("Auth failed:", err.statusCode);
  } else if (err instanceof ValidationError) {
    console.log("Bad request:", err.message);
  }
}
```

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `baseUrl` | `string` | *required* | KSwitch API base URL |
| `token` | `string` | - | Static Bearer token |
| `clientId` | `string` | - | OAuth2 client ID for M2M auth |
| `clientSecret` | `string` | - | OAuth2 client secret |
| `keycloakUrl` | `string` | - | Keycloak base URL |
| `keycloakRealm` | `string` | `"kswitch"` | Keycloak realm |
| `tokenEndpoint` | `string` | - | Custom token endpoint URL |
| `resource` | `string` | - | OAuth2 resource/audience |
| `timeout` | `number` | `30000` | Request timeout (ms) |
| `retries` | `number` | `3` | Retry count on 503/network errors |
| `backoffMs` | `number` | `1000` | Base backoff for exponential retry |

## Building

```bash
npm install
npm run build      # Builds ESM + CJS
npm run typecheck   # Type-check only
```

## License

Apache-2.0
