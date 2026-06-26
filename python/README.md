# KSwitch.ai Python SDK

Python SDK for the [KSwitch.ai](https://hub.kswitch.io) agent governance platform. Provides typed access to agent lifecycle, Cedar/Rego policy management, SPIFFE identity, AuthZen authorization, compliance (toxic combos, boundary analysis), kill switch operations, and MCP enforcement.

## Installation

```bash
pip install kswitch-sdk
```

Or from source:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Synchronous (default)

```python
from kswitch import KSwitchClient

client = KSwitchClient(
    base_url="https://localhost:5001",
    token="your-bearer-token",
)

# Register an agent
agent = client.governance.register_agent(
    display_name="data-pipeline-agent",
    risk_tier="tier_2",
    owning_division="engineering",
)
print(f"Registered: {agent.id}")

# Evaluate toxic combos
result = client.compliance.evaluate_toxic_combos(agent.id)
if result.clean:
    # Approve the agent
    client.governance.approve(agent.id, reviewed_by="admin@company.com")

client.close()
```

### Context manager

```python
with KSwitchClient(base_url="https://localhost:5001", token="...") as client:
    agents = client.governance.list_agents(page_size=100)
    for agent in agents.data:
        print(f"{agent.display_name}: {agent.status}")
```

### Async

```python
import asyncio
from kswitch import KSwitchAsyncClient

async def main():
    async with KSwitchAsyncClient(base_url="https://localhost:5001", token="...") as client:
        agent = await client.governance.register_agent(display_name="my-agent")
        decision = await client.authzen.evaluate(
            subject={"type": "agent", "id": agent.id},
            resource={"type": "tool", "id": "read-database"},
            action={"name": "invoke"},
        )
        print(f"Allowed: {decision.decision}")

asyncio.run(main())
```

### Service Auth

For service-to-service calls, use workload identity first: SPIFFE JWT-SVID,
WIMSE assertion, cloud workload identity, or another workload-bound token source
configured by your organisation. The SDK sends that assertion as a bearer token;
key custody and rotation stay with the identity provider.

OAuth2 client credentials are supported as a compatibility fallback for legacy
IdP deployments that cannot issue workload-bound tokens. Do not hard-code the
secret.

### Workload Identity

```python
import os

client = KSwitchClient(
    base_url="https://kswitch.internal:5001",
    token=os.environ["KSWITCH_WORKLOAD_TOKEN"],
)
```

### Client Credentials (compatibility fallback)

```python
import os

client = KSwitchClient(
    base_url="https://kswitch.internal:5001",
    client_id=os.environ["KSWITCH_CLIENT_ID"],
    client_secret=os.environ["KSWITCH_CLIENT_SECRET"],
    keycloak_url="https://keycloak.internal:8080",
    keycloak_realm="kswitch",
)
# Token is fetched automatically and refreshed on 401
```

## API Namespaces

| Namespace | Description |
|-----------|-------------|
| `client.governance` | Agent/MCP lifecycle: register, approve, suspend, decommission, gates |
| `client.policy` | Cedar/Rego policies: create, evaluate, validate, mode switching |
| `client.identity` | SPIFFE identities, service identities, trust domains |
| `client.compliance` | Toxic combos, boundary analysis, risk scoring |
| `client.killswitch` | Targeted, blanket, and auto kill switch operations |
| `client.events` | Event outbox: list, replay, stats, webhooks |
| `client.catalog` | Skills/tools catalog, sync sources, scanner, onboarding |
| `client.enforcement` | MCP call enforcement, fleet management, graph operations |
| `client.authzen` | AuthZen PDP: evaluate, batch, search, discovery |

## Configuration

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| `base_url` | `KSWITCH_BASE_URL` | `https://localhost:5001` | API base URL |
| `token` | `KSWITCH_AUTH_TOKEN` | — | Bearer token from PKCE or workload identity |
| `client_id` | — | — | OAuth2 client ID for fallback M2M |
| `client_secret` | — | — | OAuth2 client secret for fallback M2M |
| `keycloak_url` | — | — | Keycloak-compatible issuer base URL |
| `ca_path` | `KSWITCH_CA_FILE` | auto-detect mkcert | CA bundle for TLS |
| `verify_ssl` | — | `True` | Enable TLS verification |
| `timeout` | — | `30.0` | Request timeout (seconds) |
| `retries` | — | `3` | Max retries on 503/connection errors |

## Error Handling

```python
from kswitch import KSwitchClient, NotFoundError, AuthError, ValidationError

client = KSwitchClient(base_url="https://localhost:5001", token="...")

try:
    agent = client.governance.get_agent("nonexistent-id")
except NotFoundError:
    print("Agent not found")
except AuthError:
    print("Authentication failed")
except ValidationError as e:
    print(f"Validation error: {e}")
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type check
mypy kswitch/

# Lint
ruff check kswitch/
```

## License

Apache-2.0
