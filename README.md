# KSwitch SDKs

Official SDK packages for the KSwitch Agent Trust Control Plane.

This repository is intentionally narrow. It contains the SDK packages and small executable examples that the Developer Hub can link to directly, without marketing-site assets, website content, or unrelated documentation.

## Packages

| Language | Path | Package |
| --- | --- | --- |
| Python | `packages/python` | `kswitch-sdk` |
| TypeScript | `packages/typescript` | `@kswitch/sdk` |
| Go | `packages/go` | `github.com/KswitchDev/kswitch-sdks/packages/go/kswitch` |

## Quick Start

Set the API endpoint and token:

```sh
export KSWITCH_BASE_URL="https://api.kswitch.io"
export KSWITCH_API_KEY="..."
```

The clients also accept the Developer Hub aliases `KSWITCH_URL` and `KSWITCH_TOKEN`.

Python:

```python
from kswitch import KSwitchClient

client = KSwitchClient.from_env()
agent = client.governance.register_agent(
    display_name="customer-onboarding-v1",
    record_type="AGENT",
    risk_tier="tier_2",
    owning_division="Retail Banking",
    owning_team="onboarding-platform",
)
client.governance.connect_mcps(agent["id"], mcp_ids=["mcp-kyc", "mcp-customer-data"])
```

TypeScript:

```ts
import { KSwitchClient } from "@kswitch/sdk";

const client = KSwitchClient.fromEnv();
const agent = await client.governance.registerAgent({
  display_name: "customer-onboarding-v1",
  record_type: "AGENT",
  risk_tier: "tier_2",
  owning_division: "Retail Banking",
  owning_team: "onboarding-platform",
});
await client.governance.connectMcps(agent.id, { mcp_ids: ["mcp-kyc", "mcp-customer-data"] });
```

Go:

```go
client, err := kswitch.NewClientFromEnv()
if err != nil {
    return err
}

agent, err := client.Governance.RegisterAgent(ctx, &kswitch.RegisterAgentRequest{
    DisplayName:    "customer-onboarding-v1",
    RecordType:     "AGENT",
    RiskTier:       "tier_2",
    OwningDivision: "Retail Banking",
    OwningTeam:     "onboarding-platform",
})
```

## Repository Layout

```text
packages/
  python/
  typescript/
  go/
examples/
  python/
  typescript/
  go/
```

## Development

Python:

```sh
python -m unittest discover -s packages/python/tests
```

TypeScript:

```sh
cd packages/typescript
npm install
npm run build
npm test
```

Go:

```sh
cd packages/go
go test ./...
```

## API Compatibility

The SDKs are thin HTTP clients over the KSwitch API and are designed to track the Developer Hub and OpenAPI contract. High-level methods cover the developer journey shown in KSwitch examples: registering an agent, connecting MCPs, updating policy enforcement, listing audit events, evaluating toxic combos, and operating kill-switch actions.
