# KSwitch TypeScript SDK

TypeScript client for the KSwitch Agent Trust Control Plane.

## Install

```sh
npm install @kswitch/sdk
```

## Usage

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
```

