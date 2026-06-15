# KSwitch Go SDK

Go client for the KSwitch Agent Trust Control Plane.

## Install

```sh
go get github.com/KswitchDev/kswitch-sdks/packages/go/kswitch
```

## Usage

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

