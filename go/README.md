# KSwitch.ai Go SDK

Official Go SDK for the [KSwitch.ai](https://hub.kswitch.io) agent governance platform.

## Installation

```bash
go get github.com/KswitchDev/kswitch-devkit/go
```

Requires Go 1.22+. Zero external dependencies (standard library only).

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/KswitchDev/kswitch-devkit/go/kswitch"
)

func main() {
    client := kswitch.NewClient(
        kswitch.WithBaseURL("https://kswitch.example.com"),
        kswitch.WithToken("your-bearer-token"),
    )

    ctx := context.Background()

    // Register an agent
    agent, err := client.Governance.RegisterAgent(ctx, &kswitch.RegisterAgentRequest{
        DisplayName: "my-agent",
        RiskTier:    "tier_2",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Agent registered: %s\n", agent.ID)
}
```

## Authentication

### Static Bearer Token

```go
client := kswitch.NewClient(
    kswitch.WithToken("your-token"),
)
```

### Workload Identity

For service-to-service calls, use workload identity first: SPIFFE JWT-SVID,
WIMSE assertion, cloud workload identity, or another workload-bound token source
configured by your organisation. The SDK sends that assertion as a bearer token;
key custody and rotation stay with the identity provider. Use the Developer
Edition stack to exercise this locally.

### Client Credentials (compatibility fallback)

```go
secret := os.Getenv("KSWITCH_CLIENT_SECRET")

client := kswitch.NewClient(
    kswitch.WithKeycloak(
        "https://keycloak.example.com",  // Keycloak URL
        "kswitch",                        // Realm
        "my-client-id",                   // Client ID
        secret,                           // Client secret
    ),
)
```

Tokens are cached in memory and automatically refreshed before expiry. Use this
fallback only where the deployment cannot issue workload-bound identity.

## Services

| Service | Access | Description |
|---------|--------|-------------|
| `Governance` | `client.Governance` | Agent registration, lifecycle, MCP servers, audit, dashboard, health |
| `Policy` | `client.Policy` | Cedar/Rego policy CRUD, validation, evaluation history |
| `Identity` | `client.Identity` | SPIFFE identities, trust domains, rotation |
| `Compliance` | `client.Compliance` | Toxic combos, boundary analysis, risk assessment |
| `KillSwitch` | `client.KillSwitch` | Targeted and blanket kill switch operations |
| `Events` | `client.Events` | Governance event outbox queries and statistics |
| `Catalog` | `client.Catalog` | Skills/tools catalogs, sync sources |
| `Enforcement` | `client.Enforcement` | Scanner, graph analysis, blast radius |
| `AuthZen` | `client.AuthZen` | OpenID AuthZen PDP authorization evaluation |

## Configuration Options

```go
client := kswitch.NewClient(
    kswitch.WithBaseURL("https://kswitch.example.com"),
    kswitch.WithToken("bearer-token"),
    kswitch.WithKeycloak(url, realm, clientID, secret), // fallback M2M auth
    kswitch.WithTLSConfig(tlsConfig),   // mTLS / CA pinning
    kswitch.WithTimeout(60 * time.Second),
    kswitch.WithRetries(5),
    kswitch.WithBackoff(2 * time.Second),
    kswitch.WithHTTPClient(customClient),
    kswitch.WithLogger(slog.Default()),
    kswitch.WithUserAgent("my-app/1.0"),
    kswitch.WithResource("https://api.kswitch.ai"),
)
```

## Error Handling

```go
agent, err := client.Governance.GetAgent(ctx, "agent-123")
if err != nil {
    if kswitch.IsNotFound(err) {
        fmt.Println("Agent not found")
    } else if kswitch.IsUnauthorized(err) {
        fmt.Println("Authentication failed")
    } else {
        fmt.Printf("Error: %v\n", err)
    }
}
```

## Examples

See the [examples/](examples/) directory for complete working examples:

- **register/** - Agent registration and skill assignment
- **evaluate/** - Toxic combo evaluation and AuthZen authorization
- **killswitch/** - Kill switch history and operations

## Running the Contract Tests

The SDK ships with a full test suite — interceptor parity, Local PDP
evaluation, WIMSE builder, audit emitter, revocation cache, etc.

```bash
cd go
go test -v ./...
```

Requires Go 1.22+ on PATH (matches `go.mod` line 3). If Go is not
installed, see `docs/runbooks/GO-SDK-TOOLCHAIN.md` for the full
install path (macOS / Linux / Windows / Docker), the list of tests
the suite contains, and how to run just the interceptor parity
subset used by the cross-SDK conformance check.

CI runs `go test ./...` plus `govulncheck ./...` on every PR via
`.github/workflows/ci.yml` — see `test-sdk-go` and `security-go`
jobs (both pinned to `actions/setup-go@v5` with Go 1.22).

## License

Apache License 2.0
