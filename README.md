# KSwitch SDKs + Developer Edition

Official SDK packages and the Developer Edition landing for the KSwitch
Agent Trust Control Plane.

This repository has two jobs:

1. Ship the language SDKs developers import into agents, MCP servers, and
   governed tools.
2. Provide a local KSwitch Developer Edition path that proves the SDKs against
   a local control plane, SPIFFE identity, policy decisioning, audit, and MCP
   gateway flow.

Developer Edition has no scheduled expiry for permitted local non-commercial
development, demos, SDK integration, and bounded non-production evaluation of
the applicable release version. It is not the enterprise deployment package, a
production support entitlement, a commercial-use licence, or a full source drop.

## Start Here

| Goal | Path |
| --- | --- |
| Use a language SDK | `python/`, `typescript/`, or `go/` |
| Run Developer Edition locally | `devkit/` |
| Understand service authentication | `docs/auth-model.md` |
| Understand the commercial boundary | `docs/developer-edition-positioning.md` |
| Review bypass and hardening rules | `BYPASS_HARDENING.md` |
| Review licence boundaries | `LICENSE.md` and `COMMERCIAL-USE.md` |

## Developer Edition

The local Developer Edition stack is built from the existing pilot bundle, but
deliberately refactored for public developer use:

- No time-boxed trial posture.
- No customer-specific source drop.
- No cloud deployment templates in the free path.
- No production SLA, support entitlement, or managed deployment rights.
- Cap enforcement in official unmodified artefacts instead of trial expiry.
- No licence file or renewal flow in the free local path.
- SPIFFE/workload identity as the preferred service-auth path.

The intended developer loop is:

```sh
cd devkit
cp .env.example .env
make up
```

Then use the SDK examples against `https://localhost:5001` and the local MCP
gateway. The `devkit/` directory documents the target package shape while the
pilot assets are being imported.

## Packages

| Language | Path | Package |
| --- | --- | --- |
| Python | `python/` | `kswitch-sdk` |
| TypeScript | `typescript/` | `@kswitch/sdk` |
| Go | `go/` | `github.com/KswitchDev/kswitch-sdks/go` |

The current SDK release train is recorded in [`SDK_VERSION`](SDK_VERSION).

## Authentication Posture

For humans and local development, use the Developer Edition PKCE helper to mint
short-lived bearer tokens.

For service-to-service calls, prefer workload identity:

- SPIFFE JWT-SVID / WIMSE where the workload can access a SPIRE Workload API
  socket.
- mTLS where the deployment uses client certificate identity.
- OAuth2 client credentials only as a legacy IdP fallback when workload identity
  is not available.

Do not make `client_id` + `client_secret` the primary public example. It is
supported for compatibility, but it creates secret lifecycle and distribution
work that KSwitch should avoid when the environment can issue workload-bound
identity.

## Developer Hub

- [Python SDK docs](https://kswitch.io/sdk/python.html)
- [TypeScript SDK docs](https://kswitch.io/sdk/typescript.html)
- [Go SDK docs](https://kswitch.io/sdk/go.html)

## Local Checks

Python:

```sh
cd python
python -m pip install -e ".[dev]"
pytest tests -q
```

TypeScript:

```sh
cd typescript
npm ci
npm test
```

Go:

```sh
cd go
go test ./...
```

## Licenses

This repository uses a mixed licence model. See [`LICENSE.md`](LICENSE.md).

Each SDK package carries its own licence file:

- `python/LICENSE`
- `typescript/LICENSE`
- `go/LICENSE`

The runnable `devkit/` is source-available under the KSwitch Developer Edition
Licence and is not open source.
