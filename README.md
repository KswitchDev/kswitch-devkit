# KSwitch DevKit

[![SDK CI](https://github.com/KswitchDev/kswitch-devkit/actions/workflows/ci.yml/badge.svg)](https://github.com/KswitchDev/kswitch-devkit/actions/workflows/ci.yml)

Build governed AI-agent integrations without standing up the full enterprise
platform first.

KSwitch DevKit gives developers the language SDKs, local runtime, and examples
needed to try real agent-control flows on a laptop: register an agent, evaluate
policy, emit audit events, trigger a kill switch, and test workload identity
as the default service-to-service authentication model. It also includes the
KSwitch MCP server and governing proxy commands for MCP-compatible developer
tools.

If this helps you build or explain safer agent systems, star the repo. Stars help
us see which SDKs, examples, and integrations to invest in next.

## What You Can Do

With this repo you can:

- Add KSwitch governance calls to Python, TypeScript, or Go applications.
- Run a local Developer Edition control plane for SDK integration.
- Exercise policy decisions, audit events, and kill-switch flows end to end.
- Connect Claude Code, Cursor, Windsurf, Cline, OpenCode, or OpenClaw through
  `kswitch-mcp` or wrap existing upstream MCP servers with `kswitch-proxy`.
- Try SPIFFE/WIMSE workload identity locally with optional SPIRE services.
- Learn the production auth posture before wiring an enterprise deployment.

The Developer Edition path is free for permitted local, non-commercial
development, education, demos, SDK integration, and bounded non-production
evaluation. It has no scheduled expiry for the applicable release version.

## Quick Start

Prerequisites:

- Docker with the Compose plugin
- `make`
- `openssl`
- `curl`
- `jq`

Start the local Developer Edition stack:

```sh
cd devkit
cp .env.example .env
# Set KEYCLOAK_ADMIN_PASSWORD in .env to a strong local password.
make up
```

Then open:

- App and local API: `https://localhost:5001`
- Local docs: `https://localhost:5001/docs/`
- Health and hints: `make doctor`

For workload-identity examples, use the SPIRE profile:

```sh
make up-with-identity
```

Install the MCP commands for local MCP-compatible tools:

```sh
cd devkit
make mcp-install
```

That installs `kswitch-mcp`, `kswitch-proxy`, `kswitch-brain-mcp`, and
`kswitch-service-mcp` from the bundled `../mcp-server` package. The Docker
gateway remains the network proxy path; the MCP commands are stdio servers used
by local developer tools.

## SDKs

| Language | Package | Path | Docs |
| --- | --- | --- | --- |
| Python | `kswitch-sdk` | `python/` | [Python SDK](https://hub.kswitch.io/sdk/python.html) |
| TypeScript | `@kswitch/sdk` | `typescript/` | [TypeScript SDK](https://hub.kswitch.io/sdk/typescript.html) |
| Go | `github.com/KswitchDev/kswitch-devkit/go` | `go/` | [Go SDK](https://hub.kswitch.io/sdk/go.html) |
| MCP | `kswitch-mcp` | `mcp-server/` | [MCP package](mcp-server/README.md) |

For local development from source:

```sh
cd python
python -m pip install -e ".[dev]"

cd ../typescript
npm ci

cd ../go
go test ./...
```

## Service Auth Posture

KSwitch leads with workload identity for service-to-service calls.

Preferred order:

1. Local human development: OAuth2 PKCE using the bundled Developer Edition CLI.
2. Service workloads: SPIFFE JWT-SVID or WIMSE assertions from SPIRE.
3. Transport identity: mTLS where client certificates are the deployment
   identity.
4. Compatibility fallback: OAuth2 client credentials when workload identity is
   not available.

WLID is the KSwitch service-auth path: the workload receives a short-lived,
workload-bound assertion, while key custody and rotation stay with the identity
provider. OAuth2 client credentials remain a compatibility bridge for
environments that cannot issue workload-bound tokens yet.

Read more in [docs/auth-model.md](docs/auth-model.md) and
[docs/governed-invocation.md](docs/governed-invocation.md).

## Free Developer Edition Boundary

Developer Edition is meant for real local testing while keeping the free path
bounded. Official unmodified artefacts enforce these local caps:

| Resource | Cap |
| --- | ---: |
| Agents | 10 |
| MCP servers | 10 |
| Tools | 100 |
| Skills | 100 |

What is included:

- Local control-plane runtime for SDK evaluation.
- Local Keycloak realm for PKCE.
- Optional local SPIRE for workload identity examples.
- OPA-backed policy-decision path.
- Local MCP server and governing proxy commands for developer tools.
- Starter policies, examples, smoke checks, and doctor checks.

What is not included:

- Production deployment rights.
- Customer-facing, managed-service, revenue-generating, or internal
  business-operation use.
- Commercial support, SLA, cloud deployment packages, HA, SIEM, fleet
  operations, desktop hard-containment, or enterprise enforcement add-ons.
- Rights to bypass, disable, or remove Developer Edition caps.

Commercial use requires a separate written agreement with KSwitch. See
[LICENSE.md](LICENSE.md) and [COMMERCIAL-USE.md](COMMERCIAL-USE.md).

## Repository Map

| Path | Purpose |
| --- | --- |
| `python/` | Python SDK, tests, examples, framework adapters |
| `typescript/` | TypeScript SDK, tests, package metadata |
| `go/` | Go SDK, tests, examples |
| `devkit/` | Local Developer Edition runtime and lifecycle scripts |
| `mcp-server/` | KSwitch MCP server, governing proxy, service MCP, and client configs |
| `docs/` | Auth and Developer Edition positioning notes |
| `reports/ep227/` | Release-gate evidence for the public devkit boundary |

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

Release gate:

```sh
make validate-ep227-release
```

## Community And Security

Use the [issue chooser](https://github.com/KswitchDev/kswitch-devkit/issues/new/choose)
for bugs, usage help, docs gaps, and SDK or example requests. Do not put
secrets, customer data, production logs, or sensitive environment details in
public issues.

Report suspected vulnerabilities privately to `security@kswitch.io`.

External code contributions are not accepted until KSwitch enables an approved
DCO, CLA, or no-external-contributions workflow.
