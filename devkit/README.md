# KSwitch DevKit

KSwitch DevKit is the source-available, non-commercial local stack
for developers who want to build against the SDKs without needing a commercial
KSwitch deployment.

Current DevKit runtime image tag: `v1.39-pg`.

It is not open source. Commercial evaluation and commercial, production,
customer-facing, internal business, managed-service, hosted, resale, or
revenue-generating use are outside DevKit and require a scoped KSwitch POC
engagement or separate written agreement before use.

It should be meaningful enough to prove the product:

- Register an agent or MCP server.
- Route a governed MCP call through the local gateway.
- Install `kswitch-mcp` and `kswitch-proxy` for MCP-compatible developer tools.
- Evaluate policy through the local PDP path.
- Emit an audit event.
- Trigger and observe a kill-switch decision.
- Exercise SPIFFE/WIMSE workload identity rather than long-lived shared
  service secrets.

It should not dilute the enterprise product:

- No production deployment licence.
- No cloud deployment templates.
- No HA, multi-region, SIEM, or enterprise SSO packaging.
- No desktop hard egress containment.
- No Tetragon/eBPF host enforcement.
- No L2/L3 device assurance, TPM proof, or break-glass FIDO2.
- No fleet specialist agents or workflow automation tier.
- No commercial support entitlement or SLA.

## Quick Start

```sh
cd devkit
cp .env.example .env
# Set KEYCLOAK_ADMIN_PASSWORD and KSWITCH_ACCEPT_DEVKIT_LICENSE=1.
make up
```

`make up` starts:

- KSwitch control plane image.
- Postgres and Valkey.
- Keycloak local realm for human PKCE login.
- SPIRE server and SPIRE agent for workload identity.
- OPA and Envoy MCP gateway.
- KSwitch MCP package (`kswitch-mcp`, `kswitch-proxy`,
  `kswitch-brain-mcp`, `kswitch-service-mcp`) installable from
  `../mcp-server`.
- A simple gateway upstream for end-to-end examples.
- Seed data, starter policies, and SDK walkthrough examples.

Observability can be optional. Vault should be optional unless the example is
explicitly demonstrating secretless integration.

The gateway and the MCP package are different surfaces. The gateway is an
Envoy/OPA network proxy. The MCP package installs stdio commands for local tools
such as Claude Code, Cursor, Windsurf, OpenCode, OpenClaw, and Cline. The
bundled gateway upstream remains an echo container by default; point Envoy at a
real upstream MCP service when testing network-path enforcement.

## Entitlement Model

The public developer path does not use the pilot renewal flow and does not ship
a customer licence file.

DevKit uses a local entitlement overlay:

- No licence file required for DevKit.
- The DevKit Licence must be accepted explicitly before `make up`.
- The overlay returns a fixed local entitlement for the DevKit compose path.
- Hard caps are enforced locally by the existing server-side cap decorators.
- Enterprise-only features remain unavailable.

Hard local caps:

| Resource | Cap |
| --- | ---: |
| Agents | 10 |
| MCP servers | 10 |
| Tools | 100 |
| Skills | 100 |

See:

- [`../LICENSE.md`](../LICENSE.md)
- [`../LICENSES/KSWITCH-DEVKIT-LICENSE.md`](../LICENSES/KSWITCH-DEVKIT-LICENSE.md)
- [`../COMMERCIAL-USE.md`](../COMMERCIAL-USE.md)

## Authentication Contract

The public examples should show this order:

1. Human/local: PKCE token from the bundled CLI.
2. Workload/service: SPIFFE JWT-SVID or WIMSE from SPIRE.
3. Compatibility fallback: OAuth2 client credentials.

WLID is the intended service-to-service path for KSwitch: short-lived,
workload-bound assertions, with key custody and rotation handled by the identity
provider. Client credentials remain a compatibility bridge for legacy IdP
deployments until the runtime can issue workload-bound tokens.

## Import Source

This directory should be built from:

```text
/Users/Max1/agent-registration-config-pg/customer-bundles/edition-pilot/
```

Use `MIGRATION_FROM_PILOT.md` for the exact keep/change/drop map.
