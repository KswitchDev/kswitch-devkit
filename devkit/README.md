# KSwitch Developer Edition

KSwitch Developer Edition is the free forever local stack for developers who
want to build against the SDKs without needing a commercial KSwitch deployment.

It should be meaningful enough to prove the product:

- Register an agent or MCP server.
- Route a governed MCP call through the local gateway.
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

## Target Quick Start

```sh
cd devkit
cp .env.example .env
make up
```

The target `make up` should start:

- KSwitch control plane image.
- Postgres and Valkey.
- Keycloak local realm for human PKCE login.
- SPIRE server and SPIRE agent for workload identity.
- OPA and Envoy MCP gateway.
- A simple gateway upstream for end-to-end examples.
- Seed data, starter policies, and SDK walkthrough examples.

Observability can be optional. Vault should be optional unless the example is
explicitly demonstrating secretless integration.

## Licence Model

The public developer path should not use the pilot renewal flow.

Preferred model:

- No licence file required for Developer Edition.
- Server starts in `edition=developer` when the devkit profile is selected.
- Hard caps are enforced locally.
- Enterprise-only features remain unavailable.

Fallback model if the platform currently requires a signed licence:

- Bundle a non-customer-specific perpetual developer licence.
- Use `edition: "developer"`.
- Omit `exp`, or set a far-future non-renewal date only if the verifier cannot
  yet support no-expiry claims.
- Keep strict caps, local-only wording, and disabled enterprise features.

Suggested starter caps:

| Resource | Cap |
| --- | ---: |
| Agents | 10 |
| MCP servers | 10 |
| Tools | 100 |
| Skills | 100 |
| Policy bundles | 10 |

## Authentication Contract

The public examples should show this order:

1. Human/local: PKCE token from the bundled CLI.
2. Workload/service: SPIFFE JWT-SVID or WIMSE from SPIRE.
3. Compatibility fallback: OAuth2 client credentials.

Client credentials are still useful for legacy IdP integration, but they should
not be the flagship service-to-service path for KSwitch. They create shared
secret distribution, rotation, and storage obligations that workload identity is
meant to remove.

## Import Source

This directory should be built from:

```text
/Users/Max1/agent-registration-config-pg/customer-bundles/edition-pilot/
```

Use `MIGRATION_FROM_PILOT.md` for the exact keep/change/drop map.
