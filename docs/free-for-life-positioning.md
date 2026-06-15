# Free Forever Developer Positioning

KSwitch Developer Edition should be generous enough that developers can build,
test, and demo real governed agent flows without speaking to sales.

It should also be bounded enough that enterprise buyers still need the commercial
platform for production.

## Public Promise

Suggested wording:

> KSwitch Developer Edition is free forever for local development, demos,
> evaluation, and non-production agent governance.

Avoid calling it production-ready. Avoid calling local proxy routing hard desktop
containment. Avoid promising support, uptime, managed deployment, cloud
templates, or regulated-workload enforcement in the free repo.

## What Is Free

- Language SDKs.
- Local control-plane container image.
- Local Keycloak realm for PKCE.
- Local SPIRE for workload identity.
- Local MCP gateway with Envoy and OPA.
- Starter policies and examples.
- Audit and kill-switch walkthroughs.
- Local smoke and doctor checks.

## What Stays Commercial

- Production deployment rights.
- Enterprise support and SLA.
- Cloud/Kubernetes deployment packages.
- HA, backup/restore, multi-region, and fleet operations.
- Enterprise SSO and directory integration beyond local Keycloak.
- Desktop hard egress containment.
- Host-level eBPF/Tetragon detection.
- L2/L3 device assurance, TPM proof, WebAuthn step-up, and break-glass FIDO2.
- Streaming SIEM/event bus integrations.
- Workflow automation and fleet specialist agents.
- Commercial policy packs and managed compliance reporting.

## Recommended Limits

Use hard caps rather than expiry:

| Resource | Free Developer Edition |
| --- | ---: |
| Tenants | 1 local tenant |
| Agents | 10 |
| MCP servers | 10 |
| Tools | 100 |
| Skills | 100 |
| Deployment target | Local/laptop only |

That gives developers enough room to feel the product, while preventing the free
edition from becoming an undeclared production tier.
