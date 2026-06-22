# B005 Agent Service Profiles

These profiles expose the B005.2 `kswitch_service` surface for agent-facing
fetch/search governance.

## Managed Profile

`managed-claude-code.json` is the customer assurance profile. It registers only
`kswitch-service-mcp` and declares native fetch, native search, and unmanaged
MCP registration as denied. Commercial managed runtime controls must enforce
those denials; this file is the agent registration contract, not the endpoint
firewall.

Human identity is provider-agnostic OIDC. Deployment supplies tenant-specific
values for Entra, Ping, Okta, ForgeRock, SlashID, AD federation, or another
standards-compliant IdP. Workload identity remains SPIFFE JWT-SVID, with WIMSE
delegation required for multi-hop.

`service-context.env.example` lists the deployment-owned values that must be
present before the HTTP route resolver can build `B005TrustedContext`. These
values are not IdP-specific secrets; they bind validated SPIFFE workload
identity to the customer-owned B005 registry/profile context. OIDC user or M2M
claims alone must not be treated as B005 workload authority.

## Developer Profile

`developer-claude-code.json` is local-development only. It is explicitly
advisory and bypassable, and it may use the local Keycloak test issuer. It is
not managed-mode enforcement evidence.
