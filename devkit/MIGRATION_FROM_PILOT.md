# Migration From Pilot Bundle

The pilot bundle is the right source material for DevKit. `ATCPDev`
is not: it is a full source/trial drop and should not become the public free
developer surface.

Source:

```text
/Users/Max1/agent-registration-config-pg/customer-bundles/edition-pilot/
```

## Keep

| Pilot asset | DevKit destination | Notes |
| --- | --- | --- |
| `Makefile` | `devkit/Makefile` | Rename product text from pilot to DevKit. |
| `docker-compose.yml` | `devkit/docker-compose.yml` | Keep local-only profiles. Remove cloud/customer pilot language. |
| `.env.example` | `devkit/.env.example` | Make `KSWITCH_CUSTOMER_ID` default to `developer-local` or similar. |
| `scripts/tls.sh` | `devkit/scripts/tls.sh` | Keep local self-signed TLS path. |
| `scripts/seed.sh` | `devkit/scripts/seed.sh` | Seed developer persona and examples. |
| `scripts/smoke.sh` | `devkit/scripts/smoke.sh` | Keep no-browser API smoke. |
| `scripts/doctor.sh` | `devkit/scripts/doctor.sh` | Remove licence-expiry checks; keep health hints. |
| `gateway/` | `devkit/gateway/` | Keep Envoy/OPA gateway demo. |
| `cli/pkce.py` | `devkit/cli/pkce.py` | Human/local auth helper. |
| `seed/realm-export.json` | `devkit/seed/realm-export.json` | Keep local Keycloak realm, remove customer pilot values. |
| `sdks/*` | Use repo root SDKs | Replace bundle-copied SDKs with references to `../python`, `../typescript`, `../go`. |
| `mcp-server/` | `mcp-server/` | Keep the MCP server/proxy package as a repo-root package. Do not run it as a default compose service; local MCP clients launch the stdio commands. |

## Change

| Area | Required change |
| --- | --- |
| Branding | Replace `pilot bundle` with `DevKit`. |
| Entitlement | Remove the time-boxed renewal flow. Use the DevKit loader overlay and no customer licence file. |
| Caps | Lower from pilot-sized limits to developer caps. |
| Auth docs | Lead with PKCE for humans and SPIFFE/WIMSE for services. Client credentials are fallback only. |
| Runtime text | Say local/non-production explicitly. Avoid implying managed fleet enforcement. |
| Observability | Optional profile only. Keep light, not enterprise SIEM. |
| Vault | Optional profile only unless required for a specific secretless walkthrough. |

## Drop

| Pilot asset | Reason |
| --- | --- |
| `deploy/aws/` | Turns the free repo into a cloud deployment package. |
| `deploy/azure/` | Same. |
| `deploy/gcp/` | Same. |
| `deploy/kubernetes/` | Same unless later published as paid/eval material. |
| `RENEWAL.md` | Time-boxed trial posture conflicts with non-expiring permitted non-commercial use. |
| Customer-specific `licence/licence.jws` | Do not ship customer artefacts or expiring trial claims. |
| `scripts/licence_info.py` | No licence file exists in DevKit. Use `make devkit-limits`. |
| Support-contact language | DevKit should route to docs/community channels, not customer support promises. |

## Preserve As Commercial Boundary

Keep the pilot's "does not demonstrate" boundary, rewritten for DevKit:

- Desktop hard egress containment.
- Tetragon/eBPF ungoverned execution detection.
- Fleet specialist agents.
- Streaming event bus and workflow automation.
- L2/L3 device assurance.
- Break-glass FIDO2.
- Enterprise deployment, HA, SIEM, SSO, and managed support.

Those exclusions are important. They make the free product useful without
giving away the enterprise deployment.
