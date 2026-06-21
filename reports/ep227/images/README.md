# EP-227 Image Evidence

Status: ENGINEERING IMAGE INVENTORY READY - final digest/SBOM/scan evidence is
completed at release-tag time and approval is tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

Current public devkit image references:

| Image | Use |
| --- | --- |
| `ghcr.io/maxcope-alt/kswitch:v1.39.0-pg` | KSwitch app and bootstrap job. |
| `postgres:18` | Local database. |
| `quay.io/keycloak/keycloak:25.0` | Local OIDC realm for PKCE development. |
| `valkey/valkey:8` | Local cache/lock dependency. |
| `falkordb/falkordb:latest` | Local graph dependency. |
| `openpolicyagent/opa:1.15.1-envoy-static` | Local policy decision point. |
| `ghcr.io/spiffe/spire-server:1.11.0` | Optional local SPIRE server. |
| `ghcr.io/spiffe/spire-agent:1.11.0` | Optional local SPIRE agent. |

Final release evidence for every referenced image must include:

- immutable digest;
- provenance/source commit where applicable;
- SBOM;
- vulnerability scan;
- secret scan where applicable;
- licence inventory;
- redistribution-rights review;
- statement that no customer, trial, internal, or commercial-only artefacts are
  present.

Engineering SBOM status:

| Image | SBOM evidence |
| --- | --- |
| `postgres:18` | `sbom-postgres-18.syft.json` |
| `quay.io/keycloak/keycloak:25.0` | `sbom-keycloak-25.0.syft.json` |
| `valkey/valkey:8` | `sbom-valkey-8.syft.json` |
| `falkordb/falkordb:latest` | `sbom-falkordb-latest.syft.json` |
| `openpolicyagent/opa:1.15.1-envoy-static` | `sbom-opa-1.15.1-envoy-static.syft.json` |
| `ghcr.io/spiffe/spire-server:1.11.0` | `sbom-spire-server-1.11.0.syft.json` |
| `ghcr.io/spiffe/spire-agent:1.11.0` | `sbom-spire-agent-1.11.0.syft.json` |
| `ghcr.io/maxcope-alt/kswitch:v1.39.0-pg` | BLOCKED - registry denied unauthenticated pull during EP-227 evidence generation. Public release needs a publishable image reference and matching SBOM. |
