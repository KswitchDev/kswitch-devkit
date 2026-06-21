# EP-227 Export and Sanctions Review

Status: ENGINEERING INVENTORY COMPLETE - company approval tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

Distribution surfaces inventoried:

- Apache-2.0 candidate SDK source for Python, TypeScript, and Go.
- Source-available Developer Edition devkit configuration.
- Local PKCE helper.
- Workload-identity helper code for SPIFFE/WIMSE assertions.
- Docker image references for KSwitch app, Postgres, Keycloak, Valkey,
  FalkorDB, OPA, and optional SPIRE.

Crypto/authentication surfaces present:

- OAuth 2.1 / PKCE helper code.
- TLS self-signed local certificate generation via `openssl`.
- JWT/SVID/WIMSE helper code.
- SDK execution-token issuer/validator helpers.

Engineering judgement: the repo contains authentication and cryptographic helper
code and therefore needs company export/sanctions review before public release.
No customer data, customer identifiers, or production deployment material is
required for the public Developer Edition path.
