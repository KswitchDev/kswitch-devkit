# EP-227 Public Claims Matrix

Status: ENGINEERING REVIEW COMPLETE - company approval tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

Candidate public claims:

| Claim | Evidence | Allowed use |
| --- | --- | --- |
| SDK packages are Apache-2.0 candidates. | `LICENSE.md`, package metadata, `sdk-ip-boundary.csv`. | Only after release checklist approval. |
| Developer Edition has no scheduled expiry for permitted use of the applicable release version. | `LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md`. | Use exact wording; do not say free forever or free for life. |
| Official unmodified Developer Edition artefacts enforce 10 agents, 10 MCP servers, 100 tools, and 100 skills. | `devkit/developer-edition/licence_loader.py`, `devkit/.env.example`, docs. | Do not claim modified builds are impossible to bypass. |
| Developer Edition is source-available and not open source. | `LICENSE.md`, `COMMERCIAL-USE.md`. | Must be paired with non-commercial boundary. |
| Workload identity is preferred for production service authentication. | `docs/auth-model.md`, SDK WIMSE/SPIFFE helpers. | Client credentials remain compatibility fallback only. |

Blocked claim families unless separate approved evidence exists:

- secure / security-first
- bank-grade
- compliant
- production ready
- enterprise ready
- regulated-ready
- zero trust
- SLA / uptime / support entitlement

Engineering scan result: current public docs use bounded Developer Edition
wording and compatibility framing for client credentials. The devkit docs no
longer promise public production-gateway, scanner, runtime-worker, Vault, or
observability internals.
