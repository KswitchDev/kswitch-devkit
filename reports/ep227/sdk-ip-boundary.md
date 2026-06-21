# EP-227 SDK IP Boundary

Status: ENGINEERING REVIEW COMPLETE - company approval tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

`sdk-ip-boundary.csv` records every public SDK source file under:

- `python/kswitch/`
- `typescript/src/`
- `go/kswitch/`

The review separates four public SDK classes:

| Classification | Release posture |
| --- | --- |
| `sdk-client-api-surface` | Candidate Apache-2.0 SDK surface. |
| `sdk-workload-identity-helper` | Candidate Apache-2.0 helper for SPIFFE/WIMSE or related workload-bound assertions. |
| `sdk-audit-client-helper` | Candidate Apache-2.0 helper for client-side audit event construction and submission. |
| `sdk-developer-runtime-helper` | Candidate Apache-2.0 SDK-side developer helper for local evaluation/cache/revocation/execution-token flows. This is not the commercial control-plane compiler, managed gateway, fleet runtime, or hosted enforcement service. |

Engineering judgement for this tranche: keep the SDK-side developer helpers in
the public SDK because they are imported by the language packages and materially
improve the developer loop. Do not ship commercial control-plane source,
managed policy compilation, gateway policy packs, fleet operations, scanner
sync, or hosted enforcement logic in the public devkit.

Final licence approval for the candidate Apache-2.0 boundary is recorded in the
release checklist before publication.
