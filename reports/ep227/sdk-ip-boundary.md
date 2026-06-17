# EP-227 SDK IP Boundary

Status: PENDING - release blocked.

The current SDK tree contains client-core files and local/offline runtime
surfaces that must be classified before publication. Known high-risk paths:

- `python/kswitch/local_pdp/`
- `python/kswitch/bundle/`
- `python/kswitch/context/`
- `python/kswitch/revocation/`
- `python/kswitch/tokens/`
- `typescript/src/local_pdp/`
- `typescript/src/bundle/`
- `typescript/src/context/`
- `typescript/src/revocation/`
- `typescript/src/tokens/`
- `go/kswitch/localpdp/`
- `go/kswitch/bundle/`
- `go/kswitch/kscontext/`
- `go/kswitch/revocation/`
- `go/kswitch/tokens/`

Release blocker: every public SDK file must appear exactly once in
`sdk-ip-boundary.csv` with a final classification, licence, reason, reviewer,
and inclusion decision.
