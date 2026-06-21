# EP-227 Privacy Data Flow Review

Status: ENGINEERING REVIEW COMPLETE - company approval tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

Default posture:

- The public SDK packages do not transmit telemetry to KSwitch-hosted services
  by default.
- The devkit runs locally on the developer workstation or local Docker host.
- PKCE tokens are returned to stdout by default and are stored only when the
  developer passes `--store`; storage uses OS keychain where available and a
  `0600` file fallback.
- Devkit admin bootstrap writes `devkit/state/initial-admin.txt` with mode
  `0600` for local targets only.
- Local Docker logs may contain operational events and HTTP status codes. They
  must not be marketed as sanitized for production or customer data.

No hosted analytics, crash reporting, package-install callback, or default
KSwitch-hosted telemetry path is present in the public devkit materials reviewed
in this tranche.

Residual release note: if hosted documentation, package registries, support
forms, or crash-reporting endpoints are added later, this review must be
reopened before publication.
