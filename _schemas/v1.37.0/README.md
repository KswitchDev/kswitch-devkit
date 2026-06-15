# KSwitch wire-contract schemas - v1.37.0-pg (one-version-back)

**Purpose.** This directory holds the pinned request/response schema fixtures
for KSwitch server version **v1.37.0-pg**, the released server version
immediately preceding the frozen v1.37.1-pg fixture pin. These fixtures back the
per-SDK "one-version-back" contract tests that satisfy
`docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md`
§W4 acceptance criterion ("SDK contract tests pass against both current and
one-version-back server").

**Pin reference.**
- Previous release tag: `v1.37.0-pg`
- Tag commit: `bbd8167`
- The tagged root `VERSION` file reads `1.37.0-pg`.
- Retrieval date of this pin: **2026-06-01**.

**Assumption class.** The release pin is **vendor-documented** by the git tag
and root `VERSION` file. The concrete wire shapes are still **inferred /
untested** until Round 2 exports machine-readable OpenAPI or equivalent
fixtures from the tagged server and commits them here.

## Planned contents (Round 2)

- `register_agent.request.json` - POST `/api/v1/agents` request envelope
- `register_agent.response.json` - response envelope (success + 4xx)
- `evaluate_enforcement.request.json` - POST `/api/v1/enforcement/evaluate`
- `evaluate_enforcement.response.json`
- `wimse_chain.envelope.json` - WIMSE chain header envelope + per-hop claim set
- `kill_switch_ack.json` - kill-switch acknowledgement payload

<!-- TODO(BL-backcompat-round-2): populate from OpenAPI spec at tag v1.37.0-pg. -->
