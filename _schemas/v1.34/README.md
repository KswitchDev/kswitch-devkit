# KSwitch wire-contract schemas — v1.34.0-pg (current)

**Purpose.** This directory holds the pinned request/response schema fixtures
for the **current** KSwitch server (v1.34.0-pg). Together with the sibling
`../v1.32/` directory they back the per-SDK "one-version-back" contract tests
that satisfy
`docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md`
§W4 acceptance criterion.

**Pin reference.**
- Current `VERSION` file: `1.34.0-pg`
- Version-bump commit: `ad01198` —
  *"chore(version): bump 1.32.0-pg → 1.34.0-pg — closes EP-064/065/066 targets"*
- Retrieval date of this pin: **2026-04-22** (Wave 1 Agent F).

**Source of truth.** The v1.34 contract is whatever the live code in
`app/routes/` (the 11 blueprints listed in `CLAUDE.md`) currently serialises.
For backcompat testing purposes the interesting delta vs. v1.32 introduced in
v1.34 is:

- EP-050 §W4 — every deny response now carries a semantic `deny_reason` value
  drawn from `app/enforcement/reason_class.py`
  (`POLICY | GOVERNANCE | UNAVAILABLE | VALIDATION | UNKNOWN`). SDKs expose
  this as `DenyReason` with a forward-compatible `UNKNOWN` fallback; v1.32
  callers that have not been upgraded must not break when they encounter a
  new `deny_reason` value they don't know about (forward-compat contract —
  exercised by `test_deny_reason_v1_32_forward_compat_unknown`).

**Assumption class (bank-grade principle 3).** The concrete fixture payloads
to be placed here in Round 2 are **vendor-documented** for v1.34 (the
"vendor" being KSwitch itself, with the live API as the authority), but the
serialisation has not yet been extracted into these fixture files. Until
Round 2 populates them, the per-SDK backcompat tests remain xfail placeholders
that encode the *shape* of the contract without asserting on bytes.

## Planned contents (Round 2)

Same file list as `../v1.32/README.md`, with v1.34 deltas:
- `evaluate_enforcement.response.json` — now includes `deny_reason` field
  with values from the D5-frozen enum + `decision_duration_ms`
- `kill_switch_ack.json` — shape unchanged vs. v1.32 (explicit backcompat
  assertion)

<!-- TODO(BL-backcompat-round-2): populate from current OpenAPI / live /api/v1/openapi.json at HEAD. -->
