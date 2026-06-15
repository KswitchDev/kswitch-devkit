# KSwitch wire-contract schemas — v1.32.0-pg (one-version-back)

**Purpose.** This directory holds the pinned request/response schema fixtures
for KSwitch server version **v1.32.0-pg**, which is the most recent *released*
server version preceding the current v1.34.0-pg. These fixtures back the
per-SDK "one-version-back" contract tests that satisfy
`docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md`
§W4 acceptance criterion ("SDK contract tests pass against both current and
one-version-back server").

**Why v1.32 and not v1.33.** The product skipped version `v1.33` entirely —
the version string jumped `1.32.0-pg → 1.34.0-pg` in commit `ad01198`
("chore(version): bump 1.32.0-pg → 1.34.0-pg — closes EP-064/065/066 targets")
following a user decision to consolidate EP-064/065/066 under one release.
`CHANGELOG.md` therefore contains no `v1.33` entry. The "one-version-back"
contract is v1.32, not v1.33.

**Pin reference.**
- `v1.32.0-pg` was the VERSION string set by commit `be890ff`
  ("EP-053: Enterprise UI/UX overhaul — v1.32.0-pg") and `c7fee5f`
  ("chore(version): sync v1.32.0-pg version strings + refresh CLAUDE.md state").
- There is **no** `v1.32.0-pg` git tag in this repository. The pin is inferred
  from the final pre-v1.34 commit touching `VERSION`.
- Retrieval date of this pin: **2026-04-22** (Wave 1 Agent F).

**Assumption class (bank-grade principle 3).** The specific wire shapes that
subsequent rounds will serialise into this directory are currently
**inferred / untested** — no machine-readable OpenAPI artefact was captured at
the v1.32 release boundary. The Round 2 population step must:

1. Check out the repo at the last v1.32.0-pg commit (`be890ff` or later
   v1.32-labelled commit before `ad01198`),
2. Export the OpenAPI schema from `app/` (or derive from the live server at
   that commit),
3. Commit the exported artefact into this directory with the retrieval
   timestamp and source commit SHA in the file header.

Until that happens, the per-SDK backcompat test placeholders (see
`sdks/python/tests/test_backcompat.py`, `sdks/typescript/tests/backcompat.test.ts`,
`sdks/go/backcompat_test.go`) are `xfail(strict=True)` / `t.Skip` / `it.skip`
markers that encode the contract shape but do not assert against a concrete
payload.

## Planned contents (Round 2)

- `register_agent.request.json` — POST `/api/v1/agents` request envelope
- `register_agent.response.json` — response envelope (success + 4xx)
- `evaluate_enforcement.request.json` — POST `/api/v1/enforcement/evaluate`
- `evaluate_enforcement.response.json` — including pre-W4 `deny_reason` shape
- `wimse_chain.envelope.json` — WIMSE chain header envelope + per-hop claim set
- `kill_switch_ack.json` — kill-switch acknowledgement payload

<!-- TODO(BL-backcompat-round-2): populate from OpenAPI spec at the v1.32 tag / last pre-v1.34 commit. -->
