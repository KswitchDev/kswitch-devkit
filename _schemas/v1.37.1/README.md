# KSwitch wire-contract schemas - v1.37.1-pg (frozen fixture pin)

**Purpose.** This directory holds the pinned request/response schema fixtures
for KSwitch server version **v1.37.1-pg**. Together with the sibling
`../v1.37.0/` directory, these fixtures back the per-SDK
"one-version-back" contract tests that satisfy
`docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md`
§W4 acceptance criterion.

**Pin reference.**
- Tagged root `VERSION` file: `1.37.1-pg`
- Release tag: `v1.37.1-pg`
- Tag commit: `ccaadfd`
- Retrieval date of this pin: **2026-06-01**.

**Source of truth.** The v1.37.1 contract is whatever the tagged control-plane
code serialises through `app/routes/` and the SDK-facing route surfaces.

**Assumption class.** The release pin is **vendor-documented** by the git tag
and root `VERSION` file. The concrete fixture payloads to be placed here in
Round 2 are still **inferred / untested** until exported into this directory.

## Planned contents (Round 2)

Same file list as `../v1.37.0/README.md`, with any v1.37.1 deltas documented
in the file headers when the fixtures are exported. This directory is a frozen
fixture pin, not the current platform release.

<!-- TODO(BL-backcompat-round-2): populate from current OpenAPI / live /api/v1/openapi.json at tag v1.37.1-pg. -->
