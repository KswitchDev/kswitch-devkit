/**
 * backcompat.test.ts -- SDK one-version-back contract test scaffolding (TypeScript).
 *
 * Closes the EP-050 §W4 acceptance-criterion gap:
 *
 *   "SDK contract tests pass against both current and one-version-back server"
 *
 *   -- docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md §W4
 *      (retrieved 2026-04-22)
 *
 * This file is scaffolding. The original Wave 1 Agent F version targeted
 * v1.32/v1.34, but that became stale after the product advanced to
 * v1.37.1-pg. This refresh retargeted the placeholders to the frozen fixture
 * line: v1.37.1-pg fixture pin and v1.37.0-pg one-version-back. The real payload
 * assertions are filled in by Round 2 once v1.37.0 schema fixtures under
 * `sdks/_schemas/v1.37.0/` are populated from the v1.37.0 OpenAPI spec -- see
 * `sdks/_schemas/v1.37.0/README.md` for the retrieval plan.
 *
 * Version target note
 * -------------------
 * The platform may now be newer than these fixtures. The frozen fixture pin is
 * `1.37.1-pg`, and the previous released tag is `v1.37.0-pg`. The active
 * historical "one-version-back" scaffold is therefore `v1.37.0`.
 *
 * Vendor citations
 * ----------------
 * - Node built-in test runner `it.skip` / `it.todo` semantics:
 *   https://nodejs.org/api/test.html#testskipname-fn
 *   (retrieved 2026-04-22). The Node runner has no first-class `xfail`
 *   marker. The closest bank-grade equivalent is `it.skip` with a reason
 *   string embedded in the test name: the skip is reported explicitly and
 *   will NOT silently pass if the body is later populated incorrectly.
 *   Round 2 removes the `.skip` and adds a real round-trip assertion
 *   against the fixture bytes.
 * - EP-050 §W4 spec:
 *   `docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md`
 *   (retrieved 2026-04-22).
 *
 * Assumption class (CLAUDE.md engineering principle 3)
 * ----------------------------------------------------
 * The v1.37.0 and v1.37.1 release pins are vendor-documented by git tags and
 * their tagged root `VERSION` files. The concrete wire-contract payloads remain
 * inferred / untested until Round 2 commits real schema exports into
 * `sdks/_schemas/v1.37.0/` and `sdks/_schemas/v1.37.1/`.
 *
 * Test-runner wiring note
 * -----------------------
 * This file lives under `sdks/typescript/tests/` and is picked up by the
 * current `package.json` contract test script.
 */

import { describe, it } from "node:test";
import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import assert from "node:assert/strict";

// -----------------------------------------------------------------------------
// Contract versions exercised by this test module.
// v1.37.1 = frozen fixture pin.
// v1.37.0 = one-version-back (previous release tag).
// -----------------------------------------------------------------------------
export const SCHEMA_VERSIONS = ["v1.37.0", "v1.37.1"] as const;

const XFAIL_REASON =
  "v1.37.0/v1.37.1 schema pins pending -- spec acceptance criterion EP-050 §W4. " +
  "Scaffolding leaves bodies unpopulated until Round 2 exports the OpenAPI " +
  "artefacts into sdks/_schemas/v1.37.0/ and sdks/_schemas/v1.37.1/.";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// sdks/typescript/tests/ -> sdks/_schemas/
const SCHEMAS_ROOT = path.resolve(__dirname, "..", "..", "_schemas");

describe("SDK one-version-back contract scaffolding", () => {
  // Collection-time guard. NOT skipped. Real assertion: the schema fixture
  // directories (and their READMEs) must exist. If a future refactor deletes
  // them, this test fails loudly rather than silently passing the skipped
  // contract tests below.
  it("schema fixture directories exist (frozen v1.37.0 + v1.37.1 pins)", () => {
    for (const version of SCHEMA_VERSIONS) {
      const versionDir = path.join(SCHEMAS_ROOT, version);
      assert.ok(
        fs.existsSync(versionDir) && fs.statSync(versionDir).isDirectory(),
        `Expected schema fixture directory at ${versionDir} ` +
          `(see sdks/_schemas/${version}/README.md for the pin reference).`,
      );
      const readme = path.join(versionDir, "README.md");
      assert.ok(
        fs.existsSync(readme) && fs.statSync(readme).isFile(),
        `Expected pin-reference README at ${readme}. ` +
          `Documents retrieval date, version, and assumption class per ` +
          `CLAUDE.md engineering principles §3.`,
      );
    }
  });

  // ---------------------------------------------------------------------------
  // Contract placeholders. All `it.skip` with the xfail reason embedded in
  // the name so it is visible in test reports. Round 2 replaces each body
  // with a real round-trip test against the v1.37.0 / v1.37.1 fixtures and
  // removes the `.skip`.
  // ---------------------------------------------------------------------------

  it.skip(
    `test_register_agent_request_shape_v1_37_0_accepted [XFAIL: ${XFAIL_REASON}]`,
    () => {
      // TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
      // Contract: POST /api/v1/agents request envelope produced by the
      // current SDK must remain accepted by a v1.37.0 server. The v1.37.1 SDK
      // MUST NOT add new REQUIRED fields. Additive optional fields are
      // allowed; removing or renaming required fields is breaking.
      throw new Error("v1.37.0 register_agent request fixture pending");
    },
  );

  it.skip(
    `test_evaluate_enforcement_v1_37_0_response_shape [XFAIL: ${XFAIL_REASON}]`,
    () => {
      // TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
      // Contract: POST /api/v1/enforcement/evaluate v1.37.0 response envelope
      // must still deserialise cleanly through the v1.37.1 SDK. Additive
      // fields in v1.37.1 must remain optional for older server payloads.
      throw new Error("v1.37.0 evaluate_enforcement response fixture pending");
    },
  );

  it.skip(
    `test_wimse_chain_v1_37_0_envelope_accepted [XFAIL: ${XFAIL_REASON}]`,
    () => {
      // TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
      // Contract: WIMSE delegation chain envelope produced at v1.37.0 must
      // verify under the current SDK's chain validator
      // (sdks/typescript/src/wimse.ts). Per-hop ES256 signing, chain depth
      // limit, TTL, and the WIMSE-Assertion header encoding (space-separated
      // JWTs, 8KB cap) are all frozen at D5.
      throw new Error("v1.37.0 WIMSE chain envelope fixture pending");
    },
  );

  it.skip(
    `test_kill_switch_ack_v1_37_0_shape_unchanged [XFAIL: ${XFAIL_REASON}]`,
    () => {
      // TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
      // Contract: kill-switch ack payload MUST be byte-for-byte compatible
      // between v1.37.0 and v1.37.1. Audit-critical surface under
      // .claude/rules/compliance.md.
      throw new Error("v1.37.0 kill_switch_ack fixture pending");
    },
  );

  it.skip(
    `test_deny_reason_v1_37_0_forward_compat_unknown [XFAIL: ${XFAIL_REASON}]`,
    () => {
      // TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
      // Forward-compat: deny reason parsing must keep the UNKNOWN fallback:
      //  * response without deny_reason -> SDK parser returns DenyReason.UNKNOWN
      //  * response with an unknown deny_reason value -> DenyReason.UNKNOWN
      // Invariant lives in sdks/typescript/src/denyReason.ts.
      throw new Error("v1.37.0 deny_reason forward-compat fixture pending");
    },
  );
});
