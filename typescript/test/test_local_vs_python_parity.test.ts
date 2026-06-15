/**
 * test_local_vs_python_parity.ts — TypeScript behavior vs Python golden-path parity.
 *
 * Phase 7: Proves TypeScript local runtime aligns materially with the documented
 * Python golden-path behavior. Comparison uses the same normalization rules as
 * sdks/python/tests/parity_helpers.py.
 *
 * Normalization rules (identical to Python):
 *   Compare:
 *     - allowed (bool)
 *     - reason_class (first colon-delimited segment, lowercased)
 *     - obligation_types (sorted list)
 *     - output_control_mode (string)
 *   Exclude:
 *     - timestamps, trace_ids, UUIDs, elapsed timings
 *     - decision_path (impl-specific)
 *     - bundle_version, context_pack_id (dynamic)
 *     - evaluation_mode (intentionally differs: LOCAL_RUNTIME_TYPESCRIPT vs LOCAL_RUNTIME_PYTHON)
 *
 * Oracle: Pinned Python golden-path behavior documented below in test cases.
 * Live co-execution is NOT required. The Python golden-path is treated as a
 * specification that TypeScript must match.
 *
 * Unavoidable differences (documented):
 *   1. evaluation_mode: "LOCAL_RUNTIME_TYPESCRIPT" vs "LOCAL_RUNTIME_PYTHON" — EXCLUDED from comparison
 *   2. Cedar entity format: TypeScript cedar-wasm uses EntityUid objects {type, id};
 *      Python cedarpy uses Cedar string format Agent::"id" — semantically identical
 *   3. No disk I/O difference: both use atomic rename (.tmp → final)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { LocalPDPEvaluator } from "../src/local_pdp/evaluator.js";
import { LocalRevocationCache, _setRevocationCache } from "../src/revocation/cache.js";
import { LocalBundleCache, _setBundleCache } from "../src/bundle/local_cache.js";
import { LocalContextCache, _setContextCache } from "../src/context/local_cache.js";
import type { LocalDecision } from "../src/local_pdp/types.js";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kswitch-parity-test-"));

// ── Parity normalization (mirrors parity_helpers.py) ──────────────────────────

interface ParityRecord {
  allowed: boolean;
  reasonClass: string;
  obligationTypes: string[];
  outputControlMode: string;
  source: string;  // "local_ts" or "python_golden" — diagnostic only, not compared
}

function extractReasonClass(reason: string): string {
  if (!reason) return "unknown";
  const first = reason.split(":")[0].split(" ")[0].trim().toLowerCase();
  return first || "unknown";
}

function extractObligationTypes(obligations: unknown[]): string[] {
  const types: string[] = [];
  for (const ob of obligations) {
    const o = ob as Record<string, string>;
    const t = o.obligation_type || o.type || "";
    if (t) types.push(t.toLowerCase());
  }
  return types.sort();
}

function extractOutputControlMode(outputPolicy: unknown): string {
  if (!outputPolicy) return "allow_raw";
  const p = outputPolicy as Record<string, string>;
  return (p.mode || "allow_raw").toLowerCase();
}

function normalizeLocalDecision(d: LocalDecision): ParityRecord {
  return {
    allowed: d.allowed,
    reasonClass: extractReasonClass(d.reason),
    obligationTypes: extractObligationTypes(d.obligations),
    outputControlMode: extractOutputControlMode(d.outputPolicy),
    source: "local_ts",
  };
}

function assertParity(
  ts: ParityRecord,
  python: ParityRecord,
  scenario: string,
): void {
  const mismatches: string[] = [];

  if (ts.allowed !== python.allowed) {
    mismatches.push(`  MISMATCH [allowed]: ts=${ts.allowed}  python=${python.allowed}`);
  }
  if (ts.reasonClass !== python.reasonClass) {
    mismatches.push(`  MISMATCH [reason_class]: ts=${ts.reasonClass}  python=${python.reasonClass}`);
  }
  if (JSON.stringify(ts.obligationTypes) !== JSON.stringify(python.obligationTypes)) {
    mismatches.push(
      `  MISMATCH [obligation_types]: ts=${JSON.stringify(ts.obligationTypes)}  ` +
      `python=${JSON.stringify(python.obligationTypes)}`,
    );
  }
  if (ts.outputControlMode !== python.outputControlMode) {
    mismatches.push(
      `  MISMATCH [output_control_mode]: ts=${ts.outputControlMode}  python=${python.outputControlMode}`,
    );
  }

  if (mismatches.length > 0) {
    throw new Error(
      `PARITY FAILURE [${scenario}]: ${mismatches.length} field(s) drifted.\n` +
      mismatches.join("\n"),
    );
  }
}

// ── Test fixture factory ──────────────────────────────────────────────────────

function makeEvaluator(suffix: string, opts: {
  agentStatus?: string;
  isRevoked?: boolean;
  blanketKill?: boolean;
  bundleEnforceCount?: number;
  dataClassifications?: string[];
  /** Set to false to skip bundle creation even for active agents */
  storeBundle?: boolean;
} = {}): { evaluator: LocalPDPEvaluator; revCache: LocalRevocationCache } {
  const dir = path.join(tmpDir, suffix);
  const revCache = new LocalRevocationCache(path.join(dir, "rev"));
  const bundleCache = new LocalBundleCache(path.join(dir, "bundle"));
  const contextCache = new LocalContextCache(path.join(dir, "ctx"));

  _setRevocationCache(revCache);
  _setBundleCache(bundleCache);
  _setContextCache(contextCache);

  if (opts.blanketKill) {
    revCache.setBlanketKill(true);
  } else if (opts.isRevoked) {
    revCache.revoke("agent:test@bank.internal");
  }

  if (opts.agentStatus !== undefined) {
    contextCache.store("agent:test@bank.internal", {
      status: opts.agentStatus,
      risk_tier: "medium",
      data_classifications: opts.dataClassifications ?? [],
      is_revoked: false,
      compiled_at: "2026-01-01T00:00:00Z",
      pack_version: 1,
    });
  }

  // Store bundle unless explicitly disabled (storeBundle=false)
  if (opts.agentStatus === "active" && opts.storeBundle !== false) {
    bundleCache.store({
      version: 1, bundle_id: "bundle:v1", compiled_at: "2026-01-01T00:00:00Z",
      cedar_text_enforce: "",
      cedar_text_shadow: "",
      enforce_count: opts.bundleEnforceCount ?? 0,
      shadow_count: 0, tool_count: 0, tool_index: {}, signature: "",
    });
  }

  const evaluator = new LocalPDPEvaluator({ getRevocationCache: () => revCache });
  return { evaluator, revCache };
}

// ── Python golden-path reference records ──────────────────────────────────────
// These are the pinned Python golden-path outcomes.
// Source: Python LocalPDPEvaluator + test suite (sdks/python/tests/).

const PYTHON_GOLDEN = {
  localAllow: {
    allowed: true,
    reasonClass: "allowed",
    obligationTypes: [] as string[],
    outputControlMode: "allow_raw",
    source: "python_golden",
  } satisfies ParityRecord,

  localDenyRevoked: {
    allowed: false,
    reasonClass: "agent_revoked",
    obligationTypes: [] as string[],
    outputControlMode: "allow_raw",
    source: "python_golden",
  } satisfies ParityRecord,

  localDenySuspended: {
    allowed: false,
    reasonClass: "agent_suspended",
    obligationTypes: [] as string[],
    outputControlMode: "allow_raw",
    source: "python_golden",
  } satisfies ParityRecord,

  conditionalBundleUnavailable: {
    allowed: false,
    reasonClass: "bundle_unavailable",
    obligationTypes: [] as string[],
    outputControlMode: "allow_raw",
    source: "python_golden",
  } satisfies ParityRecord,

  outputControlMaskFields: {
    allowed: true,
    reasonClass: "allowed",
    obligationTypes: [] as string[],
    outputControlMode: "mask_fields",
    source: "python_golden",
  } satisfies ParityRecord,
};

// ── Parity test scenarios ─────────────────────────────────────────────────────

describe("TypeScript vs Python golden-path parity", () => {

  // Scenario 1: Local ALLOW
  it("Scenario 1: local allow — matches Python golden path", async () => {
    const { evaluator } = makeEvaluator("parity1", {
      agentStatus: "active",
      bundleEnforceCount: 0,
    });

    const d = await evaluator.evaluate(
      "agent:test@bank.internal", "mcp:server@bank.internal", "read_data",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.localAllow, "local_allow");
  });

  // Scenario 2: Local DENY (revoked agent)
  it("Scenario 2: local deny (revoked) — matches Python golden path", async () => {
    const { evaluator } = makeEvaluator("parity2", { isRevoked: true });

    const d = await evaluator.evaluate(
      "agent:test@bank.internal", "mcp:server@bank.internal",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.localDenyRevoked, "local_deny_revoked");
  });

  // Scenario 3: Revoked deny (blanket kill)
  it("Scenario 3: blanket kill deny — aligns with Python revocation behavior", async () => {
    const { evaluator } = makeEvaluator("parity3", { blanketKill: true });

    const d = await evaluator.evaluate(
      "agent:innocent@bank.internal", "mcp:server@bank.internal",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.localDenyRevoked, "blanket_kill_deny");
  });

  // Scenario 4: Conditional shape
  it("Scenario 4: conditional (bundle_unavailable) — escalation structure matches Python", async () => {
    const { evaluator } = makeEvaluator("parity4", {
      agentStatus: "active",
      storeBundle: false,  // Explicitly no bundle → conditional
    });

    const d = await evaluator.evaluate(
      "agent:test@bank.internal", "mcp:server@bank.internal",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.conditionalBundleUnavailable, "conditional_shape");
  });

  // Scenario 5: Output control / obligation semantics (PII classification → mask_fields)
  it("Scenario 5: output control mask_fields for PII — matches Python", async () => {
    const { evaluator } = makeEvaluator("parity5", {
      agentStatus: "active",
      bundleEnforceCount: 0,
      dataClassifications: ["PII"],
    });

    const d = await evaluator.evaluate(
      "agent:test@bank.internal", "mcp:server@bank.internal", "read_customer",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.outputControlMaskFields, "output_control_mask_fields");
  });

  // Scenario 6: Suspended agent deny
  it("Scenario 6: suspended agent deny — matches Python", async () => {
    const { evaluator } = makeEvaluator("parity6", { agentStatus: "suspended" });

    const d = await evaluator.evaluate(
      "agent:test@bank.internal", "mcp:server@bank.internal",
    );
    const tsRecord = normalizeLocalDecision(d);
    assertParity(tsRecord, PYTHON_GOLDEN.localDenySuspended, "agent_suspended_deny");
  });

  // ── Meta: normalization helper tests ───────────────────────────────────────

  it("normalize: reason_class extraction matches Python (first colon segment)", () => {
    assert.equal(extractReasonClass("agent_revoked"), "agent_revoked");
    assert.equal(extractReasonClass("agent_revoked:kill_switch:manual"), "agent_revoked");
    assert.equal(extractReasonClass("policy_denied:cedar"), "policy_denied");
    assert.equal(extractReasonClass(""), "unknown");
    assert.equal(extractReasonClass("ALLOWED"), "allowed");
  });

  it("normalize: obligation_types are sorted (matches Python sorted() behavior)", () => {
    const obs = [
      { obligation_type: "shadow_denied" },
      { obligation_type: "audit_flag" },
    ];
    const types = extractObligationTypes(obs);
    assert.deepEqual(types, ["audit_flag", "shadow_denied"]);
  });

  it("normalize: output_control_mode defaults to allow_raw for null policy (matches Python)", () => {
    assert.equal(extractOutputControlMode(null), "allow_raw");
    assert.equal(extractOutputControlMode(undefined), "allow_raw");
    assert.equal(extractOutputControlMode({ mode: "mask_fields" }), "mask_fields");
  });

  it("parity record equality ignores source field (same as Python ParityRecord.__eq__)", () => {
    const ts: ParityRecord = {
      allowed: true, reasonClass: "allowed",
      obligationTypes: [], outputControlMode: "allow_raw",
      source: "local_ts",
    };
    const python: ParityRecord = {
      allowed: true, reasonClass: "allowed",
      obligationTypes: [], outputControlMode: "allow_raw",
      source: "python_golden",
    };
    // assert_parity should pass — source is diagnostic only
    assert.doesNotThrow(() => assertParity(ts, python, "equality_ignores_source"));
  });

  it("parity failure shows field-level diff (regression guard)", () => {
    const ts: ParityRecord = {
      allowed: false,  // WRONG: python says true
      reasonClass: "allowed",
      obligationTypes: [],
      outputControlMode: "allow_raw",
      source: "local_ts",
    };
    assert.throws(
      () => assertParity(ts, PYTHON_GOLDEN.localAllow, "intentional_mismatch"),
      (err: Error) => {
        assert.ok(err.message.includes("PARITY FAILURE"));
        assert.ok(err.message.includes("MISMATCH [allowed]"));
        return true;
      },
    );
  });

  // ── Documented unavoidable differences ────────────────────────────────────

  it("DOCUMENTED DIFFERENCE: evaluation_mode is LOCAL_RUNTIME_TYPESCRIPT not LOCAL_RUNTIME_PYTHON", async () => {
    const { evaluator } = makeEvaluator("parity_doc", { agentStatus: "active", bundleEnforceCount: 0 });
    const d = await evaluator.evaluate("agent:test@bank.internal", "mcp:s@b.i");
    // This is intentionally different — documented per execution pack
    assert.equal(d.evaluationMode, "LOCAL_RUNTIME_TYPESCRIPT");
    // Python would be "LOCAL_RUNTIME_PYTHON"
    // This field is EXCLUDED from parity comparison (confirmed in normalization rules)
  });
});
