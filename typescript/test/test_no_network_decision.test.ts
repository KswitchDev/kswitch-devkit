/**
 * test_no_network_decision.ts — Prove TypeScript local ALLOW/DENY make no server calls.
 *
 * Tests that:
 *   1. Local ALLOW outcome never calls the Flask enforcement endpoint
 *   2. Local DENY outcome never calls the Flask enforcement endpoint
 *   3. Conditional outcome DOES call the server (correct escalation)
 *
 * The network guard makes the HTTP path fail loudly if called during local
 * allow/deny — any call to the mock enforcement endpoint during a local path
 * will cause the test to fail.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { KSwitchInterceptor } from "../src/interceptor.js";
import { LocalPDPEvaluator } from "../src/local_pdp/evaluator.js";
import { LocalRevocationCache, _setRevocationCache } from "../src/revocation/cache.js";
import { LocalBundleCache, _setBundleCache } from "../src/bundle/local_cache.js";
import { LocalContextCache, _setContextCache } from "../src/context/local_cache.js";
import type { LocalDecision } from "../src/local_pdp/types.js";
import type { MCPCallEnforcementResponse } from "../src/types.js";

// ── Network guard ─────────────────────────────────────────────────────────────

/** Mock KSwitchClient that FAILS loudly if enforcement is called. */
function makeGuardedClient(
  serverResponse?: MCPCallEnforcementResponse,
): { client: unknown; callCount: number } {
  const state = { callCount: 0 };

  const client = {
    enforcement: {
      async enforceMCPCall(_req: unknown): Promise<MCPCallEnforcementResponse> {
        state.callCount += 1;
        if (!serverResponse) {
          // Guard: if this is called unexpectedly, throw so the test fails
          throw new Error(
            "SERVER ENFORCEMENT CALLED ON LOCAL PATH — local runtime network guard triggered",
          );
        }
        return serverResponse;
      },
      async reportObligations(_id: string, _types: string[]): Promise<void> {},
    },
  };

  return { client, callCount: state.callCount };
}

// ── Mock evaluator factory ────────────────────────────────────────────────────

function makeEvaluatorReturning(outcome: LocalDecision) {
  const evaluator = {
    async evaluate(
      _agentId: string,
      _mcpServerId: string,
      _toolName?: string,
      _context?: Record<string, unknown>,
    ): Promise<LocalDecision> {
      return outcome;
    },
  } as unknown as LocalPDPEvaluator;
  return evaluator;
}

function makeLocalAllow(agentId = "agent:test@bank.internal"): LocalDecision {
  return {
    outcome: "allow",
    reason: "allowed",
    allowed: true,
    decisionPath: ["local_sdk", "agent_active", "bundle_v1", "no_policies", "enforcement_complete"],
    obligations: [],
    outputPolicy: { mode: "allow_raw", masking_classifications: [] },
    enforcementId: crypto.randomUUID(),
    evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    bundleVersion: "bundle:v1",
    contextPackId: "cp:v1",
    riskTier: "medium",
    agentId,
    mcpServerId: "mcp:server@bank.internal",
    toolName: "read_data",
    evaluatedAt: Date.now(),
  };
}

function makeLocalDeny(reason = "agent_revoked"): LocalDecision {
  return {
    outcome: "deny",
    reason,
    allowed: false,
    decisionPath: ["local_sdk", "revocation_cache_hit"],
    obligations: [],
    outputPolicy: null,
    enforcementId: crypto.randomUUID(),
    evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    bundleVersion: "",
    contextPackId: "",
    riskTier: "medium",
    agentId: "agent:test@bank.internal",
    mcpServerId: "mcp:server@bank.internal",
    toolName: "transfer",
    evaluatedAt: Date.now(),
  };
}

function makeConditional(): LocalDecision {
  return {
    outcome: "conditional",
    reason: "bundle_unavailable",
    allowed: false,
    decisionPath: ["local_sdk", "bundle_miss_escalate"],
    obligations: [],
    outputPolicy: null,
    enforcementId: crypto.randomUUID(),
    evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    bundleVersion: "",
    contextPackId: "",
    riskTier: "medium",
    agentId: "agent:test@bank.internal",
    mcpServerId: "mcp:server@bank.internal",
    toolName: "transfer",
    evaluatedAt: Date.now(),
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("No-network local decisions", () => {

  it("local ALLOW: tool runs, server enforcement is NOT called", async () => {
    const { client } = makeGuardedClient(); // throws if called
    const evaluator = makeEvaluatorReturning(makeLocalAllow());
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    let toolCalled = false;
    const result = await interceptor.checkAndInvoke({
      agentId: "agent:test@bank.internal",
      mcpServerId: "mcp:server@bank.internal",
      toolName: "read_data",
      toolFn: (_args) => {
        toolCalled = true;
        return { data: "hello" };
      },
    });

    assert.ok(toolCalled, "Tool function should have been called");
    assert.deepEqual(result, { data: "hello" });
    // If we get here without an error from the guard, server was not called ✓
  });

  it("local DENY: throws KSwitchEnforcementError, server is NOT called", async () => {
    const { client } = makeGuardedClient(); // throws if called
    const evaluator = makeEvaluatorReturning(makeLocalDeny("agent_revoked"));
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    let toolCalled = false;
    await assert.rejects(
      async () => {
        await interceptor.checkAndInvoke({
          agentId: "agent:test@bank.internal",
          mcpServerId: "mcp:server@bank.internal",
          toolName: "transfer",
          toolFn: (_args) => { toolCalled = true; return "ok"; },
        });
      },
      (err: Error) => {
        assert.equal(err.name, "KSwitchEnforcementError");
        assert.ok(err.message.includes("agent_revoked"));
        return true;
      },
    );

    assert.equal(toolCalled, false, "Tool must NOT be called on DENY");
    // Guard not triggered → server was not called ✓
  });

  it("local DENY: policy_denied throws, server is NOT called", async () => {
    const { client } = makeGuardedClient(); // throws if called
    const evaluator = makeEvaluatorReturning(makeLocalDeny("policy_denied"));
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    await assert.rejects(
      async () => {
        await interceptor.checkAndInvoke({
          agentId: "agent:test@bank.internal",
          mcpServerId: "mcp:server@bank.internal",
          toolName: "write_data",
          toolFn: () => "ok",
        });
      },
      (err: Error) => {
        assert.equal(err.name, "KSwitchEnforcementError");
        return true;
      },
    );
  });

  it("conditional: escalates to server, server IS called", async () => {
    const serverResp: MCPCallEnforcementResponse = {
      allowed: true,
      reason: "allowed_by_server",
      obligations: [],
      output_policy: { mode: "allow_raw" },
    };
    const { client } = makeGuardedClient(serverResp);
    const evaluator = makeEvaluatorReturning(makeConditional());
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    let toolCalled = false;
    await interceptor.checkAndInvoke({
      agentId: "agent:test@bank.internal",
      mcpServerId: "mcp:server@bank.internal",
      toolName: "transfer",
      toolFn: () => { toolCalled = true; return { status: "ok" }; },
    });

    assert.ok(toolCalled, "Tool should run after server allow");
  });

  it("conditional: server DENY escalation throws KSwitchEnforcementError", async () => {
    const serverResp: MCPCallEnforcementResponse = {
      allowed: false,
      reason: "server_policy_denied",
      obligations: [],
    };
    const { client } = makeGuardedClient(serverResp);
    const evaluator = makeEvaluatorReturning(makeConditional());
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    await assert.rejects(
      async () => {
        await interceptor.checkAndInvoke({
          agentId: "agent:test@bank.internal",
          mcpServerId: "mcp:server@bank.internal",
          toolName: "transfer",
          toolFn: () => "ok",
        });
      },
      (err: Error) => {
        assert.equal(err.name, "KSwitchEnforcementError");
        assert.ok(err.message.includes("server_policy_denied"));
        return true;
      },
    );
  });

  it("no localPDP: always calls server (backward compat)", async () => {
    const serverResp: MCPCallEnforcementResponse = {
      allowed: true,
      reason: "allowed",
      obligations: [],
    };
    const { client } = makeGuardedClient(serverResp);
    // No localPDP passed → should call server
    const interceptor = new KSwitchInterceptor(client as never);

    let toolCalled = false;
    await interceptor.checkAndInvoke({
      agentId: "agent:test@bank.internal",
      mcpServerId: "mcp:server@bank.internal",
      toolName: "read",
      toolFn: () => { toolCalled = true; return "data"; },
    });

    assert.ok(toolCalled, "Tool should have been called via server path");
  });

  it("output_policy=deny_export on local ALLOW throws OutputDeniedError", async () => {
    const { client } = makeGuardedClient(); // throws if called
    const denyExportDecision: LocalDecision = {
      ...makeLocalAllow(),
      outputPolicy: { mode: "deny_export", masking_classifications: ["PII"] },
    };
    const evaluator = makeEvaluatorReturning(denyExportDecision);
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    await assert.rejects(
      async () => {
        await interceptor.checkAndInvoke({
          agentId: "agent:test@bank.internal",
          mcpServerId: "mcp:server@bank.internal",
          toolName: "read_data",
          toolFn: () => ({ ssn: "123-45-6789" }),
        });
      },
      (err: Error) => {
        assert.equal(err.name, "OutputDeniedError");
        return true;
      },
    );
  });

  it("output_policy=mask_fields masks sensitive keys in output", async () => {
    const { client } = makeGuardedClient(); // throws if called
    const maskDecision: LocalDecision = {
      ...makeLocalAllow(),
      outputPolicy: { mode: "mask_fields", masking_classifications: ["PII"] },
    };
    const evaluator = makeEvaluatorReturning(maskDecision);
    const interceptor = new KSwitchInterceptor(client as never, { localPDP: evaluator });

    const result = await interceptor.checkAndInvoke({
      agentId: "agent:test@bank.internal",
      mcpServerId: "mcp:server@bank.internal",
      toolName: "read_data",
      toolFn: () => ({ name: "Alice", ssn: "123-45-6789", amount: 100 }),
    }) as Record<string, unknown>;

    assert.ok(
      (result.ssn as string).startsWith("[REDACTED"),
      "SSN should be redacted",
    );
    assert.equal(result.amount, 100, "Non-sensitive field should be unchanged");
  });
});
