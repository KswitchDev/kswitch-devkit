/**
 * test_audit_sink.ts — Unit tests for AuditEmitter + AuditSender.
 *
 * Tests:
 *   - AuditEmitter: writes JSONL file, handles rotation, never throws on error
 *   - AuditSender: enqueues events, flushes batches, retry/backoff
 *   - Decision path is NOT blocked on central send failure
 *   - Central forwarding failures are non-fatal
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { AuditEmitter, buildAuditEvent } from "../src/audit/emitter.js";
import { AuditSender } from "../src/audit/sender.js";

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kswitch-audit-test-"));

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeEvent(overrides: Record<string, unknown> = {}) {
  return buildAuditEvent({
    eventType: "enforcement.allow",
    agentId: "agent:test@bank.internal",
    mcpServerId: "mcp:server@bank.internal",
    toolName: "read_data",
    allowed: true,
    reason: "allowed",
    decisionId: crypto.randomUUID(),
    decisionPath: ["local_sdk", "enforcement_complete"],
    obligations: [],
    outputPolicy: { mode: "allow_raw" },
    evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    bundleVersion: "bundle:v1",
    contextPackId: "cp:v1",
    riskTier: "medium",
    elapsedMs: 1.5,
    ...overrides,
  });
}

// ── AuditEmitter tests ────────────────────────────────────────────────────────

describe("AuditEmitter", () => {

  it("writes JSONL line to local file", () => {
    const dir = path.join(tmpDir, "emit1");
    const emitter = new AuditEmitter(dir);
    const event = makeEvent();

    emitter.emit(event);

    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8");
    const lines = content.trim().split("\n");
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(parsed.event_type, "enforcement.allow");
    assert.equal(parsed.agent_id, "agent:test@bank.internal");
    assert.equal(parsed.runtime_mode, "LOCAL_RUNTIME_TYPESCRIPT");
  });

  it("appends multiple events as separate JSONL lines", () => {
    const dir = path.join(tmpDir, "emit2");
    const emitter = new AuditEmitter(dir);

    emitter.emit(makeEvent({ event_type: "enforcement.allow" }));
    emitter.emit(makeEvent({ event_type: "enforcement.deny" }));

    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8");
    const lines = content.trim().split("\n");
    assert.equal(lines.length, 2);
  });

  it("never throws when audit dir is unwritable (silently fails)", () => {
    // Use a file where a directory would be — causes write to fail
    const dir = path.join(tmpDir, "emit3");
    fs.mkdirSync(dir, { recursive: true });
    // Create a FILE at the expected JSONL path to cause write failure
    fs.writeFileSync(path.join(dir, "events.jsonl"), "not a dir");
    fs.chmodSync(path.join(dir, "events.jsonl"), 0o000);

    const emitter = new AuditEmitter(dir);
    // Must not throw
    assert.doesNotThrow(() => {
      emitter.emit(makeEvent());
    });

    // Restore permissions for cleanup
    try { fs.chmodSync(path.join(dir, "events.jsonl"), 0o644); } catch { /* ok */ }
  });

  it("does NOT block decision when central sender throws", () => {
    const dir = path.join(tmpDir, "emit4");
    const emitter = new AuditEmitter(dir);

    // Register a sender that always throws
    const badSender = {
      enqueue: (_event: unknown) => {
        throw new Error("sender blew up");
      },
    } as unknown as AuditSender;
    emitter.setSender(badSender);

    // Must not throw — JSONL write should still succeed
    assert.doesNotThrow(() => {
      emitter.emit(makeEvent());
    });

    // JSONL file should still have the event
    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8").trim();
    assert.ok(content.length > 0, "JSONL file should not be empty");
  });

  it("event contains required fields", () => {
    const dir = path.join(tmpDir, "emit5");
    const emitter = new AuditEmitter(dir);
    emitter.emit(makeEvent());

    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8");
    const parsed = JSON.parse(content.trim()) as Record<string, unknown>;

    const required = [
      "event_id", "event_type", "event_version",
      "agent_id", "mcp_server_id", "tool_name", "action",
      "decision_id", "allowed", "outcome", "reason", "decision_path",
      "obligations", "output_policy_mode",
      "bundle_version", "context_pack_id", "risk_tier", "runtime_mode",
      "elapsed_ms", "evaluated_at",
    ];
    for (const field of required) {
      assert.ok(field in parsed, `Missing required field: ${field}`);
    }
  });

  it("emits enforcement.deny event with correct fields", () => {
    const dir = path.join(tmpDir, "emit6");
    const emitter = new AuditEmitter(dir);
    emitter.emit(buildAuditEvent({
      eventType: "enforcement.deny",
      agentId: "agent:bad@bank.internal",
      mcpServerId: "mcp:s@b.i",
      toolName: "transfer",
      allowed: false,
      reason: "agent_revoked",
      decisionId: crypto.randomUUID(),
      decisionPath: ["local_sdk", "revocation_cache_hit"],
      obligations: [],
      outputPolicy: null,
      evaluationMode: "LOCAL_RUNTIME_TYPESCRIPT",
    }));

    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8");
    const parsed = JSON.parse(content.trim()) as Record<string, unknown>;
    assert.equal(parsed.event_type, "enforcement.deny");
    assert.equal(parsed.allowed, false);
    assert.equal(parsed.outcome, "deny");
    assert.equal(parsed.reason, "agent_revoked");
  });
});

// ── AuditSender tests ─────────────────────────────────────────────────────────

describe("AuditSender", () => {

  it("enqueue + flush sends events to central server", async () => {
    let receivedBody: { events: unknown[] } | null = null;
    const mockFetch: typeof globalThis.fetch = async (_url, init) => {
      receivedBody = JSON.parse(init?.body as string) as { events: unknown[] };
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const sender = new AuditSender({
      ingestUrl: "http://localhost:5001/api/v1/sdk/audit/events",
      batchSize: 10,
      flushInterval: 60,  // high — we'll trigger manually
      fetchFn: mockFetch,
    });
    sender.start();

    const event = makeEvent();
    sender.enqueue(event);

    // Stop triggers flush
    await sender.stop();

    assert.ok(receivedBody !== null, "Expected POST to be sent");
    const body = receivedBody as { events: unknown[] };
    assert.ok(Array.isArray(body.events));
    assert.equal(body.events.length, 1);
  });

  it("sends in { events: [...] } batch format (matches Python)", async () => {
    let capturedPayload: { events: unknown[] } | null = null;
    const mockFetch: typeof globalThis.fetch = async (_url, init) => {
      capturedPayload = JSON.parse(init?.body as string) as { events: unknown[] };
      return new Response("{}", { status: 200 });
    };

    const sender = new AuditSender({
      ingestUrl: "http://localhost:5001/api/v1/sdk/audit/events",
      batchSize: 2,
      flushInterval: 60,
      fetchFn: mockFetch,
    });
    sender.start();
    sender.enqueue(makeEvent());
    sender.enqueue(makeEvent());
    // batch_size=2 triggers immediate flush
    await new Promise((r) => setTimeout(r, 50));
    await sender.stop();

    assert.ok(capturedPayload !== null);
    const payload = capturedPayload as { events: unknown[] };
    assert.ok("events" in payload, "Payload must have 'events' key (batch format)");
    assert.ok(Array.isArray(payload.events));
  });

  it("decision path is NOT blocked when central send fails", async () => {
    const dir = path.join(tmpDir, "sender_fail");
    const emitter = new AuditEmitter(dir);

    // Sender that always fails
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error("Network error");
    };
    const failingSender = new AuditSender({
      ingestUrl: "http://localhost:9999/fail",
      maxRetries: 0,
      flushInterval: 60,
      fetchFn: failFetch,
    });
    failingSender.start();
    emitter.setSender(failingSender);

    // Emit — should not throw despite sender failing
    const event = makeEvent();
    let threw = false;
    try {
      emitter.emit(event);
    } catch {
      threw = true;
    }
    assert.equal(threw, false, "emit() must not throw even when sender fails");

    // Local JSONL file should have event despite sender failure
    const content = fs.readFileSync(path.join(dir, "events.jsonl"), "utf-8");
    assert.ok(content.trim().length > 0, "JSONL must be written even when sender fails");

    await failingSender.stop();
  });

  it("drops events when queue is full (graceful degradation)", () => {
    const sender = new AuditSender({
      ingestUrl: "http://localhost:9999/noop",
      batchSize: 1000,
      flushInterval: 3600,
      // No fetchFn — queue never drains
    });
    // Fill the queue beyond QUEUE_MAXSIZE (500)
    for (let i = 0; i < 510; i++) {
      sender.enqueue(makeEvent());
    }
    const diag = sender.diagnostics();
    assert.ok(diag.drop_count > 0, "Expected some events to be dropped");
    assert.ok(diag.queue_depth <= 500, "Queue depth should be capped");
  });

  it("diagnostics returns expected shape", () => {
    const sender = new AuditSender({
      ingestUrl: "http://localhost:9999/noop",
    });
    const diag = sender.diagnostics();
    assert.ok("forwarding_enabled" in diag);
    assert.ok("running" in diag);
    assert.ok("queue_depth" in diag);
    assert.ok("send_count" in diag);
    assert.ok("fail_count" in diag);
    assert.ok("drop_count" in diag);
  });

  it("retries failed sends with exponential backoff (fast test)", async () => {
    let attemptCount = 0;
    const mockFetch: typeof globalThis.fetch = async () => {
      attemptCount++;
      if (attemptCount < 3) {
        return new Response("{}", { status: 500 });
      }
      return new Response("{}", { status: 200 });
    };

    const sender = new AuditSender({
      ingestUrl: "http://localhost:9999/retry",
      maxRetries: 3,
      flushInterval: 3600,
      fetchFn: mockFetch,
    });
    sender.start();
    sender.enqueue(makeEvent());
    await sender.stop();

    assert.ok(attemptCount >= 3, `Expected ≥3 attempts, got ${attemptCount}`);
    const diag = sender.diagnostics();
    assert.equal(diag.drop_count, 0, "Event should succeed after retries");
  });
});
