/**
 * test_revocation_sync.ts — Unit tests for LocalRevocationCache + RevocationSyncWorker.
 *
 * Tests:
 *   - Revocation cache: revoke, clearAgent, setBlanketKill, isRevoked
 *   - applyServerState: full-state sync
 *   - Sync worker: syncOnce, version-check-then-fetch, blanket kill fast path
 *   - No live server needed — HTTP is mocked via injectable fetchFn
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { LocalRevocationCache } from "../src/revocation/cache.js";
import { RevocationSyncWorker } from "../src/revocation/sync.js";

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kswitch-rev-test-"));

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeCache(suffix = ""): LocalRevocationCache {
  return new LocalRevocationCache(path.join(tmpDir, `rev${suffix}`));
}

/** Build a mock fetchFn for revision sync. */
function makeMockFetch(
  versionResp: object,
  stateResp?: object,
): typeof globalThis.fetch {
  let callCount = 0;
  return async (url: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    callCount++;
    const urlStr = typeof url === "string" ? url : url.toString();
    if (urlStr.includes("/version")) {
      return new Response(JSON.stringify(versionResp), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (urlStr.includes("/state") && stateResp) {
      return new Response(JSON.stringify(stateResp), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw new Error(`Unexpected URL: ${urlStr}`);
  };
}

// ── Cache unit tests ──────────────────────────────────────────────────────────

describe("LocalRevocationCache", () => {

  it("isRevoked returns false for unknown agent", () => {
    const cache = makeCache("a");
    assert.equal(cache.isRevoked("agent:unknown@bank.internal"), false);
  });

  it("revoke + isRevoked", () => {
    const cache = makeCache("b");
    cache.revoke("agent:bad@bank.internal");
    assert.equal(cache.isRevoked("agent:bad@bank.internal"), true);
  });

  it("clearAgent removes revocation", () => {
    const cache = makeCache("c");
    cache.revoke("agent:bad@bank.internal");
    cache.clearAgent("agent:bad@bank.internal");
    assert.equal(cache.isRevoked("agent:bad@bank.internal"), false);
  });

  it("setBlanketKill=true makes every agent appear revoked", () => {
    const cache = makeCache("d");
    cache.setBlanketKill(true);
    assert.equal(cache.isRevoked("agent:innocent@bank.internal"), true);
    assert.equal(cache.isRevoked("agent:another@bank.internal"), true);
  });

  it("setBlanketKill=false clears blanket state", () => {
    const cache = makeCache("e");
    cache.setBlanketKill(true);
    cache.setBlanketKill(false);
    assert.equal(cache.isRevoked("agent:innocent@bank.internal"), false);
  });

  it("applyServerState replaces entire revocation set atomically", () => {
    const cache = makeCache("f");
    cache.revoke("agent:old@bank.internal");
    assert.equal(cache.isRevoked("agent:old@bank.internal"), true);

    cache.applyServerState({
      version: 5,
      blanket_kill_active: false,
      revoked_agents: ["agent:new@bank.internal"],
    });

    // old is gone, new is present
    assert.equal(cache.isRevoked("agent:old@bank.internal"), false);
    assert.equal(cache.isRevoked("agent:new@bank.internal"), true);
    assert.equal(cache.getServerVersion(), 5);
  });

  it("applyServerState with blanket_kill_active=true", () => {
    const cache = makeCache("g");
    cache.applyServerState({
      version: 7,
      blanket_kill_active: true,
      revoked_agents: [],
    });
    assert.equal(cache.isRevoked("agent:any@bank.internal"), true);
    const diag = cache.getDiagnostics();
    assert.equal(diag.blanket_kill_active, true);
  });

  it("isSyncStale returns true if never synced (threshold > 0)", () => {
    const cache = makeCache("h");
    assert.equal(cache.isSyncStale(30), true);
  });

  it("isSyncStale returns false if threshold=0", () => {
    const cache = makeCache("i");
    assert.equal(cache.isSyncStale(0), false);
  });

  it("isSyncStale returns false after recent applyServerState", () => {
    const cache = makeCache("j");
    cache.applyServerState({ version: 1, revoked_agents: [] });
    assert.equal(cache.isSyncStale(30), false);
  });

  it("getDiagnostics returns expected shape", () => {
    const cache = makeCache("k");
    cache.revoke("agent:x@bank.internal");
    const diag = cache.getDiagnostics();
    assert.ok("server_version" in diag);
    assert.ok("last_synced_at" in diag);
    assert.ok("blanket_kill_active" in diag);
    assert.ok("revoked_count" in diag);
    assert.equal(diag.revoked_count, 1);
  });

  it("recordSyncFailure increments sync_failure_count", () => {
    const cache = makeCache("l");
    cache.recordSyncFailure("timeout");
    cache.recordSyncFailure("connect_refused");
    const diag = cache.getDiagnostics();
    assert.equal(diag.sync_failure_count, 2);
    assert.equal(diag.last_sync_failure, "connect_refused");
  });

  it("persists to disk and loads on new instance", () => {
    const dir = path.join(tmpDir, "persist_test");
    const cache1 = new LocalRevocationCache(dir);
    cache1.revoke("agent:persisted@bank.internal");

    const cache2 = new LocalRevocationCache(dir);
    assert.equal(cache2.isRevoked("agent:persisted@bank.internal"), true);
  });
});

// ── Sync worker tests ─────────────────────────────────────────────────────────

describe("RevocationSyncWorker", () => {

  it("syncOnce: returns false when version unchanged", async () => {
    const cache = makeCache("sw1");
    cache.applyServerState({ version: 10, revoked_agents: [] });

    const fetchFn = makeMockFetch({ version: 10, blanket_kill_active: false });
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn,
    });

    const fetched = await worker.syncOnce();
    // Version unchanged → no state fetch
    assert.equal(fetched, false);
  });

  it("syncOnce: fetches full state when version changed", async () => {
    const cache = makeCache("sw2");
    cache.applyServerState({ version: 1, revoked_agents: [] });

    const fetchFn = makeMockFetch(
      { version: 2, blanket_kill_active: false },
      { version: 2, blanket_kill_active: false, revoked_agents: ["agent:a@bank.internal"] },
    );
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn,
    });

    const fetched = await worker.syncOnce();
    assert.equal(fetched, true);
    assert.equal(cache.isRevoked("agent:a@bank.internal"), true);
    assert.equal(cache.getServerVersion(), 2);
  });

  it("syncOnce: blanket kill fast path", async () => {
    const cache = makeCache("sw3");
    // Initial state: no blanket kill
    cache.applyServerState({ version: 1, blanket_kill_active: false, revoked_agents: [] });

    const fetchFn = makeMockFetch({ version: 1, blanket_kill_active: true });
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn,
    });

    const fetched = await worker.syncOnce();
    assert.equal(fetched, true);
    assert.equal(cache.isRevoked("agent:any@bank.internal"), true);
    const diag = cache.getDiagnostics();
    assert.equal(diag.blanket_kill_active, true);
  });

  it("syncOnce: records failure on HTTP error", async () => {
    const cache = makeCache("sw4");
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn: failFetch,
    });

    const fetched = await worker.syncOnce();
    assert.equal(fetched, false);
    const diag = cache.getDiagnostics();
    assert.ok(diag.sync_failure_count > 0);
  });

  it("diagnostics returns expected shape", async () => {
    const cache = makeCache("sw5");
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn: makeMockFetch({ version: 1 }),
    });
    const diag = worker.diagnostics();
    assert.ok("sync_worker" in diag);
    assert.ok("cache" in diag);
    assert.equal(diag.sync_worker.running, false);
    assert.equal(diag.sync_worker.stale_mode, "warn");
  });

  it("deny after remote revoke: after syncOnce, agent is denied locally", async () => {
    const cache = makeCache("sw6");
    // No initial state
    const fetchFn = makeMockFetch(
      { version: 1, blanket_kill_active: false },
      { version: 1, blanket_kill_active: false, revoked_agents: ["agent:killed@bank.internal"] },
    );
    const worker = new RevocationSyncWorker({
      baseUrl: "http://localhost:9999",
      revocationCache: cache,
      fetchFn,
    });

    // Before sync: not revoked
    assert.equal(cache.isRevoked("agent:killed@bank.internal"), false);

    // Sync once (simulates background polling fetching remote state)
    await worker.syncOnce();

    // After sync: now locally denied
    assert.equal(cache.isRevoked("agent:killed@bank.internal"), true);
  });
});
