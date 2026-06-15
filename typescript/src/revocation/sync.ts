/**
 * Revocation sync worker — background polling to keep local revocation cache current.
 *
 * Mirrors Python RevocationSyncWorker exactly.
 *
 * Architecture (TypeScript equivalent of Python daemon thread):
 *   - setInterval polls GET /api/v1/sdk/revocations/version on interval
 *   - If server version changed: fetches GET /api/v1/sdk/revocations/state
 *   - Atomically applies full state to LocalRevocationCache
 *   - Decision path uses O(1) local lookup — no sync latency on hot path
 *   - Sync happens entirely in background; tool invocations are never blocked
 *
 * Node.js execution model:
 *   - setInterval-based polling runs on the Node.js event loop
 *   - HTTP fetch uses the global fetch API (Node.js 18+)
 *   - All cache mutations are synchronous (single-threaded JS)
 *   - No worker_threads needed — fetch I/O is async/non-blocking
 *
 * Stale-sync behavior: identical to Python
 *   KSWITCH_REVOCATION_STALE_MODE: "warn" | "deny" | "conditional"
 */

import { getRevocationCache, LocalRevocationCache } from "./cache.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SyncWorkerConfig {
  baseUrl: string;
  interval?: number;        // seconds (default: 30)
  staleThreshold?: number;  // seconds (default: 150)
  staleMode?: "warn" | "deny" | "conditional";
  revocationCache?: LocalRevocationCache;
  /** Custom fetch function — defaults to globalThis.fetch. Injectable for tests. */
  fetchFn?: typeof globalThis.fetch;
  /**
   * Authorization header value, e.g. "Bearer <token>".
   * Required — revocation endpoints are authenticated at the application layer
   * (PR-11 closure). Set to an M2M client_credentials token or static service token
   * with Register.Service (or higher) role.
   */
  authHeader?: string;
}

// ── Worker ────────────────────────────────────────────────────────────────────

export class RevocationSyncWorker {
  static readonly VERSION_PATH = "/api/v1/sdk/revocations/version";
  static readonly STATE_PATH = "/api/v1/sdk/revocations/state";

  private readonly baseUrl: string;
  private readonly interval: number;
  private readonly staleThreshold: number;
  private readonly staleMode: string;
  private readonly cache: LocalRevocationCache;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly authHeader: string | undefined;

  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  // Diagnostics
  private startedAt: number | null = null;
  private pollCount = 0;
  private fetchCount = 0;
  private lastPollAt: number | null = null;
  private lastFetchAt: number | null = null;
  private lastError: string | null = null;

  constructor(config: SyncWorkerConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.interval = Math.max(1, config.interval ?? 30);
    this.staleThreshold = config.staleThreshold ?? 150;
    this.staleMode = config.staleMode ?? "warn";
    this.cache = config.revocationCache ?? getRevocationCache();
    this.fetchFn = config.fetchFn ?? globalThis.fetch.bind(globalThis);
    this.authHeader = config.authHeader;
  }

  /** Start the background sync polling. Idempotent. */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.startedAt = Date.now() / 1000;
    // Run once immediately, then on interval
    void this.poll();
    this.timer = setInterval(() => { void this.poll(); }, this.interval * 1000);
    console.debug(
      `kswitch.revocation.sync: started | interval=${this.interval}s ` +
      `stale_threshold=${this.staleThreshold}s stale_mode=${this.staleMode}`,
    );
  }

  /** Stop background sync gracefully. */
  stop(): void {
    if (!this.running) return;
    this.running = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    console.debug("kswitch.revocation.sync: stopped");
  }

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Perform a single sync cycle (for tests / manual trigger).
   * Returns true if a full-state fetch was performed.
   */
  async syncOnce(): Promise<boolean> {
    return this.pollAndMaybeFetch();
  }

  diagnostics(): {
    sync_worker: {
      running: boolean;
      started_at: number | null;
      poll_count: number;
      fetch_count: number;
      last_poll_at: number | null;
      last_fetch_at: number | null;
      last_error: string | null;
      interval_seconds: number;
      stale_threshold_seconds: number;
      stale_mode: string;
      is_stale: boolean;
    };
    cache: ReturnType<LocalRevocationCache["getDiagnostics"]>;
  } {
    return {
      sync_worker: {
        running: this.running,
        started_at: this.startedAt,
        poll_count: this.pollCount,
        fetch_count: this.fetchCount,
        last_poll_at: this.lastPollAt,
        last_fetch_at: this.lastFetchAt,
        last_error: this.lastError,
        interval_seconds: this.interval,
        stale_threshold_seconds: this.staleThreshold,
        stale_mode: this.staleMode,
        is_stale: this.cache.isSyncStale(this.staleThreshold),
      },
      cache: this.cache.getDiagnostics(),
    };
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private async poll(): Promise<void> {
    try {
      await this.pollAndMaybeFetch();
    } catch (exc) {
      const err = String(exc).slice(0, 120);
      this.lastError = err;
      this.cache.recordSyncFailure(err);
      console.warn(`kswitch.revocation.sync: poll error: ${err}`);
      this.checkStaleBehavior();
    }
  }

  private async pollAndMaybeFetch(): Promise<boolean> {
    const now = Date.now() / 1000;
    this.pollCount += 1;
    this.lastPollAt = now;

    // ── Step 1: Cheap version check ──────────────────────────────────────────
    const versionUrl = this.baseUrl + RevocationSyncWorker.VERSION_PATH;
    const authHeaders: Record<string, string> = this.authHeader
      ? { Authorization: this.authHeader }
      : {};
    let versionData: { version?: number; blanket_kill_active?: boolean };
    try {
      const resp = await this.fetchFn(versionUrl, {
        signal: AbortSignal.timeout(5000),
        headers: authHeaders,
      });
      if (resp.status === 401) {
        const err = "revocation_version_auth_failed: HTTP 401 — check authHeader or SDK token config";
        this.lastError = err;
        this.cache.recordSyncFailure(err);
        console.error(`kswitch.revocation.sync: ${err}`);
        return false;
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      versionData = await resp.json() as typeof versionData;
    } catch (exc) {
      const err = `version_check_failed: ${String(exc).slice(0, 80)}`;
      this.lastError = err;
      this.cache.recordSyncFailure(err);
      console.warn(`kswitch.revocation.sync: version check failed: ${err}`);
      this.checkStaleBehavior();
      return false;
    }

    const serverVersion = versionData.version ?? null;
    const blanket = Boolean(versionData.blanket_kill_active);

    // ── Step 2: Blanket kill fast path ────────────────────────────────────────
    if (blanket) {
      const diag = this.cache.getDiagnostics();
      if (!diag.blanket_kill_active) {
        console.error("kswitch.revocation.sync: BLANKET KILL ACTIVE — applying immediately");
        this.cache.applyServerState({
          version: serverVersion,
          blanket_kill_active: true,
          revoked_agents: [],
        });
        return true;
      }
    }

    // ── Step 3: Version comparison ────────────────────────────────────────────
    const localVersion = this.cache.getServerVersion();
    if (localVersion !== null && localVersion === serverVersion) {
      console.debug(
        `kswitch.revocation.sync: version unchanged (${serverVersion}) — skip fetch`,
      );
      // Update lastSyncedAt so staleness clock resets even on no-op polls
      // We call applyServerState with existing data to refresh the timestamp
      const diag = this.cache.getDiagnostics();
      // Use a no-op applyServerState to reset the sync timestamp:
      // pass current state back to itself to bump lastSyncedAt
      this.cache.applyServerState({
        version: localVersion,
        blanket_kill_active: diag.blanket_kill_active,
        revoked_agents: [], // preserved by apply
      });
      return false;
    }

    // ── Step 4: Full-state fetch ──────────────────────────────────────────────
    console.info(
      `kswitch.revocation.sync: version changed ${localVersion}→${serverVersion} — fetching full state`,
    );
    const stateUrl = this.baseUrl + RevocationSyncWorker.STATE_PATH;
    let state: { version?: number; blanket_kill_active?: boolean; revoked_agents?: string[] };
    try {
      const stateResp = await this.fetchFn(stateUrl, {
        signal: AbortSignal.timeout(10000),
        headers: authHeaders,
      });
      if (stateResp.status === 401) {
        const err = "revocation_state_auth_failed: HTTP 401 — check authHeader or SDK token config";
        this.lastError = err;
        this.cache.recordSyncFailure(err);
        console.error(`kswitch.revocation.sync: ${err}`);
        return false;
      }
      if (!stateResp.ok) {
        throw new Error(`HTTP ${stateResp.status}`);
      }
      state = await stateResp.json() as typeof state;
    } catch (exc) {
      const err = `state_fetch_failed: ${String(exc).slice(0, 80)}`;
      this.lastError = err;
      this.cache.recordSyncFailure(err);
      console.error(`kswitch.revocation.sync: state fetch failed: ${err}`);
      return false;
    }

    // ── Step 5: Atomic cache update ───────────────────────────────────────────
    this.cache.applyServerState(state);
    this.fetchCount += 1;
    this.lastFetchAt = Date.now() / 1000;
    this.lastError = null;

    console.info(
      `kswitch.revocation.sync: synced ok | version=${state.version} ` +
      `blanket=${state.blanket_kill_active} revoked=${state.revoked_agents?.length ?? 0}`,
    );
    return true;
  }

  private checkStaleBehavior(): void {
    if (!this.cache.isSyncStale(this.staleThreshold)) return;
    if (this.staleMode === "warn") {
      console.warn(
        `kswitch.revocation.sync: STALE — revocation state has not synced ` +
        `for >${this.staleThreshold}s (stale_mode=warn, decisions continue with cached state)`,
      );
    } else if (this.staleMode === "deny") {
      console.error(
        "kswitch.revocation.sync: STALE — stale_mode=deny, all decisions " +
        "will be DENIED until sync recovers",
      );
    } else if (this.staleMode === "conditional") {
      console.warn(
        "kswitch.revocation.sync: STALE — stale_mode=conditional, all " +
        "decisions will escalate to server until sync recovers",
      );
    }
  }
}

// ── Module-level singleton worker ─────────────────────────────────────────────

let _worker: RevocationSyncWorker | null = null;

export function getSyncWorker(): RevocationSyncWorker | null {
  return _worker;
}

/** Start (or return existing) module-level sync worker. Idempotent. */
export function startSyncWorker(config: SyncWorkerConfig): RevocationSyncWorker {
  if (_worker !== null && _worker.isRunning()) {
    return _worker;
  }
  _worker = new RevocationSyncWorker(config);
  _worker.start();
  return _worker;
}

/** Stop the module-level sync worker if running. */
export function stopSyncWorker(): void {
  if (_worker !== null) {
    _worker.stop();
    _worker = null;
  }
}
