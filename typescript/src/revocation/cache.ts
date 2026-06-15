/**
 * Local revocation cache — in-process O(1) lookup for killed/suspended agents.
 *
 * Push-based: RevocationSyncWorker.syncOnce() fetches from server and populates.
 * Disk persistence: ~/.kswitch/revocation/revoked.json (survives process restart).
 *
 * Mirrors Python LocalRevocationCache exactly.
 * Node.js is single-threaded for JS code, so no explicit mutex is needed —
 * all state mutations are synchronous.
 *
 * The cache is checked BEFORE any bundle/context evaluation.
 * A revoked agent is denied without any further evaluation.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const DEFAULT_REVOCATION_DIR = path.join(os.homedir(), ".kswitch", "revocation");
const REVOCATION_FILE = "revoked.json";
const REVOCATION_EXPIRY = 86400; // 24 hours

// ── Revocation entry ──────────────────────────────────────────────────────────

interface RevocationEntry {
  revoked_at: number;  // Unix timestamp (seconds)
  reason: string;
}

// ── Cache ─────────────────────────────────────────────────────────────────────

export class LocalRevocationCache {
  private readonly dir: string;
  private revoked: Map<string, RevocationEntry> = new Map();
  private blanketActive = false;
  private loaded = false;

  // PR-11 sync metadata
  private serverVersion: number | null = null;
  private lastSyncedAt: number | null = null;
  private lastSyncFailure: string | null = null;
  private syncFailureCount = 0;

  constructor(revocationDir = DEFAULT_REVOCATION_DIR) {
    this.dir = revocationDir;
  }

  private get filePath(): string {
    return path.join(this.dir, REVOCATION_FILE);
  }

  /** Load persisted revocations from disk. */
  loadFromDisk(): void {
    const p = this.filePath;
    if (!fs.existsSync(p)) return;
    try {
      const data = JSON.parse(fs.readFileSync(p, "utf-8")) as {
        revoked?: Record<string, RevocationEntry>;
        blanket_active?: boolean;
      };
      this.revoked = new Map(Object.entries(data.revoked ?? {}));
      this.blanketActive = data.blanket_active ?? false;
      this.loaded = true;
    } catch {
      // Corrupt file — start fresh
    }
  }

  private ensureLoaded(): void {
    if (!this.loaded) {
      this.loadFromDisk();
      this.loaded = true;
    }
  }

  isRevoked(agentId: string): boolean {
    this.ensureLoaded();
    if (this.blanketActive) return true;
    const entry = this.revoked.get(agentId);
    if (!entry) return false;
    // Check expiry
    if (Date.now() / 1000 - entry.revoked_at > REVOCATION_EXPIRY) {
      this.revoked.delete(agentId);
      return false;
    }
    return true;
  }

  revoke(agentId: string, reason = "kill_switch"): void {
    this.ensureLoaded();
    this.revoked.set(agentId, { revoked_at: Date.now() / 1000, reason });
    this.persist();
  }

  setBlanketKill(active: boolean, _reason = ""): void {
    this.blanketActive = active;
    this.persist();
  }

  clearAgent(agentId: string): void {
    this.revoked.delete(agentId);
    this.persist();
  }

  private persist(): void {
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const p = this.filePath;
      const tmp = p + ".tmp";
      const data = {
        revoked: Object.fromEntries(this.revoked),
        blanket_active: this.blanketActive,
        updated_at: Date.now() / 1000,
        server_version: this.serverVersion,
        last_synced_at: this.lastSyncedAt,
      };
      fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf-8");
      fs.renameSync(tmp, p);
    } catch {
      // Persistence failure is non-fatal
    }
  }

  // ── PR-11: Server sync API ─────────────────────────────────────────────────

  getServerVersion(): number | null {
    return this.serverVersion;
  }

  /**
   * Atomically replace local revocation state from a server state payload.
   *
   * Called by the background sync worker after a full-state fetch.
   * Replaces the entire revocation set and blanket flag atomically.
   *
   * @param state Server response from GET /api/v1/sdk/revocations/state
   */
  applyServerState(state: {
    version?: number | null;
    blanket_kill_active?: boolean;
    revoked_agents?: string[];
  }): void {
    const serverVersion = state.version ?? null;
    const blanket = Boolean(state.blanket_kill_active);
    const revokedIds = state.revoked_agents ?? [];
    const now = Date.now() / 1000;

    // Replace entire set (full-state sync — correctness over delta)
    this.revoked = new Map(
      revokedIds.map((id) => [id, { revoked_at: now, reason: "server_sync" }]),
    );
    this.blanketActive = blanket;
    this.serverVersion = serverVersion;
    this.lastSyncedAt = now;
    this.lastSyncFailure = null;
    this.loaded = true;

    this.persist();
  }

  recordSyncFailure(error: string): void {
    this.lastSyncFailure = error;
    this.syncFailureCount += 1;
  }

  /**
   * Return true if the last successful sync was more than thresholdSeconds ago.
   * Returns true if never synced and threshold > 0 (initial state is stale).
   */
  isSyncStale(thresholdSeconds: number): boolean {
    if (thresholdSeconds <= 0) return false;
    if (this.lastSyncedAt === null) return true;
    return Date.now() / 1000 - this.lastSyncedAt > thresholdSeconds;
  }

  /** Return sync diagnostics for observability. */
  getDiagnostics(): {
    server_version: number | null;
    last_synced_at: number | null;
    last_sync_failure: string | null;
    sync_failure_count: number;
    blanket_kill_active: boolean;
    revoked_count: number;
    loaded_from_disk: boolean;
  } {
    return {
      server_version: this.serverVersion,
      last_synced_at: this.lastSyncedAt,
      last_sync_failure: this.lastSyncFailure,
      sync_failure_count: this.syncFailureCount,
      blanket_kill_active: this.blanketActive,
      revoked_count: this.revoked.size,
      loaded_from_disk: this.loaded,
    };
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _cache = new LocalRevocationCache();

export function getRevocationCache(): LocalRevocationCache {
  return _cache;
}

/** Replace the singleton (for testing). */
export function _setRevocationCache(cache: LocalRevocationCache): void {
  _cache = cache;
}
