/**
 * Local context cache — disk-backed agent/MCP context for SDK-local evaluation.
 *
 * Context pack file: ~/.kswitch/context/{sanitized_agent_id}.contextpack  (JSON)
 *
 * Context pack JSON schema (subset of server ContextPack — identical to Python SDK):
 * {
 *   "agent_id": "agent:fraud-detector@bank.internal",
 *   "status": "active",
 *   "risk_tier": "high",
 *   "data_classifications": ["PII"],
 *   "is_revoked": false,
 *   "compiled_at": "2026-03-28T21:00:00Z",
 *   "pack_version": 3
 * }
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const DEFAULT_CONTEXT_DIR = path.join(os.homedir(), ".kswitch", "context");

/** Context pack TTLs in seconds — mirrors Python _CONTEXT_PACK_TTL */
const CONTEXT_PACK_TTL: Record<string, number> = {
  critical: 5,
  high: 30,
  medium: 120,
  low: 300,
};

// ── Error ─────────────────────────────────────────────────────────────────────

export class ContextNotAvailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContextNotAvailableError";
  }
}

// ── Context pack model ────────────────────────────────────────────────────────

export interface LocalContextPack {
  agentId: string;
  status: string;
  riskTier: string;
  dataClassifications: string[];
  isRevoked: boolean;
  compiledAt: string;
  packVersion: number;
  /** Epoch ms when loaded — not persisted, used for staleness checks */
  readonly loadedAt: number;
}

export function isContextPackActive(pack: LocalContextPack): boolean {
  return (
    ["active", "declared", "pending"].includes(pack.status) &&
    !pack.isRevoked
  );
}

export function isContextPackStale(pack: LocalContextPack): boolean {
  const ttl = CONTEXT_PACK_TTL[pack.riskTier.toLowerCase()] ?? 120;
  return (Date.now() - pack.loadedAt) / 1000 > ttl;
}

// ── Sanitize agent ID to filename ─────────────────────────────────────────────

export function sanitizeAgentId(agentId: string): string {
  return agentId
    .replace(/:/g, "_")
    .replace(/\//g, "_")
    .replace(/@/g, "_at_")
    .replace(/\./g, "_");
}

// ── Cache ─────────────────────────────────────────────────────────────────────

export class LocalContextCache {
  private readonly dir: string;
  private readonly packs = new Map<string, LocalContextPack>();

  constructor(contextDir = DEFAULT_CONTEXT_DIR) {
    this.dir = contextDir;
  }

  private packPath(agentId: string): string {
    return path.join(this.dir, `${sanitizeAgentId(agentId)}.contextpack`);
  }

  /** Load context pack for agent from disk. */
  load(agentId: string): LocalContextPack {
    const p = this.packPath(agentId);
    if (!fs.existsSync(p)) {
      throw new ContextNotAvailableError(
        `No local context pack for ${agentId} at ${p}. ` +
        "Fetch from server: client.context.fetchAndStore(agentId)",
      );
    }

    let data: Record<string, unknown>;
    try {
      const raw = fs.readFileSync(p, "utf-8");
      data = JSON.parse(raw) as Record<string, unknown>;
    } catch (e) {
      throw new ContextNotAvailableError(`Context pack unreadable for ${agentId}: ${e}`);
    }

    const pack: LocalContextPack = {
      agentId: (data.agent_id as string) ?? agentId,
      status: (data.status as string) ?? "unknown",
      riskTier: (data.risk_tier as string) ?? "medium",
      dataClassifications: (data.data_classifications as string[]) ?? [],
      isRevoked: (data.is_revoked as boolean) ?? false,
      compiledAt: (data.compiled_at as string) ?? "",
      packVersion: (data.pack_version as number) ?? 0,
      loadedAt: Date.now(),
    };

    this.packs.set(agentId, pack);
    return pack;
  }

  /** Return cached pack or load from disk. Returns null if unavailable. */
  getOrLoad(agentId: string): LocalContextPack | null {
    const cached = this.packs.get(agentId);
    if (cached !== undefined && !isContextPackStale(cached)) {
      return cached;
    }
    try {
      return this.load(agentId);
    } catch {
      return null;
    }
  }

  /**
   * Write context pack JSON to disk atomically.
   * Accepts the raw server dict — same format Python writes.
   */
  store(agentId: string, packData: Record<string, unknown>): void {
    fs.mkdirSync(this.dir, { recursive: true });
    const p = this.packPath(agentId);
    const tmp = p + ".tmp";
    const payload = { ...packData, agent_id: agentId };
    fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), "utf-8");
    fs.renameSync(tmp, p);
    this.packs.delete(agentId); // Force reload
  }

  invalidate(agentId: string): void {
    this.packs.delete(agentId);
  }

  getVersion(agentId: string): number | null {
    const pack = this.getOrLoad(agentId);
    return pack ? pack.packVersion : null;
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _cache = new LocalContextCache();

export function loadContextPack(agentId: string): LocalContextPack | null {
  return _cache.getOrLoad(agentId);
}

export function getContextCache(): LocalContextCache {
  return _cache;
}

/** Replace the singleton (for testing). */
export function _setContextCache(cache: LocalContextCache): void {
  _cache = cache;
}
