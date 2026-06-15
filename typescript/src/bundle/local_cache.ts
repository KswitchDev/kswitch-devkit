/**
 * Local bundle cache — disk-backed signed policy bundle for SDK-local evaluation.
 *
 * Bundle file: ~/.kswitch/bundle/current.bundle  (JSON)
 *
 * Bundle JSON schema (matches server PolicyBundle serialization and Python SDK):
 * {
 *   "version": 5,
 *   "bundle_id": "bundle:v5",
 *   "compiled_at": "2026-03-28T21:00:00Z",
 *   "cedar_text_enforce": "permit(...);",
 *   "cedar_text_shadow": "",
 *   "enforce_count": 3,
 *   "shadow_count": 0,
 *   "tool_count": 2,
 *   "tool_index": {"initiate_payment": {"requires_human_approval": false}},
 *   "signature": "sha256:<hex>"
 * }
 *
 * This format is IDENTICAL to the Python LocalBundleCache format.
 * No TypeScript-specific variant is used.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as os from "node:os";

const DEFAULT_BUNDLE_DIR = path.join(os.homedir(), ".kswitch", "bundle");
const BUNDLE_FILE = "current.bundle";

/** Max ages in seconds — mirrors Python _BUNDLE_MAX_AGE */
const BUNDLE_MAX_AGE: Record<string, number> = {
  critical: 60,
  high: 300,
  medium: 900,
  low: 3600,
};

// ── Error ─────────────────────────────────────────────────────────────────────

export class BundleNotAvailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BundleNotAvailableError";
  }
}

// ── Bundle model ──────────────────────────────────────────────────────────────

export interface LocalBundle {
  version: number;
  bundleId: string;
  compiledAt: string;
  cedarTextEnforce: string;
  cedarTextShadow: string;
  enforceCount: number;
  shadowCount: number;
  toolCount: number;
  toolIndex: Record<string, { requires_human_approval?: boolean; [key: string]: unknown }>;
  signature: string;
  /** Epoch ms when loaded — not persisted, used for staleness checks */
  readonly loadedAt: number;
}

export function isBundleStale(bundle: LocalBundle, riskTier = "medium"): boolean {
  const maxAge = BUNDLE_MAX_AGE[riskTier.toLowerCase()] ?? 900;
  return (Date.now() - bundle.loadedAt) / 1000 > maxAge;
}

export function bundleHasTool(bundle: LocalBundle, toolName: string): boolean {
  return toolName in bundle.toolIndex;
}

export function bundleRequiresHumanApproval(bundle: LocalBundle, toolName: string): boolean {
  return bundle.toolIndex[toolName]?.requires_human_approval === true;
}

// ── Cache ─────────────────────────────────────────────────────────────────────

export class LocalBundleCache {
  private readonly dir: string;
  private cachedBundle: LocalBundle | null = null;

  constructor(bundleDir = DEFAULT_BUNDLE_DIR) {
    this.dir = bundleDir;
  }

  private get bundlePath(): string {
    return path.join(this.dir, BUNDLE_FILE);
  }

  /** Load bundle from disk. Throws BundleNotAvailableError if missing/invalid. */
  load(): LocalBundle {
    const p = this.bundlePath;
    if (!fs.existsSync(p)) {
      throw new BundleNotAvailableError(
        `No local bundle at ${p}. ` +
        "Fetch from server: client.bundle.fetchAndStore()",
      );
    }

    let data: Record<string, unknown>;
    try {
      const raw = fs.readFileSync(p, "utf-8");
      data = JSON.parse(raw) as Record<string, unknown>;
    } catch (e) {
      throw new BundleNotAvailableError(`Bundle file unreadable: ${e}`);
    }

    if (!verifySignature(data)) {
      throw new BundleNotAvailableError(
        "Bundle signature verification failed. " +
        "Bundle may be tampered with or signing key rotated.",
      );
    }

    const bundle: LocalBundle = {
      version: (data.version as number) ?? 0,
      bundleId: (data.bundle_id as string) ?? "",
      compiledAt: (data.compiled_at as string) ?? "",
      cedarTextEnforce: (data.cedar_text_enforce as string) ?? "",
      cedarTextShadow: (data.cedar_text_shadow as string) ?? "",
      enforceCount: (data.enforce_count as number) ?? 0,
      shadowCount: (data.shadow_count as number) ?? 0,
      toolCount: (data.tool_count as number) ?? 0,
      toolIndex: (data.tool_index as LocalBundle["toolIndex"]) ?? {},
      signature: (data.signature as string) ?? "",
      loadedAt: Date.now(),
    };

    this.cachedBundle = bundle;
    return bundle;
  }

  /** Return cached bundle or load from disk. Returns null if unavailable. */
  getOrLoad(): LocalBundle | null {
    if (this.cachedBundle !== null) {
      return this.cachedBundle;
    }
    try {
      return this.load();
    } catch {
      return null;
    }
  }

  /** Invalidate in-memory cache. Next call will reload from disk. */
  invalidate(): void {
    this.cachedBundle = null;
  }

  /**
   * Write bundle JSON to disk atomically. Called after fetching from server.
   * Accepts the raw server response dict — same format Python writes.
   */
  store(bundleData: Record<string, unknown>): void {
    fs.mkdirSync(this.dir, { recursive: true });
    const p = this.bundlePath;
    const tmp = p + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(bundleData, null, 2), "utf-8");
    fs.renameSync(tmp, p); // Atomic rename (same as Python os.replace)
    this.cachedBundle = null; // Force reload
  }

  getVersion(): number | null {
    const bundle = this.getOrLoad();
    return bundle ? bundle.version : null;
  }
}

// ── Signature verification ────────────────────────────────────────────────────

function verifySignature(data: Record<string, unknown>): boolean {
  const storedSig = (data.signature as string) ?? "";
  if (!storedSig) {
    // No signature — accept in dev mode (KSWITCH_ENV != production)
    if (process.env["KSWITCH_ENV"] === "production") {
      return false;
    }
    return true;
  }
  // Compute signature over stable fields (excluding signature + _loaded_at)
  const stable = Object.fromEntries(
    Object.entries(data).filter(([k]) => k !== "signature" && k !== "_loaded_at"),
  );
  // Sort keys for deterministic serialization — matches Python sort_keys=True
  const content = JSON.stringify(stable, Object.keys(stable).sort());
  const expected = "sha256:" + crypto.createHash("sha256").update(content, "utf-8").digest("hex");
  return storedSig === expected;
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _cache = new LocalBundleCache();

export function loadCurrentBundle(): LocalBundle | null {
  return _cache.getOrLoad();
}

export function getBundleCache(): LocalBundleCache {
  return _cache;
}

/** Replace the singleton (for testing). */
export function _setBundleCache(cache: LocalBundleCache): void {
  _cache = cache;
}
