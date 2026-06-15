/**
 * KSwitch TypeScript SDK — Execution Token Validator (Phase 1 service-library).
 *
 * Enforces all ten required checks (design spec Section 11.3).
 * Uses a local JWKS cache at KSWITCH_STATE_DIR/jwks/current.json.
 * Maintains an independent disk-backed replay cache at KSWITCH_STATE_DIR/replay_cache/.
 *
 * Uses Node.js built-in `node:crypto` — zero external dependencies.
 *
 * @example
 * ```ts
 * const validator = KSwitchTokenValidator.fromEnv();
 * const result = validator.validate(token, { action: "read_customer", resource: "mcp:crm@bank" });
 * if (!result.valid) throw new Error(result.errorCode);
 * ```
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";

const TOLERANCE_SECONDS = 30;
const GRACE_SECONDS = 5;

// ── ValidationResult ─────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errorCode?: string;
  claims?: Record<string, unknown>;
  jti?: string;
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function b64urlDecode(s: string): Buffer {
  const padded = s + "=".repeat((-s.length) & 3);
  return Buffer.from(padded, "base64url");
}

function parseJwks(jwks: { keys?: object[] }): Map<string, crypto.KeyObject> {
  const keys = new Map<string, crypto.KeyObject>();
  for (const jwk of jwks.keys ?? []) {
    const j = jwk as Record<string, unknown>;
    if (j["kty"] !== "EC" || j["crv"] !== "P-256") continue;
    try {
      const pub = crypto.createPublicKey({
        key: { kty: j["kty"], crv: j["crv"], x: j["x"], y: j["y"] } as Record<string, unknown>,
        format: "jwk",
      } as Parameters<typeof crypto.createPublicKey>[0]);
      keys.set(j["kid"] as string, pub);
    } catch {
      // Skip malformed JWK
    }
  }
  return keys;
}

/** Convert raw 64-byte r||s to DER for `crypto.verify`. */
function raw64ToDer(raw: Buffer): Buffer {
  if (raw.length !== 64) throw new Error(`ES256 sig must be 64 bytes, got ${raw.length}`);

  // Strip leading zeros, re-add leading 0x00 if high bit is set (DER positive integer)
  function encode(buf: Buffer): Buffer {
    let b = buf;
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
    return b;
  }

  const r = encode(raw.slice(0, 32));
  const s = encode(raw.slice(32, 64));

  const inner = Buffer.concat([
    Buffer.from([0x02, r.length]), r,
    Buffer.from([0x02, s.length]), s,
  ]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

function verifyEs256(
  headerB64: string,
  payloadB64: string,
  sigB64: string,
  pubKey: crypto.KeyObject,
): void {
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const rawSig = b64urlDecode(sigB64);
  const derSig = raw64ToDer(rawSig);
  const ok = crypto.verify("sha256", signingInput, pubKey, derSig);
  if (!ok) throw new Error("ES256 signature verification failed");
}

// ── Replay cache (disk-backed, thread-safe via synchronous writes) ────────────

class ReplayCache {
  private store: Map<string, number> = new Map();
  private readonly filePath: string;

  constructor(cacheDir: string) {
    fs.mkdirSync(cacheDir, { recursive: true });
    this.filePath = path.join(cacheDir, "replay_cache.json");
    this._load();
  }

  isReplayed(jti: string): boolean {
    this._evict();
    return this.store.has(jti);
  }

  record(jti: string, expDeadline: number): void {
    this._evict();
    this.store.set(jti, expDeadline);
    this._save();
  }

  private _load(): void {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as Record<string, number>;
        const now = Date.now() / 1000;
        for (const [k, v] of Object.entries(data)) {
          if (v > now) this.store.set(k, v);
        }
      }
    } catch {
      this.store = new Map();
    }
  }

  private _save(): void {
    try {
      const obj: Record<string, number> = {};
      for (const [k, v] of this.store) obj[k] = v;
      fs.writeFileSync(this.filePath, JSON.stringify(obj));
    } catch {
      // Best effort
    }
  }

  private _evict(): void {
    const now = Date.now() / 1000;
    for (const [k, v] of this.store) {
      if (v < now) this.store.delete(k);
    }
  }
}

// ── Synchronous JWKS fetch via curl (fallback for cold start) ─────────────────

function fetchJwksSync(url: string): string | null {
  try {
    const result = spawnSync("curl", ["-sk", "--max-time", "3", url], {
      encoding: "utf8",
      timeout: 4000,
    });
    if (result.status === 0 && result.stdout) return result.stdout;
  } catch {
    // curl not available or failed
  }
  return null;
}

// ── Validator ─────────────────────────────────────────────────────────────────

export class KSwitchTokenValidator {
  private publicKeys: Map<string, crypto.KeyObject> = new Map();
  private readonly jwksCachePath: string;
  private readonly replayCache: ReplayCache | null;

  constructor(
    private readonly jwksUrl?: string,
    jwksCachePath?: string,
    private readonly expectedIssuer: string = "kswitch",
    private readonly expectedAudience: string = "kswitch-control-plane",
    replayCacheDir?: string,
    private readonly replayCacheEnabled: boolean = true,
  ) {
    const stateDir =
      process.env["KSWITCH_STATE_DIR"] ?? path.join(os.homedir(), ".kswitch", "state");

    this.jwksCachePath = jwksCachePath ?? path.join(stateDir, "jwks", "current.json");
    fs.mkdirSync(path.dirname(this.jwksCachePath), { recursive: true });

    if (replayCacheEnabled) {
      const dir = replayCacheDir ?? path.join(stateDir, "replay_cache");
      this.replayCache = new ReplayCache(dir);
    } else {
      this.replayCache = null;
    }

    this._loadJwks();
  }

  static fromEnv(): KSwitchTokenValidator {
    const stateDir =
      process.env["KSWITCH_STATE_DIR"] ?? path.join(os.homedir(), ".kswitch", "state");
    return new KSwitchTokenValidator(
      process.env["KSWITCH_EXECUTION_TOKEN_JWKS_URL"],
      path.join(stateDir, "jwks", "current.json"),
      process.env["KSWITCH_EXECUTION_TOKEN_EXPECTED_ISSUER"] ?? "kswitch",
      process.env["KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE"] ?? "kswitch-control-plane",
      path.join(stateDir, "replay_cache"),
      (process.env["KSWITCH_EXECUTION_TOKEN_REPLAY_CACHE_ENABLED"] ?? "true").toLowerCase() ===
        "true",
    );
  }

  /** Load JWKS directly — used in tests to inject keys without network. */
  loadJwksFromDict(jwks: { keys?: object[] }): void {
    this.publicKeys = parseJwks(jwks);
  }

  /** Validate token against all ten required checks. */
  validate(
    token: string,
    opts?: {
      action?: string;
      resource?: string;
      requestParams?: Record<string, unknown>;
    },
  ): ValidationResult {
    if (!token) {
      return { valid: false, errorCode: "execution_token_missing" };
    }

    // Parse header to get kid
    let parts: string[];
    let header: Record<string, unknown>;
    let kid: string | undefined;
    try {
      parts = token.split(".");
      if (parts.length !== 3) throw new Error("bad parts");
      header = JSON.parse(b64urlDecode(parts[0]!).toString("utf8"));
      kid = header["kid"] as string | undefined;
    } catch {
      return { valid: false, errorCode: "execution_token_invalid_signature" };
    }

    // Check 2: kid known
    if (!kid || !this.publicKeys.has(kid)) {
      this._refreshJwks();
      if (!kid || !this.publicKeys.has(kid)) {
        return { valid: false, errorCode: "execution_token_unknown_kid" };
      }
    }
    const pubKey = this.publicKeys.get(kid)!;

    // Check 1: Signature valid
    try {
      verifyEs256(parts[0]!, parts[1]!, parts[2]!, pubKey);
    } catch {
      return { valid: false, errorCode: "execution_token_invalid_signature" };
    }

    // Decode payload
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(b64urlDecode(parts[1]!).toString("utf8"));
    } catch {
      return { valid: false, errorCode: "execution_token_invalid_signature" };
    }

    const jti = claims["jti"] as string | undefined;
    const now = Date.now() / 1000;

    // Check 3: Issuer
    if (claims["iss"] !== this.expectedIssuer) {
      return { valid: false, errorCode: "execution_token_unknown_kid", jti };
    }

    // Check 4: Audience
    const aud = claims["aud"];
    const audOk = Array.isArray(aud)
      ? aud.includes(this.expectedAudience)
      : aud === this.expectedAudience;
    if (!audOk) {
      return { valid: false, errorCode: "execution_token_wrong_audience", jti };
    }

    // Check 5: Not expired
    if (((claims["exp"] as number | undefined) ?? 0) < now) {
      return { valid: false, errorCode: "execution_token_expired", jti };
    }

    // Check 6: Not before
    if (((claims["nbf"] as number | undefined) ?? 0) > now + TOLERANCE_SECONDS) {
      return { valid: false, errorCode: "execution_token_not_yet_valid", jti };
    }

    // Check 7: Action matches
    if (opts?.action !== undefined && claims["action"] !== opts.action) {
      return { valid: false, errorCode: "execution_token_action_mismatch", jti };
    }

    // Check 8: Resource matches
    if (opts?.resource !== undefined && claims["resource"] !== opts.resource) {
      return { valid: false, errorCode: "execution_token_resource_mismatch", jti };
    }

    // Check 9: req_hash
    if ("req_hash" in claims && opts?.requestParams !== undefined) {
      const canonical = JSON.stringify(
        Object.fromEntries(Object.entries(opts.requestParams).sort()),
      );
      const expected = crypto.createHash("sha256").update(canonical).digest("hex");
      if (claims["req_hash"] !== expected) {
        return { valid: false, errorCode: "execution_token_request_mismatch", jti };
      }
    }

    // Check 10: Replay
    if (claims["single_use"] && jti && this.replayCacheEnabled && this.replayCache) {
      if (this.replayCache.isReplayed(jti)) {
        return { valid: false, errorCode: "execution_token_replay_detected", jti };
      }
      const exp = ((claims["exp"] as number | undefined) ?? now + 30) + GRACE_SECONDS;
      this.replayCache.record(jti, exp);
    }

    return { valid: true, claims, jti };
  }

  // ── JWKS ──────────────────────────────────────────────────────────────────

  private _loadJwks(): void {
    try {
      if (fs.existsSync(this.jwksCachePath)) {
        const jwks = JSON.parse(fs.readFileSync(this.jwksCachePath, "utf8"));
        this.publicKeys = parseJwks(jwks);
        return;
      }
    } catch {
      // Fall through to network refresh
    }
    this._refreshJwks();
  }

  private _refreshJwks(): void {
    if (!this.jwksUrl) return;
    try {
      const raw = fetchJwksSync(this.jwksUrl);
      if (!raw) return;
      const jwks = JSON.parse(raw);
      this.publicKeys = parseJwks(jwks);
      fs.writeFileSync(this.jwksCachePath, raw);
    } catch {
      // Best effort — continue with existing keys
    }
  }
}
