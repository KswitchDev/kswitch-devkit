/**
 * KSwitch TypeScript SDK -- WIMSE delegation assertion builder.
 *
 * Implements draft-ietf-wimse-workload-identity-02 with KSwitch extensions.
 *
 * Signing algorithm: ES256 (ECDSA P-256) universally across all three SDKs,
 * the JWKS registry, and the boundary validator. SPIRE issues EC P-256 SVIDs
 * by default. Do NOT use Ed25519 -- it is incompatible with ES256 and will
 * produce JWTs that fail verification at the boundary validator.
 *
 * Uses Node.js built-in `node:crypto` -- zero external dependencies.
 *
 * @example
 * ```ts
 * import { WIMSEChainBuilder } from "@kswitch/sdk";
 *
 * const chain = new WIMSEChainBuilder();
 * await chain.addHop({
 *   delegateeSpiffeId: "spiffe://bank.internal/agent/risk-engine",
 *   scope: "payments:read",
 *   purpose: "fraud-check",
 *   resourceContext: "account:123456",
 *   rootSessionId: "sess-abc-123",
 * });
 * const headerValue = chain.toHeaderValue();
 * // Attach as: X-WIMSE-Delegation-Chain: <headerValue>
 * ```
 */

import * as crypto from "node:crypto";
import { fetchSvid } from "./spire.js";

// ── Field length limits (enforced before signing) ────────────────────────────

export const MAX_PURPOSE_LEN = 128;
export const MAX_RESOURCE_CONTEXT_LEN = 256;
export const MAX_WORKFLOW_ID_LEN = 64;
export const MAX_CHAIN_DEPTH = 3;
export const MAX_ASSERTION_TTL_SECONDS = 300; // 5 minutes hard max
export const MAX_CHAIN_HEADER_BYTES = 8192; // 8 KB HTTP header limit

// ── Helpers ──────────────────────────────────────────────────────────────────

function b64url(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}

/**
 * Convert DER-encoded ECDSA signature (produced by Node.js `crypto.sign`)
 * to raw 64-byte r||s format required by JWS ES256.
 */
function derToRaw64(der: Buffer): Buffer {
  // DER SEQUENCE: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
  let offset = 2; // skip 0x30 + total len
  if (der[1]! > 0x80) offset += der[1]! - 0x80; // long-form length

  // r
  offset++; // 0x02
  const rLen = der[offset++]!;
  let r = der.subarray(offset, offset + rLen);
  offset += rLen;
  if (r[0] === 0x00) r = r.subarray(1); // strip leading zero byte

  // s
  offset++; // 0x02
  const sLen = der[offset++]!;
  let s = der.subarray(offset, offset + sLen);
  if (s[0] === 0x00) s = s.subarray(1);

  // Pad to 32 bytes each
  const out = Buffer.alloc(64, 0);
  r.copy(out, 32 - r.length);
  s.copy(out, 64 - s.length);
  return out;
}

// ── WIMSEAssertion ───────────────────────────────────────────────────────────

export interface WIMSEAssertionFields {
  /** Delegating agent SPIFFE ID. */
  iss: string;
  /** Delegatee SPIFFE ID. */
  sub: string;
  /** Delegated scope (must be <= parent). */
  scope: string;
  /** Business intent binding (mandatory). */
  purpose: string;
  /** Data scope binding (mandatory). */
  resourceContext: string;
  /** Initiating human session ID (propagated unchanged). */
  rootSessionId: string;
  /** Optional workflow correlation ID. */
  workflowId?: string;
  /** None at hop 1, previous jti thereafter. */
  parentJti?: string | null;
  /** Current delegation depth (1-indexed). */
  delegationDepth?: number;
  /** Mandatory for Class 4 operations. */
  approvalHash?: string;
  /** Assertion TTL in seconds (max 300). */
  ttlSeconds?: number;
  /** Unique assertion ID. Auto-generated if omitted. */
  jti?: string;
}

/**
 * A single signed delegation assertion for one hop.
 *
 * Fields follow the WIMSE workload identity draft with KSwitch extensions
 * for intent binding (purpose, resource_context), human accountability
 * (root_session_id, approval_hash), and chain binding (parent_jti,
 * delegation_depth).
 */
export class WIMSEAssertion {
  readonly iss: string;
  readonly sub: string;
  readonly scope: string;
  readonly purpose: string;
  readonly resourceContext: string;
  readonly rootSessionId: string;
  readonly workflowId?: string;
  readonly parentJti: string | null;
  readonly delegationDepth: number;
  readonly approvalHash?: string;
  readonly ttlSeconds: number;
  readonly jti: string;

  constructor(fields: WIMSEAssertionFields) {
    this.iss = fields.iss;
    this.sub = fields.sub;
    this.scope = fields.scope;
    this.purpose = fields.purpose;
    this.resourceContext = fields.resourceContext;
    this.rootSessionId = fields.rootSessionId;
    this.workflowId = fields.workflowId;
    this.parentJti = fields.parentJti ?? null;
    this.delegationDepth = fields.delegationDepth ?? 1;
    this.approvalHash = fields.approvalHash;
    this.ttlSeconds = fields.ttlSeconds ?? 300;
    this.jti = fields.jti ?? crypto.randomUUID();
  }

  /**
   * Validate field constraints before signing.
   *
   * @throws {Error} if any field exceeds its maximum length or value.
   */
  validate(): void {
    if (this.purpose.length > MAX_PURPOSE_LEN) {
      throw new Error(`purpose exceeds ${MAX_PURPOSE_LEN} chars`);
    }
    if (this.resourceContext.length > MAX_RESOURCE_CONTEXT_LEN) {
      throw new Error(
        `resource_context exceeds ${MAX_RESOURCE_CONTEXT_LEN} chars`,
      );
    }
    if (this.workflowId && this.workflowId.length > MAX_WORKFLOW_ID_LEN) {
      throw new Error(`workflow_id exceeds ${MAX_WORKFLOW_ID_LEN} chars`);
    }
    if (this.delegationDepth > MAX_CHAIN_DEPTH) {
      throw new Error(
        `delegation_depth ${this.delegationDepth} exceeds max ${MAX_CHAIN_DEPTH}`,
      );
    }
    if (this.ttlSeconds > MAX_ASSERTION_TTL_SECONDS) {
      throw new Error(
        `ttl_seconds exceeds ${MAX_ASSERTION_TTL_SECONDS}s max`,
      );
    }
  }

  /**
   * Sign the assertion and return a compact ES256 JWT.
   *
   * Algorithm: ES256 (ECDSA P-256) -- matches SPIRE default SVID key type.
   * The `privateKeyPem` must be a PEM-encoded PKCS8 EC P-256 private key.
   *
   * @param privateKeyPem - PEM-encoded EC P-256 private key string.
   * @returns Compact JWS string (`header.payload.signature`).
   * @throws {Error} if field validation fails or key is not EC P-256.
   */
  sign(privateKeyPem: string): string {
    this.validate();

    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: "pem",
    });

    // Verify EC P-256
    const keyDetails = privateKey.asymmetricKeyDetails;
    if (
      privateKey.asymmetricKeyType !== "ec" ||
      (keyDetails?.namedCurve !== "prime256v1" &&
        keyDetails?.namedCurve !== "P-256")
    ) {
      throw new TypeError(
        "SVID private key must be EC (P-256) for ES256 signing. " +
          `Got: ${privateKey.asymmetricKeyType}/${keyDetails?.namedCurve}. ` +
          "Do not use Ed25519 -- it is incompatible with ES256.",
      );
    }

    const now = Math.floor(Date.now() / 1000);

    const payload: Record<string, unknown> = {
      // Standard WIMSE fields
      iss: this.iss,
      sub: this.sub,
      iat: now,
      exp: now + this.ttlSeconds,
      jti: this.jti,
      // Chain binding
      parent_jti: this.parentJti,
      delegation_depth: this.delegationDepth,
      // Scope
      scope: this.scope,
      // Intent binding (v0.2 -- mandatory)
      purpose: this.purpose,
      resource_context: this.resourceContext,
      // Human accountability (v0.2 -- mandatory)
      root_session_id: this.rootSessionId,
    };

    // Add optional fields
    if (this.workflowId != null) {
      payload["workflow_id"] = this.workflowId;
    }
    if (this.approvalHash != null) {
      payload["approval_hash"] = this.approvalHash;
    }

    // Manual JWT construction (same pattern as tokens/issuer.ts -- no jose dep)
    const header = { alg: "ES256", typ: "wimse+jwt" };
    const hdrB64 = b64url(JSON.stringify(header));
    const payB64 = b64url(JSON.stringify(payload));
    const signingInput = `${hdrB64}.${payB64}`;

    // Node.js returns DER-encoded ECDSA signature; convert to raw 64-byte r||s
    const derSig = crypto.sign(
      "sha256",
      Buffer.from(signingInput),
      privateKey,
    );
    const rawSig = derToRaw64(derSig);
    const sigB64 = rawSig.toString("base64url");

    return `${hdrB64}.${payB64}.${sigB64}`;
  }
}

// ── WIMSEHopOptions ──────────────────────────────────────────────────────────

export interface WIMSEHopOptions {
  /** SPIFFE ID of the agent receiving delegation. */
  delegateeSpiffeId: string;
  /** Delegated scope string (must be <= parent scope). */
  scope: string;
  /** Business intent binding (mandatory, max 128 chars). */
  purpose: string;
  /** Data scope binding (mandatory, max 256 chars). */
  resourceContext: string;
  /** Initiating human session ID (propagated unchanged). */
  rootSessionId: string;
  /** Optional workflow correlation ID (max 64 chars). */
  workflowId?: string;
  /** Mandatory for Class 4 operations. */
  approvalHash?: string;
  /** Assertion TTL (max 300 seconds). */
  ttlSeconds?: number;
}

// ── WIMSEChainBuilder ────────────────────────────────────────────────────────

/**
 * Builds and manages a delegation chain across multiple hops.
 *
 * Each call to `addHop()` fetches a fresh SVID from the local SPIRE agent,
 * constructs a `WIMSEAssertion`, signs it, and appends the resulting JWT to
 * the chain. The chain is serialized as a space-separated list of JWTs for
 * the `X-WIMSE-Delegation-Chain` HTTP header.
 *
 * @example
 * ```ts
 * const builder = new WIMSEChainBuilder();
 * await builder.addHop({
 *   delegateeSpiffeId: "spiffe://bank.internal/agent/risk",
 *   scope: "payments:read",
 *   purpose: "fraud-check",
 *   resourceContext: "account:123",
 *   rootSessionId: "sess-001",
 * });
 * await builder.addHop({
 *   delegateeSpiffeId: "spiffe://bank.internal/agent/ml",
 *   scope: "payments:read",
 *   purpose: "scoring",
 *   resourceContext: "account:123",
 *   rootSessionId: "sess-001",
 * });
 * headers["X-WIMSE-Delegation-Chain"] = builder.toHeaderValue();
 * ```
 */
export class WIMSEChainBuilder {
  private _chain: string[] = [];
  private _lastJti: string | null = null;
  private _currentDepth: number = 0;

  /** Current chain depth (number of hops added). */
  get depth(): number {
    return this._currentDepth;
  }

  /**
   * Add a delegation hop. Signs with this workload's SVID private key.
   *
   * @param opts - Hop configuration.
   * @returns `this` for chaining.
   * @throws {Error} chain depth exceeded, field validation failure, or
   *   header size exceeded.
   * @throws {SPIREUnavailableError} SPIRE agent socket not available.
   */
  async addHop(opts: WIMSEHopOptions): Promise<this> {
    this._currentDepth += 1;
    if (this._currentDepth > MAX_CHAIN_DEPTH) {
      throw new Error(
        `Chain depth ${this._currentDepth} exceeds maximum ${MAX_CHAIN_DEPTH}`,
      );
    }

    // Atomic fetch: key and ID from the same SVID to avoid rotation race
    const svid = await fetchSvid();

    const assertion = new WIMSEAssertion({
      iss: svid.spiffeId,
      sub: opts.delegateeSpiffeId,
      scope: opts.scope,
      purpose: opts.purpose,
      resourceContext: opts.resourceContext,
      rootSessionId: opts.rootSessionId,
      workflowId: opts.workflowId,
      parentJti: this._lastJti,
      delegationDepth: this._currentDepth,
      approvalHash: opts.approvalHash,
      ttlSeconds: opts.ttlSeconds,
    });

    const signedJwt = assertion.sign(svid.privateKeyPem);
    this._chain.push(signedJwt);
    this._lastJti = assertion.jti;
    return this;
  }

  /**
   * Serialize chain as space-separated JWTs for X-WIMSE-Delegation-Chain.
   *
   * @returns Space-separated JWT string.
   * @throws {Error} if the serialized chain exceeds the 8 KB header limit.
   */
  toHeaderValue(): string {
    const value = this._chain.join(" ");
    if (Buffer.byteLength(value, "utf-8") > MAX_CHAIN_HEADER_BYTES) {
      throw new Error(
        `Chain exceeds ${MAX_CHAIN_HEADER_BYTES} byte header limit`,
      );
    }
    return value;
  }

  /**
   * UNSAFE -- debug / logging only. Decodes without signature verification.
   *
   * Do NOT use decoded payloads for access control or trust decisions.
   * The boundary validator performs real cryptographic verification.
   * Not part of the public SDK API -- prefixed with underscore.
   *
   * @param headerValue - Space-separated JWTs from the delegation chain header.
   * @returns List of decoded JWT payload objects (unverified).
   */
  static _debugDecodeChain(headerValue: string): object[] {
    const tokens = headerValue.split(" ");
    const decoded: object[] = [];
    for (const t of tokens) {
      try {
        const parts = t.split(".");
        if (parts.length !== 3) {
          decoded.push({ _error: "invalid JWT format" });
          continue;
        }
        // Decode payload (second segment) with base64url
        const payloadB64 = parts[1]!;
        // Add padding
        const padding = 4 - (payloadB64.length % 4);
        const padded =
          padding !== 4 ? payloadB64 + "=".repeat(padding) : payloadB64;
        const payloadBytes = Buffer.from(padded, "base64url");
        decoded.push(JSON.parse(payloadBytes.toString("utf-8")) as object);
      } catch (exc) {
        decoded.push({
          _error: exc instanceof Error ? exc.message : String(exc),
        });
      }
    }
    return decoded;
  }
}
