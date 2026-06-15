/**
 * KSwitch TypeScript SDK — Execution Token Issuer.
 *
 * Issues ES256-signed JWTs on ALLOW decisions in the SDK interceptor path.
 * Uses Node.js built-in `node:crypto` — zero external dependencies.
 * Startup fails hard on bad key config.
 *
 * @example
 * ```ts
 * const issuer = KSwitchTokenIssuer.fromEnv();
 * const token = issuer.issue(decision, {
 *   agentId: "agent:fraud-detector@bank",
 *   mcpServerId: "mcp:crm@bank",
 *   toolName: "read_customer",
 * });
 * ```
 */

import * as crypto from "node:crypto";

// ── TTL by risk tier (seconds) ────────────────────────────────────────────────

const TTL_BY_TIER: Record<string, number> = {
  critical: 10,
  high: 20,
  medium: 45,
  low: 90,
};

const DEFAULT_SINGLE_USE_CLASSES = new Set([
  "payment",
  "admin",
  "data_export",
  "human_approval",
]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function b64url(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}

function classifyAction(action: string): string {
  const a = action.toLowerCase();
  if (/pay|transfer|charge|financial|fund|debit|credit/.test(a)) return "payment";
  if (/admin|sudo|privilege|root|grant_role/.test(a)) return "admin";
  if (/export|download|extract|dump|transfer_data/.test(a)) return "data_export";
  if (/approve|authorize|human_approval|release/.test(a)) return "human_approval";
  return "";
}

// ── Issuer ────────────────────────────────────────────────────────────────────

export interface IssuerDecision {
  risk_tier?: string;
  trace_id?: string;
  id?: string;
  decision_id?: string;
  policy_ids_matched?: string[];
  bundle_version?: string;
  context_pack_id?: string;
  revocation_version?: string;
  [key: string]: unknown;
}

export interface IssueOptions {
  agentId: string;
  mcpServerId: string;
  toolName: string;
  context?: Record<string, unknown>;
}

export class KSwitchTokenIssuer {
  private readonly privateKey: crypto.KeyObject;

  constructor(
    private readonly privateKeyPem: string,
    private readonly kid: string,
    private readonly issuer: string = "kswitch",
    private readonly audience: string = "kswitch-control-plane",
    private readonly defaultTtl: number = 30,
    private readonly singleUseClasses: Set<string> = DEFAULT_SINGLE_USE_CLASSES,
  ) {
    try {
      this.privateKey = crypto.createPrivateKey({
        key: privateKeyPem.replace(/\\n/g, "\n"),
        format: "pem",
      });
    } catch (err) {
      throw new Error(`KSwitchTokenIssuer: bad signing key — ${err}`);
    }

    // Verify EC P-256
    const keyDetails = this.privateKey.asymmetricKeyDetails;
    if (
      this.privateKey.asymmetricKeyType !== "ec" ||
      (keyDetails?.namedCurve !== "prime256v1" && keyDetails?.namedCurve !== "P-256")
    ) {
      throw new Error("KSwitchTokenIssuer: signing key must be EC P-256 (ES256)");
    }
  }

  static fromEnv(): KSwitchTokenIssuer {
    const key = process.env["KSWITCH_EXECUTION_TOKEN_SIGNING_KEY"] ?? "";
    if (!key) {
      throw new Error("KSWITCH_EXECUTION_TOKEN_SIGNING_KEY not set");
    }
    const suRaw =
      process.env["KSWITCH_EXECUTION_TOKEN_SINGLE_USE_CLASSES"] ??
      "payment,admin,data_export,human_approval";
    return new KSwitchTokenIssuer(
      key,
      process.env["KSWITCH_EXECUTION_TOKEN_KID"] ?? "default",
      process.env["KSWITCH_EXECUTION_TOKEN_ISSUER"] ?? "kswitch",
      process.env["KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE"] ?? "kswitch-control-plane",
      parseInt(process.env["KSWITCH_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS"] ?? "30", 10),
      new Set(suRaw.split(",").map((s) => s.trim()).filter(Boolean)),
    );
  }

  /** Issue a signed ES256 JWT for an ALLOW decision. */
  issue(decision: IssuerDecision, opts: IssueOptions): string {
    const { agentId, mcpServerId, toolName, context } = opts;
    const now = Math.floor(Date.now() / 1000);
    const riskTier = ((decision["risk_tier"] as string | undefined) ?? "low").toLowerCase();
    const ttl = TTL_BY_TIER[riskTier] ?? this.defaultTtl;
    const actionClass = classifyAction(toolName);
    const singleUse = this.singleUseClasses.has(actionClass);

    const claims: Record<string, unknown> = {
      iss: this.issuer,
      sub: agentId,
      aud: this.audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + ttl,
      nbf: now,
      trace_id: (decision["trace_id"] as string | undefined) ?? crypto.randomUUID(),
      decision_id:
        (decision["id"] as string | undefined) ??
        (decision["decision_id"] as string | undefined) ??
        crypto.randomUUID(),
      policy_id:
        ((decision["policy_ids_matched"] as string[] | undefined)?.[0]) ?? "unknown",
      bundle_version: (decision["bundle_version"] as string | undefined) ?? "0",
      context_pack_id: (decision["context_pack_id"] as string | undefined) ?? "default",
      action: toolName,
      resource: mcpServerId,
      risk_tier: riskTier,
      revocation_version: (decision["revocation_version"] as string | undefined) ?? "0",
      sdk_language: "typescript",
    };

    // req_hash for CRITICAL and HIGH
    if (riskTier === "critical" || riskTier === "high") {
      const reqParams: Record<string, unknown> = {
        agent_id: agentId,
        mcp_server_id: mcpServerId,
        tool_name: toolName,
      };
      if (context) reqParams["context"] = context;
      const canonical = JSON.stringify(
        Object.fromEntries(Object.entries(reqParams).sort()),
      );
      claims["req_hash"] = crypto
        .createHash("sha256")
        .update(canonical)
        .digest("hex");
    }

    if (singleUse) {
      claims["single_use"] = true;
    }

    // Sign
    const header = { alg: "ES256", kid: this.kid, typ: "JWT" };
    const hdrB64 = b64url(JSON.stringify(header));
    const payB64 = b64url(JSON.stringify(claims));
    const signingInput = `${hdrB64}.${payB64}`;

    // Node.js returns DER-encoded ECDSA signature; convert to raw 64-byte r||s
    const derSig = crypto.sign("sha256", Buffer.from(signingInput), this.privateKey);
    const rawSig = derToRaw64(derSig);
    const sigB64 = rawSig.toString("base64url");

    return `${hdrB64}.${payB64}.${sigB64}`;
  }

  /** Return JWKS containing the public key for this issuer. */
  getJwks(): { keys: object[] } {
    const pubKey = crypto.createPublicKey(this.privateKey);
    const jwk = pubKey.export({ format: "jwk" }) as {
      kty: string;
      crv: string;
      x: string;
      y: string;
    };
    return {
      keys: [
        {
          kty: jwk.kty,
          crv: jwk.crv,
          x: jwk.x,
          y: jwk.y,
          kid: this.kid,
          use: "sig",
          alg: "ES256",
        },
      ],
    };
  }
}

// ── DER → raw 64-byte ECDSA signature ────────────────────────────────────────

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
  let r = der.slice(offset, offset + rLen);
  offset += rLen;
  if (r[0] === 0x00) r = r.slice(1); // strip leading zero byte

  // s
  offset++; // 0x02
  const sLen = der[offset++]!;
  let s = der.slice(offset, offset + sLen);
  if (s[0] === 0x00) s = s.slice(1);

  // Pad to 32 bytes each
  const out = Buffer.alloc(64, 0);
  r.copy(out, 32 - r.length);
  s.copy(out, 64 - s.length);
  return out;
}
