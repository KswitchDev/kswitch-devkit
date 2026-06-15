/**
 * SPIRE Workload API integration -- SVID private key retrieval for WIMSE signing.
 *
 * Key facts:
 *   - SPIRE issues EC P-256 X.509 SVIDs by default. The private key is therefore
 *     compatible with ES256 (ECDSA P-256). Never assume Ed25519.
 *   - The SDK retrieves the private key via gRPC to the SPIRE Agent Workload API
 *     socket at /run/spiffe/sockets/agent.sock using workload.proto FetchX509SVID.
 *   - The SDK must NOT cache the private key. Call fetchSvid() on each signing
 *     operation. SPIRE handles rotation transparently via the socket.
 *   - Format returned: PEM-encoded PKCS8 EC private key (standard DER-in-PEM).
 */

import * as fs from "node:fs";

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_SPIRE_SOCKET = "/run/spiffe/sockets/agent.sock";

const SPIRE_SOCKET_PATH =
  process.env["SPIFFE_ENDPOINT_SOCKET"]?.replace(/^unix:\/\//, "") ??
  DEFAULT_SPIRE_SOCKET;

// ── Errors ───────────────────────────────────────────────────────────────────

export class SPIREUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SPIREUnavailableError";
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface SVIDBundle {
  /** PEM-encoded PKCS8 EC P-256 private key. */
  privateKeyPem: string;
  /** URI SAN, e.g. "spiffe://bank.internal/agent/payments". */
  spiffeId: string;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Retrieve this workload's SVID private key AND SPIFFE ID in a single call.
 *
 * CRITICAL: Key and ID must come from the same SVID to avoid a race condition
 * where SPIRE rotates the SVID between two separate calls. If you fetch key
 * and ID separately, the key may belong to the old SVID while the ID belongs
 * to the new one -- producing a JWT whose `iss` claim does not match the
 * signing key. The boundary validator will reject this with
 * "signature verification failed."
 *
 * Protocol:
 *   1. Open gRPC channel to unix:///run/spiffe/sockets/agent.sock
 *   2. Call workload.SpiffeWorkloadAPI/FetchX509SVID (unary RPC)
 *   3. Extract private key (PEM) and spiffe_id from first SVID
 *
 * @throws {SPIREUnavailableError} socket absent, SPIRE agent not running,
 *   or RPC failed. Do NOT catch this silently -- propagate it.
 */
export async function fetchSvid(): Promise<SVIDBundle> {
  if (!fs.existsSync(SPIRE_SOCKET_PATH)) {
    throw new SPIREUnavailableError(
      `SPIRE Workload API socket not found at ${SPIRE_SOCKET_PATH}. ` +
        `Ensure the SPIRE Agent DaemonSet is running and the socket is mounted.`,
    );
  }

  // In production this would use @grpc/grpc-js to call FetchX509SVID.
  // For now, throw so callers know SPIRE gRPC is not yet wired.
  throw new SPIREUnavailableError(
    "SPIRE gRPC client not yet implemented in TypeScript SDK. " +
      "Use mock in tests or provide SVIDBundle directly.",
  );
}
