"""SPIRE Workload API integration -- SVID private key retrieval for WIMSE signing.

Key facts:
  - SPIRE issues EC P-256 X.509 SVIDs by default. The private key is therefore
    compatible with ES256 (ECDSA P-256). Never assume Ed25519.
  - The SDK retrieves the private key via gRPC to the SPIRE Agent Workload API
    socket at /run/spiffe/sockets/agent.sock using workload.proto FetchX509SVID.
  - The SDK must NOT cache the private key. Call fetch_svid() on each signing
    operation. SPIRE handles rotation transparently via the socket.
  - Format returned: PEM-encoded PKCS8 EC private key (standard DER-in-PEM).
    Load with: cryptography.hazmat.primitives.serialization.load_pem_private_key()
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

SPIRE_SOCKET_PATH = os.environ.get(
    "SPIRE_SOCKET_PATH", "/run/spiffe/sockets/agent.sock"
)


class SPIREUnavailableError(Exception):
    """Raised when the SPIRE Workload API socket is absent or unreachable."""


@dataclass
class SVIDBundle:
    """Result from a single SPIRE FetchX509SVID RPC -- key and ID are atomic."""

    private_key_pem: bytes  # PEM-encoded PKCS8 EC P-256 private key
    spiffe_id: str          # URI SAN, e.g. "spiffe://bank.internal/agent/payments"


def fetch_svid() -> SVIDBundle:
    """Retrieve this workload's SVID private key AND SPIFFE ID in a single RPC.

    CRITICAL: Key and ID must come from the same SVID to avoid a race condition
    where SPIRE rotates the SVID between two separate RPC calls. If you call
    get_svid_private_key() and get_spiffe_id() separately, the key may belong
    to the old SVID while the ID belongs to the new one -- producing a JWT
    whose ``iss`` claim does not match the signing key. The boundary validator
    will reject this with "signature verification failed."

    Protocol:
      1. Open gRPC channel to unix:///run/spiffe/sockets/agent.sock
      2. Call workload.SpiffeWorkloadAPI/FetchX509SVID (unary RPC)
         -- header: workload.spiffe.io = true
      3. Response: X509SVIDResponse containing repeated X509SVID messages
      4. Take svid_list[0] (first SVID -- the default workload identity)
      5. Extract x509_svid_key (DER-encoded PKCS8 private key) AND spiffe_id

    Returns:
        SVIDBundle with PEM-encoded key and SPIFFE ID string.

    Raises:
        SPIREUnavailableError: socket absent, SPIRE agent not running, or RPC
        failed. Do NOT catch this silently -- propagate it. A missing SPIRE
        socket means this workload has no identity and cannot sign delegation
        assertions.
    """
    if not os.path.exists(SPIRE_SOCKET_PATH):
        raise SPIREUnavailableError(
            f"SPIRE Workload API socket not found at {SPIRE_SOCKET_PATH}. "
            f"Ensure the SPIRE Agent DaemonSet is running and the socket is mounted."
        )

    try:
        import grpc  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SPIREUnavailableError(
            "grpcio is not installed. Install it with: pip install grpcio"
        ) from exc

    try:
        channel = grpc.secure_channel(
            f"unix://{SPIRE_SOCKET_PATH}",
            grpc.local_channel_credentials(),
        )
    except Exception as exc:
        raise SPIREUnavailableError(
            f"Failed to open gRPC channel to {SPIRE_SOCKET_PATH}: {exc}"
        ) from exc

    try:
        from spire.proto.workload import (  # type: ignore[import-untyped]
            workload_pb2,
            workload_pb2_grpc,
        )
    except ImportError as exc:
        raise SPIREUnavailableError(
            "SPIRE protobuf stubs not available. "
            "Install spire-api with: pip install spire-api"
        ) from exc

    try:
        stub = workload_pb2_grpc.SpiffeWorkloadAPIStub(channel)
        response = stub.FetchX509SVID(
            workload_pb2.X509SVIDRequest(),
            metadata=[("workload.spiffe.io", "true")],
            timeout=5.0,
        )
        svid = response.svids[0]

        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            load_der_private_key,
        )

        private_key = load_der_private_key(svid.x509_svid_key, password=None)
        private_key_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

        return SVIDBundle(private_key_pem=private_key_pem, spiffe_id=svid.spiffe_id)

    except Exception as exc:
        if "RpcError" in type(exc).__name__:
            raise SPIREUnavailableError(
                f"SPIRE FetchX509SVID RPC failed: {exc}"
            ) from exc
        raise SPIREUnavailableError(
            f"SPIRE SVID retrieval failed: {exc}"
        ) from exc


def get_svid_private_key() -> bytes:
    """Convenience wrapper -- returns only the private key PEM.

    Prefer :func:`fetch_svid` for WIMSE signing to avoid rotation race.
    """
    return fetch_svid().private_key_pem


def get_spiffe_id() -> str:
    """Convenience wrapper -- returns only the SPIFFE ID.

    Prefer :func:`fetch_svid` for WIMSE signing to avoid rotation race.
    """
    return fetch_svid().spiffe_id
