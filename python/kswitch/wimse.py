"""WIMSE delegation assertion builder.

Implements draft-ietf-wimse-workload-identity-02 with KSwitch extensions.

Signing algorithm: ES256 (ECDSA P-256) universally across all three SDKs,
the JWKS registry, and the boundary validator. SPIRE issues EC P-256 SVIDs
by default. Do NOT import Ed25519PrivateKey -- Ed25519 is incompatible with
ES256 and will produce JWTs that fail verification at the boundary validator.

Usage::

    from kswitch.wimse import WIMSEChainBuilder

    chain = WIMSEChainBuilder()
    chain.add_hop(
        delegatee_spiffe_id="spiffe://bank.internal/agent/risk-engine",
        scope="payments:read",
        purpose="fraud-check",
        resource_context="account:123456",
        root_session_id="sess-abc-123",
    )
    header_value = chain.to_header_value()
    # Attach as: X-WIMSE-Delegation-Chain: <header_value>
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Field length limits (enforced before signing) ─────────────────────────────

MAX_PURPOSE_LEN = 128
MAX_RESOURCE_CONTEXT_LEN = 256
MAX_WORKFLOW_ID_LEN = 64
MAX_CHAIN_DEPTH = 3
MAX_ASSERTION_TTL_SECONDS = 300   # 5 minutes hard max
MAX_CHAIN_HEADER_BYTES = 8192     # 8 KB HTTP header limit


# ── WIMSEAssertion ────────────────────────────────────────────────────────────


@dataclass
class WIMSEAssertion:
    """A single signed delegation assertion for one hop.

    Fields follow the WIMSE workload identity draft with KSwitch extensions
    for intent binding (purpose, resource_context), human accountability
    (root_session_id, approval_hash), and chain binding (parent_jti,
    delegation_depth).
    """

    iss: str                                    # delegating agent SPIFFE ID
    sub: str                                    # delegatee SPIFFE ID
    scope: str                                  # delegated scope (must be <= parent)
    purpose: str                                # business intent binding (mandatory)
    resource_context: str                       # data scope binding (mandatory)
    root_session_id: str                        # initiating human session (propagated unchanged)
    workflow_id: Optional[str] = None
    parent_jti: Optional[str] = None            # None at hop 1
    delegation_depth: int = 1
    approval_hash: Optional[str] = None         # mandatory for Class 4
    ttl_seconds: int = 300
    jti: str = field(default_factory=lambda: str(uuid.uuid4()))

    def validate(self) -> None:
        """Validate field constraints before signing.

        Raises:
            ValueError: if any field exceeds its maximum length or value.
        """
        if len(self.purpose) > MAX_PURPOSE_LEN:
            raise ValueError(f"purpose exceeds {MAX_PURPOSE_LEN} chars")
        if len(self.resource_context) > MAX_RESOURCE_CONTEXT_LEN:
            raise ValueError(f"resource_context exceeds {MAX_RESOURCE_CONTEXT_LEN} chars")
        if self.workflow_id and len(self.workflow_id) > MAX_WORKFLOW_ID_LEN:
            raise ValueError(f"workflow_id exceeds {MAX_WORKFLOW_ID_LEN} chars")
        if self.delegation_depth > MAX_CHAIN_DEPTH:
            raise ValueError(
                f"delegation_depth {self.delegation_depth} exceeds max {MAX_CHAIN_DEPTH}"
            )
        if self.ttl_seconds > MAX_ASSERTION_TTL_SECONDS:
            raise ValueError(f"ttl_seconds exceeds {MAX_ASSERTION_TTL_SECONDS}s max")

    def sign(self, private_key_pem: bytes) -> str:
        """Sign the assertion and return a compact ES256 JWT.

        Algorithm: ES256 (ECDSA P-256) -- matches SPIRE default SVID key type.
        The *private_key_pem* must be a PEM-encoded PKCS8 EC P-256 private key
        as returned by :func:`~kswitch.spire.get_svid_private_key`. Any other
        key type will raise.

        Args:
            private_key_pem: PEM-encoded EC P-256 private key bytes.

        Returns:
            Compact JWS string (``header.payload.signature``).

        Raises:
            ValueError: if field validation fails.
            TypeError: if the key is not an EC private key.
        """
        self.validate()

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        now = int(time.time())
        payload = {
            # Standard WIMSE fields
            "iss": self.iss,
            "sub": self.sub,
            "iat": now,
            "exp": now + self.ttl_seconds,
            "jti": self.jti,
            # Chain binding
            "parent_jti": self.parent_jti,
            "delegation_depth": self.delegation_depth,
            # Scope
            "scope": self.scope,
            # Intent binding (v0.2 -- mandatory)
            "purpose": self.purpose,
            "resource_context": self.resource_context,
            "workflow_id": self.workflow_id,
            # Human accountability (v0.2 -- mandatory)
            "root_session_id": self.root_session_id,
            "approval_hash": self.approval_hash,
        }
        # Remove None values except parent_jti (null at hop 1 is meaningful)
        payload = {
            k: v for k, v in payload.items() if v is not None or k == "parent_jti"
        }

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"SVID private key must be EC (P-256) for ES256 signing. "
                f"Got: {type(private_key).__name__}. "
                f"Do not use Ed25519PrivateKey -- it is incompatible with ES256."
            )

        # Manual JWT construction (same pattern as tokens/issuer.py -- no PyJWT dep)
        header = {"alg": "ES256", "typ": "wimse+jwt"}
        hdr_b64 = _b64url(json.dumps(header, separators=(",", ":")))
        pay_b64 = _b64url(json.dumps(payload, separators=(",", ":")))
        signing_input = f"{hdr_b64}.{pay_b64}".encode()

        der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        return f"{hdr_b64}.{pay_b64}.{sig_b64}"


# ── WIMSEChainBuilder ─────────────────────────────────────────────────────────


class WIMSEChainBuilder:
    """Builds and manages a delegation chain across multiple hops.

    Each call to :meth:`add_hop` fetches a fresh SVID from the local SPIRE
    agent, constructs a :class:`WIMSEAssertion`, signs it, and appends the
    resulting JWT to the chain. The chain is serialized as a space-separated
    list of JWTs for the ``X-WIMSE-Delegation-Chain`` HTTP header.

    Usage::

        builder = WIMSEChainBuilder()
        builder.add_hop(
            delegatee_spiffe_id="spiffe://bank.internal/agent/risk",
            scope="payments:read",
            purpose="fraud-check",
            resource_context="account:123",
            root_session_id="sess-001",
        )
        builder.add_hop(
            delegatee_spiffe_id="spiffe://bank.internal/agent/ml",
            scope="payments:read",
            purpose="scoring",
            resource_context="account:123",
            root_session_id="sess-001",
        )
        headers["X-WIMSE-Delegation-Chain"] = builder.to_header_value()
    """

    def __init__(self) -> None:
        self._chain: list[str] = []
        self._last_jti: Optional[str] = None
        self._current_depth: int = 0

    @property
    def depth(self) -> int:
        """Current chain depth (number of hops added)."""
        return self._current_depth

    def add_hop(
        self,
        delegatee_spiffe_id: str,
        scope: str,
        purpose: str,
        resource_context: str,
        root_session_id: str,
        workflow_id: Optional[str] = None,
        approval_hash: Optional[str] = None,
        ttl_seconds: int = 300,
    ) -> WIMSEChainBuilder:
        """Add a delegation hop. Signs with this workload's SVID private key.

        Args:
            delegatee_spiffe_id: SPIFFE ID of the agent receiving delegation.
            scope: Delegated scope string (must be <= parent scope).
            purpose: Business intent binding (mandatory, max 128 chars).
            resource_context: Data scope binding (mandatory, max 256 chars).
            root_session_id: Initiating human session ID (propagated unchanged).
            workflow_id: Optional workflow correlation ID (max 64 chars).
            approval_hash: Mandatory for Class 4 operations.
            ttl_seconds: Assertion TTL (max 300 seconds).

        Returns:
            ``self`` for chaining.

        Raises:
            ValueError: chain depth exceeded, field validation failure, or
                header size exceeded.
            SPIREUnavailableError: SPIRE agent socket not available.
        """
        from .spire import fetch_svid

        self._current_depth += 1
        if self._current_depth > MAX_CHAIN_DEPTH:
            raise ValueError(
                f"Chain depth {self._current_depth} exceeds maximum {MAX_CHAIN_DEPTH}"
            )

        # Atomic fetch: key and ID from the same SVID to avoid rotation race
        svid = fetch_svid()

        assertion = WIMSEAssertion(
            iss=svid.spiffe_id,
            sub=delegatee_spiffe_id,
            scope=scope,
            purpose=purpose,
            resource_context=resource_context,
            root_session_id=root_session_id,
            workflow_id=workflow_id,
            parent_jti=self._last_jti,
            delegation_depth=self._current_depth,
            approval_hash=approval_hash,
            ttl_seconds=ttl_seconds,
        )

        signed_jwt = assertion.sign(svid.private_key_pem)
        self._chain.append(signed_jwt)
        self._last_jti = assertion.jti
        return self

    def to_header_value(self) -> str:
        """Serialize chain as space-separated JWTs for X-WIMSE-Delegation-Chain.

        Returns:
            Space-separated JWT string.

        Raises:
            ValueError: if the serialized chain exceeds the 8 KB header limit.
        """
        value = " ".join(self._chain)
        if len(value.encode("utf-8")) > MAX_CHAIN_HEADER_BYTES:
            raise ValueError(
                f"Chain exceeds {MAX_CHAIN_HEADER_BYTES} byte header limit"
            )
        return value

    @staticmethod
    def _debug_decode_chain(header_value: str) -> list[dict]:
        """UNSAFE -- debug / logging only. Decodes without signature verification.

        Do NOT use decoded payloads for access control or trust decisions.
        The boundary validator performs real cryptographic verification.
        Not part of the public SDK API -- prefixed with underscore.

        Args:
            header_value: Space-separated JWTs from the delegation chain header.

        Returns:
            List of decoded JWT payload dicts (unverified).
        """
        tokens = header_value.split(" ")
        decoded = []
        for t in tokens:
            try:
                parts = t.split(".")
                if len(parts) != 3:
                    decoded.append({"_error": "invalid JWT format"})
                    continue
                # Decode payload (second segment)
                payload_b64 = parts[1]
                # Add padding
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload_bytes = base64.urlsafe_b64decode(payload_b64)
                decoded.append(json.loads(payload_bytes))
            except Exception as exc:
                decoded.append({"_error": str(exc)})
        return decoded


# ── Helpers ───────────────────────────────────────────────────────────────────


def _b64url(data: str | bytes) -> str:
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
