"""KSwitch Python SDK — Execution Token Issuer.

Issues ES256-signed JWTs on ALLOW decisions in the SDK interceptor path.
Sync + async compatible. Startup fails hard on bad key config.

Usage::

    issuer = KSwitchTokenIssuer.from_env()
    token = issuer.issue(decision, request)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Optional

logger = logging.getLogger(__name__)

_TTL_BY_TIER: dict[str, int] = {
    "critical": 10,
    "high": 20,
    "medium": 45,
    "low": 90,
}

_SINGLE_USE_CLASSES = frozenset({"payment", "admin", "data_export", "human_approval"})


class KSwitchTokenIssuer:
    """ES256 JWT issuer for the KSwitch Python SDK."""

    def __init__(
        self,
        private_key_pem: str,
        kid: str,
        issuer: str = "kswitch",
        audience: str = "kswitch-control-plane",
        default_ttl: int = 30,
        single_use_classes: Optional[frozenset] = None,
    ) -> None:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = private_key_pem.replace("\\n", "\n").encode()
        try:
            self._key = load_pem_private_key(pem, password=None)
        except Exception as exc:
            raise RuntimeError(f"KSwitchTokenIssuer: bad signing key — {exc}") from exc

        if not isinstance(self._key, ec.EllipticCurvePrivateKey):
            raise RuntimeError("KSwitchTokenIssuer: signing key must be EC P-256 (ES256)")

        self._kid = kid
        self._issuer = issuer
        self._audience = audience
        self._default_ttl = default_ttl
        self._single_use = single_use_classes or _SINGLE_USE_CLASSES

    @classmethod
    def from_env(cls) -> "KSwitchTokenIssuer":
        """Construct from environment variables. Raises RuntimeError on missing config."""
        key = os.environ.get("KSWITCH_EXECUTION_TOKEN_SIGNING_KEY", "")
        if not key:
            raise RuntimeError("KSWITCH_EXECUTION_TOKEN_SIGNING_KEY not set")
        su_raw = os.environ.get(
            "KSWITCH_EXECUTION_TOKEN_SINGLE_USE_CLASSES",
            "payment,admin,data_export,human_approval",
        )
        return cls(
            private_key_pem=key,
            kid=os.environ.get("KSWITCH_EXECUTION_TOKEN_KID", "default"),
            issuer=os.environ.get("KSWITCH_EXECUTION_TOKEN_ISSUER", "kswitch"),
            audience=os.environ.get("KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE", "kswitch-control-plane"),
            default_ttl=int(os.environ.get("KSWITCH_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS", "30")),
            single_use_classes=frozenset(c.strip() for c in su_raw.split(",") if c.strip()),
        )

    def issue(
        self,
        decision: Any,
        *,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str,
        context: Optional[dict] = None,
    ) -> str:
        """Issue a signed ES256 JWT for an ALLOW decision.

        Works synchronously — safe to call from both sync and async code.
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        # Extract decision attributes (works for dict or Pydantic model)
        def _get(obj: Any, attr: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(attr, default)
            return getattr(obj, attr, default)

        now = int(time.time())
        risk_tier = (_get(decision, "risk_tier") or "low").lower()
        ttl = _TTL_BY_TIER.get(risk_tier, self._default_ttl)
        action_class = _classify_action(tool_name)
        single_use = action_class in self._single_use

        claims: dict[str, Any] = {
            "iss": self._issuer,
            "sub": agent_id,
            "aud": self._audience,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + ttl,
            "nbf": now,
            "trace_id": _get(decision, "trace_id") or str(uuid.uuid4()),
            "decision_id": _get(decision, "id") or _get(decision, "decision_id") or str(uuid.uuid4()),
            "policy_id": (_get(decision, "policy_ids_matched") or ["unknown"])[0],
            "bundle_version": _get(decision, "bundle_version") or "0",
            "context_pack_id": _get(decision, "context_pack_id") or "default",
            "action": tool_name,
            "resource": mcp_server_id,
            "risk_tier": risk_tier,
            "revocation_version": _get(decision, "revocation_version") or "0",
            "sdk_language": "python",
        }

        # req_hash for CRITICAL and HIGH
        if risk_tier in ("critical", "high"):
            req_params = {"agent_id": agent_id, "mcp_server_id": mcp_server_id, "tool_name": tool_name}
            if context:
                req_params["context"] = context
            canonical = json.dumps(req_params, separators=(",", ":"), sort_keys=True)
            claims["req_hash"] = hashlib.sha256(canonical.encode()).hexdigest()

        if single_use:
            claims["single_use"] = True

        # Sign
        header = {"alg": "ES256", "kid": self._kid, "typ": "JWT"}
        hdr_b64 = _b64url(json.dumps(header, separators=(",", ":")))
        pay_b64 = _b64url(json.dumps(claims, separators=(",", ":")))
        signing_input = f"{hdr_b64}.{pay_b64}".encode()
        der_sig = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        return f"{hdr_b64}.{pay_b64}.{sig_b64}"


def _b64url(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _classify_action(action: str) -> str:
    a = action.lower()
    if any(k in a for k in ("pay", "transfer", "charge", "financial", "fund", "debit", "credit")):
        return "payment"
    if any(k in a for k in ("admin", "sudo", "privilege", "root", "grant_role")):
        return "admin"
    if any(k in a for k in ("export", "download", "extract", "dump", "transfer_data")):
        return "data_export"
    if any(k in a for k in ("approve", "authorize", "human_approval", "release")):
        return "human_approval"
    return ""
