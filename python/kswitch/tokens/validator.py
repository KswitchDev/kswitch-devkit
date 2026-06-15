"""KSwitch Python SDK — Execution Token Validator (Phase 1 service-library).

Enforces all ten required checks (design spec Section 11.3).
Uses a local JWKS cache at KSWITCH_STATE_DIR/jwks/current.json.
Maintains an independent disk-backed replay cache at KSWITCH_STATE_DIR/replay_cache/.

Usage::

    validator = KSwitchTokenValidator.from_env()
    result = validator.validate(token, action="read_customer", resource="mcp:crm@bank")
    if not result.valid:
        raise RuntimeError(result.error_code)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

_TOLERANCE_SECONDS = 30
_GRACE_SECONDS = 5


@dataclass
class ValidationResult:
    valid: bool
    error_code: Optional[str] = None
    claims: Optional[dict] = None
    jti: Optional[str] = None


class KSwitchTokenValidator:
    """Validates ES256 execution tokens with offline JWKS and replay cache."""

    def __init__(
        self,
        *,
        jwks_url: Optional[str] = None,
        jwks_cache_path: Optional[str] = None,
        expected_issuer: str = "kswitch",
        expected_audience: str = "kswitch-control-plane",
        replay_cache_dir: Optional[str] = None,
        replay_cache_enabled: bool = True,
    ) -> None:
        self._jwks_url = jwks_url
        state_dir = os.environ.get("KSWITCH_STATE_DIR", os.path.expanduser("~/.kswitch/state"))
        self._jwks_cache_path = Path(jwks_cache_path or os.path.join(state_dir, "jwks", "current.json"))
        self._jwks_cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._replay_enabled = replay_cache_enabled
        self._public_keys: dict[str, Any] = {}
        self._lock = threading.Lock()

        # Replay cache (independent of boundary cache — different dir)
        if replay_cache_enabled:
            cache_dir = replay_cache_dir or os.path.join(state_dir, "replay_cache")
            self._replay_path = Path(cache_dir) / "replay_cache.json"
            self._replay_path.parent.mkdir(parents=True, exist_ok=True)
            self._replay_store: dict[str, float] = {}
            self._replay_lock = threading.Lock()
            self._load_replay_cache()
        else:
            self._replay_path = None
            self._replay_store = {}
            self._replay_lock = threading.Lock()

        self._load_jwks()

    @classmethod
    def from_env(cls) -> "KSwitchTokenValidator":
        state_dir = os.environ.get("KSWITCH_STATE_DIR", os.path.expanduser("~/.kswitch/state"))
        return cls(
            jwks_url=os.environ.get("KSWITCH_EXECUTION_TOKEN_JWKS_URL"),
            jwks_cache_path=os.path.join(state_dir, "jwks", "current.json"),
            expected_issuer=os.environ.get("KSWITCH_EXECUTION_TOKEN_EXPECTED_ISSUER", "kswitch"),
            expected_audience=os.environ.get("KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE", "kswitch-control-plane"),
            replay_cache_dir=os.path.join(state_dir, "replay_cache"),
            replay_cache_enabled=os.environ.get("KSWITCH_EXECUTION_TOKEN_REPLAY_CACHE_ENABLED", "true").lower() == "true",
        )

    def validate(
        self,
        token: str,
        *,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        request_params: Optional[dict] = None,
    ) -> ValidationResult:
        """Validate token against all ten required checks."""
        if not token:
            return ValidationResult(valid=False, error_code="execution_token_missing")

        # Decode header to get kid
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return ValidationResult(valid=False, error_code="execution_token_invalid_signature")
            header = json.loads(_b64url_decode(parts[0]))
            kid = header.get("kid")
        except Exception:
            return ValidationResult(valid=False, error_code="execution_token_invalid_signature")

        # Check 2: kid known
        with self._lock:
            if kid not in self._public_keys:
                self._refresh_jwks()
                if kid not in self._public_keys:
                    return ValidationResult(valid=False, error_code="execution_token_unknown_kid")
            pub_key = self._public_keys[kid]

        # Check 1: Signature valid
        try:
            _verify_es256(parts[0], parts[1], parts[2], pub_key)
        except Exception:
            return ValidationResult(valid=False, error_code="execution_token_invalid_signature")

        # Decode payload
        try:
            claims = json.loads(_b64url_decode(parts[1]))
        except Exception:
            return ValidationResult(valid=False, error_code="execution_token_invalid_signature")

        jti = claims.get("jti")
        now = time.time()

        # Check 3: Issuer
        if claims.get("iss") != self._expected_issuer:
            return ValidationResult(valid=False, error_code="execution_token_unknown_kid", jti=jti)

        # Check 4: Audience
        aud = claims.get("aud")
        aud_ok = self._expected_audience in aud if isinstance(aud, list) else aud == self._expected_audience
        if not aud_ok:
            return ValidationResult(valid=False, error_code="execution_token_wrong_audience", jti=jti)

        # Check 5: Not expired
        if claims.get("exp", 0) < now:
            return ValidationResult(valid=False, error_code="execution_token_expired", jti=jti)

        # Check 6: Not before
        if claims.get("nbf", 0) > now + _TOLERANCE_SECONDS:
            return ValidationResult(valid=False, error_code="execution_token_not_yet_valid", jti=jti)

        # Check 7: Action matches
        if action is not None and claims.get("action") != action:
            return ValidationResult(valid=False, error_code="execution_token_action_mismatch", jti=jti)

        # Check 8: Resource matches
        if resource is not None and claims.get("resource") != resource:
            return ValidationResult(valid=False, error_code="execution_token_resource_mismatch", jti=jti)

        # Check 9: req_hash
        if "req_hash" in claims and request_params is not None:
            canonical = json.dumps(
                {k: v for k, v in sorted(request_params.items())},
                separators=(",", ":"), sort_keys=True,
            )
            if claims["req_hash"] != hashlib.sha256(canonical.encode()).hexdigest():
                return ValidationResult(valid=False, error_code="execution_token_request_mismatch", jti=jti)

        # Check 10: Replay
        if claims.get("single_use") and jti and self._replay_enabled:
            with self._replay_lock:
                self._evict_replay()
                if jti in self._replay_store:
                    return ValidationResult(valid=False, error_code="execution_token_replay_detected", jti=jti)
                self._replay_store[jti] = float(claims.get("exp", now + 30)) + _GRACE_SECONDS
                self._save_replay_cache()

        return ValidationResult(valid=True, claims=claims, jti=jti)

    # ── JWKS ──────────────────────────────────────────────────────────────────

    def _load_jwks(self) -> None:
        if self._jwks_cache_path.exists():
            try:
                jwks = json.loads(self._jwks_cache_path.read_text())
                self._public_keys = _parse_jwks(jwks)
                return
            except Exception as exc:
                logger.warning("SDK validator JWKS cache load failed: %s", exc)
        self._refresh_jwks()

    def _refresh_jwks(self) -> None:
        if not self._jwks_url:
            return
        try:
            # EP-025: TLS verification — use CA file if available, enforce in production
            _ca = os.environ.get("KSWITCH_CA_FILE", "")
            if _ca and os.path.exists(_ca):
                _verify_tls = _ca
            elif os.environ.get("KSWITCH_ENV") == "production":
                _verify_tls = True  # Use system CA bundle in production
            else:
                import logging as _log
                _log.getLogger("kswitch.tls").warning("SDK JWKS fetch: TLS verification disabled (dev)")
                _verify_tls = False
            resp = httpx.get(self._jwks_url, timeout=3, verify=_verify_tls)
            resp.raise_for_status()
            jwks = resp.json()
            self._public_keys = _parse_jwks(jwks)
            self._jwks_cache_path.write_text(json.dumps(jwks))
        except Exception as exc:
            logger.warning("SDK validator JWKS refresh failed: %s", exc)

    def load_jwks_from_dict(self, jwks: dict) -> None:
        """Load JWKS directly (used in tests to inject keys without network)."""
        with self._lock:
            self._public_keys = _parse_jwks(jwks)

    # ── Replay cache ──────────────────────────────────────────────────────────

    def _load_replay_cache(self) -> None:
        if self._replay_path and self._replay_path.exists():
            try:
                data = json.loads(self._replay_path.read_text())
                now = time.time()
                self._replay_store = {k: v for k, v in data.items() if v > now}
            except Exception:
                self._replay_store = {}

    def _save_replay_cache(self) -> None:
        if self._replay_path:
            try:
                self._replay_path.write_text(json.dumps(self._replay_store))
            except Exception:
                pass

    def _evict_replay(self) -> None:
        now = time.time()
        for k in [jti for jti, dl in self._replay_store.items() if dl < now]:
            del self._replay_store[k]


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _parse_jwks(jwks: dict) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    keys: dict[str, Any] = {}
    for jwk in jwks.get("keys", []):
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue
        try:
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
            keys[jwk["kid"]] = pub
        except Exception as exc:
            logger.warning("Failed to parse JWK kid=%s: %s", jwk.get("kid"), exc)
    return keys


def _verify_es256(header_b64: str, payload_b64: str, sig_b64: str, pub_key: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig_bytes = _b64url_decode(sig_b64)
    if len(sig_bytes) != 64:
        raise ValueError(f"ES256 sig must be 64 bytes, got {len(sig_bytes)}")
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    pub_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
