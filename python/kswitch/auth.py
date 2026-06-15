"""Authentication helpers for KSwitch SDK.

Supports:
- Static bearer token
- Keycloak / Logto M2M (client_credentials) with auto-refresh
- JWT-SVID (SPIFFE workload identity)
- mTLS client certificate configuration
"""

from __future__ import annotations

import logging
import os
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("kswitch.auth")


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------

@dataclass
class _TokenEntry:
    token: str = ""
    expires_at: float = 0.0

    @property
    def is_valid(self) -> bool:
        """Token is present and has at least 60 s of remaining life."""
        return bool(self.token) and self.expires_at > time.time() + 60


_token_cache: dict[str, _TokenEntry] = {}


# ---------------------------------------------------------------------------
# M2M token fetcher
# ---------------------------------------------------------------------------

def fetch_m2m_token(
    *,
    client_id: str,
    client_secret: str,
    token_url: str,
    resource: str | None = None,
    scopes: list[str] | None = None,
    timeout: float = 10.0,
) -> tuple[str, float]:
    """Fetch an M2M access token via OAuth2 ``client_credentials`` grant.

    Returns ``(access_token, expires_in_seconds)``.
    """
    cache_key = f"{token_url}:{client_id}"
    cached = _token_cache.get(cache_key)
    if cached and cached.is_valid:
        return cached.token, cached.expires_at - time.time()

    data: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if resource:
        data["resource"] = resource
    if scopes:
        data["scope"] = " ".join(scopes)

    resp = httpx.post(token_url, data=data, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()

    token = body["access_token"]
    expires_in = float(body.get("expires_in", 3600))

    _token_cache[cache_key] = _TokenEntry(token=token, expires_at=time.time() + expires_in)
    logger.debug("M2M token refreshed, expires_in=%s", expires_in)
    return token, expires_in


def build_token_url(
    *,
    keycloak_url: str | None = None,
    keycloak_realm: str = "kswitch",
    logto_url: str | None = None,
) -> str:
    """Derive the OIDC token endpoint from Keycloak or Logto base URL."""
    if keycloak_url:
        return f"{keycloak_url.rstrip('/')}/realms/{keycloak_realm}/protocol/openid-connect/token"
    if logto_url:
        base = logto_url.rstrip("/")
        if "realms" in base:
            return f"{base}/protocol/openid-connect/token"
        return f"{base}/oidc/token"
    raise ValueError("Either keycloak_url or logto_url must be provided for M2M auth")


def clear_token_cache() -> None:
    """Clear all cached M2M tokens (useful for testing)."""
    _token_cache.clear()


# ---------------------------------------------------------------------------
# mTLS / SSL helpers
# ---------------------------------------------------------------------------

_MKCERT_CA_PATHS = [
    os.path.expanduser("~/.mkcert-ca.pem"),
    os.path.expanduser("~/Library/Application Support/mkcert/rootCA.pem"),
    "/etc/ssl/certs/mkcert-ca.pem",
    "/usr/local/share/ca-certificates/mkcert-ca.pem",
]


def resolve_ca_path(ca_path: str | None = None) -> str | bool:
    """Resolve the CA bundle path for SSL verification.

    Priority:
    1. Explicit *ca_path* argument
    2. ``KSWITCH_CA_FILE`` environment variable
    3. Auto-detect mkcert root CA in well-known locations
    4. Fall back to ``True`` (use system default)
    """
    if ca_path and os.path.exists(ca_path):
        return ca_path

    env_ca = os.environ.get("KSWITCH_CA_FILE", "")
    if env_ca and os.path.exists(env_ca):
        return env_ca

    for path in _MKCERT_CA_PATHS:
        if os.path.exists(path):
            logger.debug("Auto-detected mkcert CA at %s", path)
            return path

    return True  # system default


def build_ssl_context(
    *,
    cert_path: str | None = None,
    key_path: str | None = None,
    ca_path: str | None = None,
    verify_ssl: bool = True,
) -> tuple[httpx.Client | None, Any]:
    """Build httpx-compatible SSL params.

    Returns ``(cert_tuple_or_none, verify_value)``.
    """
    cert = None
    if cert_path and key_path:
        cert = (cert_path, key_path)

    if not verify_ssl:
        return cert, False

    return cert, resolve_ca_path(ca_path)


# ---------------------------------------------------------------------------
# Auth manager (used by KSwitchClient internally)
# ---------------------------------------------------------------------------

@dataclass
class AuthManager:
    """Manages token lifecycle for a KSwitchClient instance."""

    token: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    keycloak_url: str | None = None
    keycloak_realm: str = "kswitch"
    logto_url: str | None = None
    resource: str | None = None
    scopes: list[str] | None = None
    _token_url: str | None = field(default=None, repr=False)

    @property
    def has_m2m_config(self) -> bool:
        return bool(self.client_id and self.client_secret and (self.keycloak_url or self.logto_url))

    @property
    def token_url(self) -> str:
        if self._token_url:
            return self._token_url
        self._token_url = build_token_url(
            keycloak_url=self.keycloak_url,
            keycloak_realm=self.keycloak_realm,
            logto_url=self.logto_url,
        )
        return self._token_url

    def get_token(self) -> str | None:
        """Return a valid bearer token, refreshing via M2M if needed."""
        if self.token:
            return self.token
        if self.has_m2m_config:
            try:
                token, _ = fetch_m2m_token(
                    client_id=self.client_id,  # type: ignore[arg-type]
                    client_secret=self.client_secret,  # type: ignore[arg-type]
                    token_url=self.token_url,
                    resource=self.resource,
                    scopes=self.scopes,
                )
                self.token = token
                return token
            except Exception:
                logger.warning("M2M token fetch failed", exc_info=True)
                return None
        return None

    def refresh_token(self) -> str | None:
        """Force-refresh the token (called on 401)."""
        self.token = None
        cache_key = f"{self.token_url}:{self.client_id}" if self.has_m2m_config else ""
        if cache_key in _token_cache:
            del _token_cache[cache_key]
        return self.get_token()

    def auth_headers(self) -> dict[str, str]:
        """Return Authorization header dict, or empty dict if no token."""
        token = self.get_token()
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}
