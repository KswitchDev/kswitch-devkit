"""Lightweight async HTTP client for KSwitch.ai API.

Handles authentication (direct token or M2M client_credentials),
automatic token refresh on 401, and mkcert CA auto-detection.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── Configuration from environment ────────────────────────────────────────

BASE_URL = os.environ.get("KSWITCH_URL", "https://localhost:5001")
TOKEN = os.environ.get("KSWITCH_TOKEN", "")
CLIENT_ID = os.environ.get("KSWITCH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("KSWITCH_CLIENT_SECRET", "")
KC_URL = os.environ.get("KSWITCH_KEYCLOAK_URL", "")
KC_REALM = os.environ.get("KSWITCH_KEYCLOAK_REALM", "kswitch")
VERIFY_SSL = os.environ.get("KSWITCH_VERIFY_SSL", "true").lower() not in (
    "false",
    "0",
    "no",
)

# ── Internal state ────────────────────────────────────────────────────────

_token_cache: dict[str, Any] = {"token": "", "expires_at": 0}


def _resolve_m2m_token_verify() -> bool:
    """Return the `verify=` value for the M2M token-exchange httpx client.

    EP-063 L-7 pattern (see `app/routes/auth.py::_resolve_oidc_verify_tls`
    and `reports/security-fix-path-2026-04-24.md` §S1-D). Default is
    TLS-verify-on. Only disabled when `KSWITCH_INSECURE_TLS=true` is set
    explicitly, and that override is hard-rejected when
    `KSWITCH_ENV=production`.
    """
    if os.environ.get("KSWITCH_INSECURE_TLS", "").lower() != "true":
        return True
    if os.environ.get("KSWITCH_ENV", "").lower() == "production":
        raise RuntimeError(
            "[startup] KSWITCH_INSECURE_TLS=true is not permitted when "
            "KSWITCH_ENV=production. Configure a valid CA trust chain to "
            "the IdP or deploy through a TLS-terminating proxy."
        )
    logger.warning(
        "mcp-server: KSWITCH_INSECURE_TLS=true — M2M token-exchange TLS "
        "verification disabled (dev only)"
    )
    return False


class KSwitchAPIClient:
    """Reusable async client for the KSwitch control-plane API."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _fetch_m2m_token(self) -> str:
        """Fetch M2M token from Keycloak using client_credentials grant."""
        if _token_cache["token"] and _token_cache["expires_at"] > time.time() + 60:
            return _token_cache["token"]
        if not CLIENT_ID or not CLIENT_SECRET or not KC_URL:
            return ""
        try:
            async with httpx.AsyncClient(
                verify=_resolve_m2m_token_verify(), timeout=10
            ) as c:
                r = await c.post(
                    f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                    },
                )
                data = r.json()
                _token_cache["token"] = data.get("access_token", "")
                _token_cache["expires_at"] = time.time() + data.get("expires_in", 3600)
                return _token_cache["token"]
        except Exception:
            return _token_cache.get("token", "")

    def _resolve_verify(self) -> bool | str:
        """Resolve SSL verification — auto-detect mkcert CA bundle."""
        if not VERIFY_SSL:
            return False
        # Check explicit CA file
        ca_file = os.environ.get("KSWITCH_CA_FILE", "")
        if ca_file and os.path.exists(ca_file):
            return ca_file
        # Auto-detect mkcert CA
        for ca in [
            os.path.expanduser("~/.mkcert-ca.pem"),
            os.path.expanduser(
                "~/Library/Application Support/mkcert/rootCA.pem"
            ),
            "/etc/ssl/certs/mkcert-ca.pem",
        ]:
            if os.path.exists(ca):
                return ca
        return True

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init httpx client with auth and TLS."""
        if self._client and not self._client.is_closed:
            return self._client

        headers: dict[str, str] = {}
        token = TOKEN or await self._fetch_m2m_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            headers=headers,
            verify=self._resolve_verify(),
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        return self._client

    async def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> dict:
        """Make an authenticated API call with auto token refresh on 401."""
        client = await self._get_client()
        r = await client.request(method, path, json=json, params=params)

        # Refresh token and retry once on 401
        if r.status_code == 401:
            _token_cache["token"] = ""
            _token_cache["expires_at"] = 0
            token = await self._fetch_m2m_token()
            if token:
                client.headers["Authorization"] = f"Bearer {token}"
                r = await client.request(method, path, json=json, params=params)

        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = {"_raw": r.text}
            body["_status"] = r.status_code
            return body

        try:
            return r.json()
        except Exception:
            return {"_raw": r.text, "_status": r.status_code}

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
