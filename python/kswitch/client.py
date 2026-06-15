"""KSwitch SDK — main client entry point.

Usage::

    from kswitch import KSwitchClient

    client = KSwitchClient(
        base_url="https://localhost:5001",
        client_id="my-app",
        client_secret="secret",
        keycloak_url="http://localhost:8080",
    )

    agent = client.governance.register_agent(display_name="my-agent")
    client.close()

Or as a context manager::

    with KSwitchClient(base_url="https://localhost:5001", token="...") as client:
        agents = client.governance.list_agents()
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import quote

import httpx

from .auth import AuthManager, build_ssl_context
from .exceptions import raise_for_status
from .__version__ import __version__ as SDK_VERSION

logger = logging.getLogger("kswitch.client")

_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._~:@!$&'()*+,;=-]+$")


def sanitize_path_param(value: str) -> str:
    """Validate and encode a user-provided ID for safe use in URL paths.

    Rejects values containing path traversal sequences, query injections,
    or other dangerous characters.
    """
    if not value:
        raise ValueError("Path parameter must not be empty")
    if ".." in value or "/" in value or "\\" in value or "?" in value or "#" in value:
        raise ValueError("Invalid characters in path parameter")
    if _SAFE_ID_RE.match(value):
        return value
    return quote(value, safe="")


class _BaseClient:
    """Shared initialisation for sync and async clients."""

    def __init__(
        self,
        base_url: str = "https://localhost:5001",
        token: str | None = None,
        # Keycloak / Logto M2M auth
        client_id: str | None = None,
        client_secret: str | None = None,
        keycloak_url: str | None = None,
        keycloak_realm: str = "kswitch",
        logto_url: str | None = None,
        resource: str | None = None,
        scopes: list[str] | None = None,
        # mTLS
        cert_path: str | None = None,
        key_path: str | None = None,
        ca_path: str | None = None,
        # Options
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 1.0,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.retries = retries
        self.backoff = backoff

        self._auth = AuthManager(
            token=token,
            client_id=client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_url,
            keycloak_realm=keycloak_realm,
            logto_url=logto_url,
            resource=resource,
            scopes=scopes,
        )

        self._cert, self._verify = build_ssl_context(
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            verify_ssl=verify_ssl,
        )
        self._timeout = httpx.Timeout(timeout, connect=10.0)

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"kswitch-sdk-python/{SDK_VERSION}",
        }
        headers.update(self._auth.auth_headers())
        return headers


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------

class KSwitchClient(_BaseClient):
    """Synchronous KSwitch API client.

    API methods are grouped into namespaced sub-clients:

    - ``client.governance`` -- agent lifecycle
    - ``client.policy`` -- Cedar policy management
    - ``client.identity`` -- SPIFFE / service identities
    - ``client.compliance`` -- toxic combos, boundary analysis
    - ``client.killswitch`` -- kill switch operations
    - ``client.events`` -- event outbox
    - ``client.catalog`` -- skills & tools catalog
    - ``client.enforcement`` -- MCP call enforcement
    - ``client.authzen`` -- AuthZen PDP
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http: httpx.Client | None = None

        # Lazy imports to avoid circular refs at module level
        from .governance import GovernanceAPI
        from .policy import PolicyAPI
        from .identity import IdentityAPI
        from .compliance import ComplianceAPI
        from .killswitch import KillSwitchAPI
        from .events import EventsAPI
        from .catalog import CatalogAPI
        from .enforcement import EnforcementAPI
        from .authzen import AuthZenAPI
        from .service import ServiceAPI

        self.governance = GovernanceAPI(self)
        self.policy = PolicyAPI(self)
        self.identity = IdentityAPI(self)
        self.compliance = ComplianceAPI(self)
        self.killswitch = KillSwitchAPI(self)
        self.events = EventsAPI(self)
        self.catalog = CatalogAPI(self)
        self.enforcement = EnforcementAPI(self)
        self.authzen = AuthZenAPI(self)
        self.service = ServiceAPI(self)

    # -- HTTP transport -------------------------------------------------

    @property
    def _client(self) -> httpx.Client:
        if self._http is None or self._http.is_closed:
            self._http = httpx.Client(
                base_url=self.base_url,
                headers=self._build_headers(),
                cert=self._cert,
                verify=self._verify,
                timeout=self._timeout,
            )
        return self._http

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request with retry on 503/connection errors and 401 token refresh."""
        last_exc: Exception | None = None

        for attempt in range(self.retries):
            try:
                resp = self._client.request(
                    method, path, json=json, params=params, content=data,
                )

                # 503 — retry with backoff
                if resp.status_code == 503 and attempt < self.retries - 1:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue

                # 429 — respect Retry-After
                if resp.status_code == 429 and attempt < self.retries - 1:
                    retry_after = float(resp.headers.get("Retry-After", self.backoff * (2 ** attempt)))
                    time.sleep(retry_after)
                    continue

                # 401 — refresh token and retry
                if resp.status_code == 401 and attempt < self.retries - 1:
                    new_token = self._auth.refresh_token()
                    if new_token:
                        self.close()  # recreate client with new headers
                        continue

                # Parse body
                try:
                    body = resp.json()
                except Exception:
                    body = {"_raw": resp.text}

                if not isinstance(body, dict):
                    body = {"data": body}

                raise_for_status(resp.status_code, body)
                return body

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
                last_exc = exc
                if attempt < self.retries - 1:
                    time.sleep(self.backoff * (2 ** attempt))

        if last_exc:
            raise last_exc
        raise RuntimeError("request failed after retries")

    # -- Convenience shortcuts ------------------------------------------

    def _get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("GET", path, **kwargs)

    def _post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("POST", path, **kwargs)

    def _patch(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("PATCH", path, **kwargs)

    def _put(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("PUT", path, **kwargs)

    def _delete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("DELETE", path, **kwargs)

    # -- Lifecycle ------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http and not self._http.is_closed:
            self._http.close()
        self._http = None

    def __enter__(self) -> KSwitchClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # -- Top-level convenience ------------------------------------------

    def health(self) -> dict[str, Any]:
        """Quick health check."""
        return self._get("/api/v1/health")

    def health_live(self) -> dict[str, Any]:
        """Liveness probe."""
        return self._get("/api/v1/health/live")

    def health_ready(self) -> dict[str, Any]:
        """Readiness probe."""
        return self._get("/api/v1/health/ready")

    def dashboard(self) -> dict[str, Any]:
        """Get the main governance dashboard."""
        return self._get("/api/v1/dashboard")


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class KSwitchAsyncClient(_BaseClient):
    """Asynchronous KSwitch API client (mirrors KSwitchClient)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http: httpx.AsyncClient | None = None

        from .governance import GovernanceAsyncAPI
        from .policy import PolicyAsyncAPI
        from .identity import IdentityAsyncAPI
        from .compliance import ComplianceAsyncAPI
        from .killswitch import KillSwitchAsyncAPI
        from .events import EventsAsyncAPI
        from .catalog import CatalogAsyncAPI
        from .enforcement import EnforcementAsyncAPI
        from .authzen import AuthZenAsyncAPI
        from .service import ServiceAsyncAPI

        self.governance = GovernanceAsyncAPI(self)
        self.policy = PolicyAsyncAPI(self)
        self.identity = IdentityAsyncAPI(self)
        self.compliance = ComplianceAsyncAPI(self)
        self.killswitch = KillSwitchAsyncAPI(self)
        self.events = EventsAsyncAPI(self)
        self.catalog = CatalogAsyncAPI(self)
        self.enforcement = EnforcementAsyncAPI(self)
        self.authzen = AuthZenAsyncAPI(self)
        self.service = ServiceAsyncAPI(self)

    @property
    def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._build_headers(),
                cert=self._cert,
                verify=self._verify,
                timeout=self._timeout,
            )
        return self._http

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
    ) -> dict[str, Any]:
        import asyncio

        last_exc: Exception | None = None

        for attempt in range(self.retries):
            try:
                resp = await self._client.request(
                    method, path, json=json, params=params, content=data,
                )

                if resp.status_code == 503 and attempt < self.retries - 1:
                    await asyncio.sleep(self.backoff * (2 ** attempt))
                    continue

                if resp.status_code == 429 and attempt < self.retries - 1:
                    retry_after = float(resp.headers.get("Retry-After", self.backoff * (2 ** attempt)))
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code == 401 and attempt < self.retries - 1:
                    new_token = self._auth.refresh_token()
                    if new_token:
                        await self.close()
                        continue

                try:
                    body = resp.json()
                except Exception:
                    body = {"_raw": resp.text}

                if not isinstance(body, dict):
                    body = {"data": body}

                raise_for_status(resp.status_code, body)
                return body

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
                last_exc = exc
                if attempt < self.retries - 1:
                    await asyncio.sleep(self.backoff * (2 ** attempt))

        if last_exc:
            raise last_exc
        raise RuntimeError("request failed after retries")

    async def _get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("GET", path, **kwargs)

    async def _post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("POST", path, **kwargs)

    async def _patch(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("PATCH", path, **kwargs)

    async def _put(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("PUT", path, **kwargs)

    async def _delete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request("DELETE", path, **kwargs)

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()
        self._http = None

    async def __aenter__(self) -> KSwitchAsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def health(self) -> dict[str, Any]:
        return await self._get("/api/v1/health")

    async def health_live(self) -> dict[str, Any]:
        return await self._get("/api/v1/health/live")

    async def health_ready(self) -> dict[str, Any]:
        return await self._get("/api/v1/health/ready")

    async def dashboard(self) -> dict[str, Any]:
        return await self._get("/api/v1/dashboard")
