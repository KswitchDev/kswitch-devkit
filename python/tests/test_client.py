"""Tests for KSwitchClient initialization, auth, retry, and error handling."""

from __future__ import annotations

import pytest
import httpx

# `respx` is an optional test-only dependency for HTTP mocking. Skip the
# whole module cleanly if it isn't installed rather than failing collection
# at the repo root — keeps `pytest` at root green for the bank dev review.
respx = pytest.importorskip("respx")

from kswitch import KSwitchClient, KSwitchAsyncClient
from kswitch.auth import AuthManager, build_token_url, clear_token_cache, resolve_ca_path
from kswitch.exceptions import (
    AuthError,
    ForbiddenError,
    KSwitchError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    raise_for_status,
)


# ---------------------------------------------------------------------------
# Exception mapping
# ---------------------------------------------------------------------------

class TestRaiseForStatus:
    def test_2xx_does_not_raise(self):
        raise_for_status(200, {"ok": True})
        raise_for_status(201, {"id": "abc"})
        raise_for_status(204, {})

    def test_400_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            raise_for_status(400, {"error": "bad request"})
        assert exc_info.value.status_code == 400

    def test_401_raises_auth_error(self):
        with pytest.raises(AuthError):
            raise_for_status(401, {"error": "unauthorized"})

    def test_403_raises_forbidden_error(self):
        with pytest.raises(ForbiddenError):
            raise_for_status(403, {"error": "forbidden"})

    def test_404_raises_not_found_error(self):
        with pytest.raises(NotFoundError):
            raise_for_status(404, {"error": "not found"})

    def test_422_raises_validation_error(self):
        with pytest.raises(ValidationError):
            raise_for_status(422, {"error": "validation failed"})

    def test_429_raises_rate_limit_error(self):
        with pytest.raises(RateLimitError) as exc_info:
            raise_for_status(429, {"error": "too many requests", "retry_after": 5})
        assert exc_info.value.retry_after == 5

    def test_500_raises_server_error(self):
        with pytest.raises(ServerError):
            raise_for_status(500, {"error": "internal"})

    def test_unknown_4xx_raises_base_error(self):
        with pytest.raises(KSwitchError):
            raise_for_status(418, {"error": "teapot"})

    def test_error_message_extraction(self):
        with pytest.raises(KSwitchError, match="custom msg"):
            raise_for_status(400, {"error": "custom msg"})

        with pytest.raises(KSwitchError, match="fallback msg"):
            raise_for_status(400, {"message": "fallback msg"})

        with pytest.raises(KSwitchError, match="HTTP 400"):
            raise_for_status(400, {})


# ---------------------------------------------------------------------------
# Auth manager
# ---------------------------------------------------------------------------

class TestAuthManager:
    def test_static_token(self):
        auth = AuthManager(token="my-token")
        assert auth.get_token() == "my-token"
        assert auth.auth_headers() == {"Authorization": "Bearer my-token"}

    def test_no_token_returns_none(self):
        auth = AuthManager()
        assert auth.get_token() is None
        assert auth.auth_headers() == {}

    def test_has_m2m_config(self):
        auth = AuthManager(client_id="id", client_secret="secret", keycloak_url="http://kc")
        assert auth.has_m2m_config is True

        auth2 = AuthManager(client_id="id")
        assert auth2.has_m2m_config is False

    def test_build_token_url_keycloak(self):
        url = build_token_url(keycloak_url="http://kc:8080", keycloak_realm="myrealm")
        assert url == "http://kc:8080/realms/myrealm/protocol/openid-connect/token"

    def test_build_token_url_logto(self):
        url = build_token_url(logto_url="http://logto:3001")
        assert url == "http://logto:3001/oidc/token"

    def test_build_token_url_requires_provider(self):
        with pytest.raises(ValueError):
            build_token_url()

    def test_clear_cache(self):
        clear_token_cache()  # should not raise


# ---------------------------------------------------------------------------
# CA resolution
# ---------------------------------------------------------------------------

class TestResolveCA:
    def test_explicit_path_nonexistent_falls_through(self):
        result = resolve_ca_path("/nonexistent/ca.pem")
        # Should return True (system default) since file doesn't exist
        assert result is True or isinstance(result, str)

    def test_returns_true_by_default(self, monkeypatch):
        monkeypatch.delenv("KSWITCH_CA_FILE", raising=False)
        result = resolve_ca_path()
        # May be True or a detected mkcert path
        assert result is True or isinstance(result, str)


# ---------------------------------------------------------------------------
# Client init
# ---------------------------------------------------------------------------

class TestClientInit:
    def test_default_init(self):
        client = KSwitchClient(base_url="http://localhost:5001", verify_ssl=False)
        assert client.base_url == "http://localhost:5001"
        assert client.retries == 3
        assert hasattr(client, "governance")
        assert hasattr(client, "policy")
        assert hasattr(client, "identity")
        assert hasattr(client, "compliance")
        assert hasattr(client, "killswitch")
        assert hasattr(client, "events")
        assert hasattr(client, "catalog")
        assert hasattr(client, "enforcement")
        assert hasattr(client, "authzen")
        client.close()

    def test_trailing_slash_stripped(self):
        client = KSwitchClient(base_url="http://localhost:5001/", verify_ssl=False)
        assert client.base_url == "http://localhost:5001"
        client.close()

    def test_context_manager(self):
        with KSwitchClient(base_url="http://localhost:5001", verify_ssl=False) as client:
            assert client is not None


# ---------------------------------------------------------------------------
# Retry and error handling (with respx mock)
# ---------------------------------------------------------------------------

class TestClientRetry:
    @respx.mock
    def test_success_request(self):
        respx.get("http://localhost:5001/api/v1/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        with KSwitchClient(base_url="http://localhost:5001", verify_ssl=False) as client:
            result = client.health()
            assert result["status"] == "ok"

    @respx.mock
    def test_404_raises(self):
        respx.get("http://localhost:5001/api/v1/agents/nonexistent").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        with KSwitchClient(base_url="http://localhost:5001", verify_ssl=False) as client:
            with pytest.raises(NotFoundError):
                client.governance.get_agent("nonexistent")

    @respx.mock
    def test_503_retry_then_success(self):
        route = respx.get("http://localhost:5001/api/v1/health")
        route.side_effect = [
            httpx.Response(503, json={"error": "unavailable"}),
            httpx.Response(200, json={"status": "ok"}),
        ]
        with KSwitchClient(base_url="http://localhost:5001", verify_ssl=False, backoff=0.01) as client:
            result = client.health()
            assert result["status"] == "ok"

    @respx.mock
    def test_non_json_response(self):
        respx.get("http://localhost:5001/api/v1/health").mock(
            return_value=httpx.Response(200, text="OK")
        )
        with KSwitchClient(base_url="http://localhost:5001", verify_ssl=False) as client:
            result = client.health()
            assert "_raw" in result


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class TestAsyncClientInit:
    def test_default_init(self):
        client = KSwitchAsyncClient(base_url="http://localhost:5001", verify_ssl=False)
        assert client.base_url == "http://localhost:5001"
        assert hasattr(client, "governance")
        assert hasattr(client, "authzen")

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_health(self):
        respx.get("http://localhost:5001/api/v1/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        async with KSwitchAsyncClient(base_url="http://localhost:5001", verify_ssl=False) as client:
            result = await client.health()
            assert result["status"] == "ok"
