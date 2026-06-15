"""AuthZen API — OpenID AuthZen PDP evaluation and search endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    AuthZenBatchResponse,
    AuthZenDecision,
    AuthZenRequest,
    AuthZenSearchResult,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class AuthZenAPI:
    """Synchronous AuthZen PDP operations.

    Implements the OpenID AuthZen PDP specification endpoints:
    - /access/v1/evaluation (single)
    - /access/v1/evaluations (batch)
    - /access/v1/search/* (resource, action, subject)
    - /.well-known/authzen-configuration (discovery)
    """

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    def evaluate(
        self,
        *,
        subject: dict[str, Any],
        resource: dict[str, Any],
        action: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AuthZenDecision:
        """Evaluate a single authorization request via AuthZen PDP."""
        payload: dict[str, Any] = {
            "subject": subject,
            "resource": resource,
            "action": action,
        }
        if context:
            payload["context"] = context
        return AuthZenDecision(**self._c._post("/access/v1/evaluation", json=payload))

    def evaluate_batch(
        self,
        *,
        evaluations: list[dict[str, Any]],
    ) -> AuthZenBatchResponse:
        """Evaluate a batch of authorization requests."""
        payload = {"evaluations": evaluations}
        return AuthZenBatchResponse(**self._c._post("/access/v1/evaluations", json=payload))

    def search_resource(self, **kwargs: Any) -> AuthZenSearchResult:
        """Search for resources a subject can access."""
        return AuthZenSearchResult(**self._c._post("/access/v1/search/resource", json=kwargs))

    def search_action(self, **kwargs: Any) -> AuthZenSearchResult:
        """Search for actions a subject can perform on a resource."""
        return AuthZenSearchResult(**self._c._post("/access/v1/search/action", json=kwargs))

    def search_subject(self, **kwargs: Any) -> AuthZenSearchResult:
        """Search for subjects that can perform an action on a resource."""
        return AuthZenSearchResult(**self._c._post("/access/v1/search/subject", json=kwargs))

    def discovery(self) -> dict[str, Any]:
        """Get AuthZen PDP configuration (well-known endpoint)."""
        return self._c._get("/.well-known/authzen-configuration")


class AuthZenAsyncAPI:
    """Asynchronous AuthZen PDP operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def evaluate(self, *, subject: dict[str, Any], resource: dict[str, Any], action: dict[str, Any], context: dict[str, Any] | None = None) -> AuthZenDecision:
        payload: dict[str, Any] = {"subject": subject, "resource": resource, "action": action}
        if context:
            payload["context"] = context
        return AuthZenDecision(**await self._c._post("/access/v1/evaluation", json=payload))

    async def evaluate_batch(self, *, evaluations: list[dict[str, Any]]) -> AuthZenBatchResponse:
        payload = {"evaluations": evaluations}
        return AuthZenBatchResponse(**await self._c._post("/access/v1/evaluations", json=payload))

    async def search_resource(self, **kwargs: Any) -> AuthZenSearchResult:
        return AuthZenSearchResult(**await self._c._post("/access/v1/search/resource", json=kwargs))

    async def search_action(self, **kwargs: Any) -> AuthZenSearchResult:
        return AuthZenSearchResult(**await self._c._post("/access/v1/search/action", json=kwargs))

    async def search_subject(self, **kwargs: Any) -> AuthZenSearchResult:
        return AuthZenSearchResult(**await self._c._post("/access/v1/search/subject", json=kwargs))

    async def discovery(self) -> dict[str, Any]:
        return await self._c._get("/.well-known/authzen-configuration")
