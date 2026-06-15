"""Policy API — Cedar/Rego policy management and evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    PaginatedResponse,
    Policy,
    PolicyDecision,
    PolicyEvaluation,
    PolicyValidation,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class PolicyAPI:
    """Synchronous policy operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- CRUD -----------------------------------------------------------

    def create(
        self,
        *,
        name: str,
        cedar_text: str | None = None,
        rego_text: str | None = None,
        **kwargs: Any,
    ) -> Policy:
        """Create a new governance policy."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        if cedar_text:
            payload["cedar_text"] = cedar_text
        if rego_text:
            payload["rego_text"] = rego_text
        return Policy(**self._c._post("/api/v1/policies", json=payload))

    def list(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Policy]:
        """List policies with pagination."""
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = self._c._get("/api/v1/policies", params=params)
        items = resp.get("data", resp.get("policies", []))
        return PaginatedResponse[Policy](
            data=[Policy(**p) for p in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    def get(self, policy_id: str) -> Policy:
        """Get a policy by ID (includes full Cedar/Rego text)."""
        return Policy(**self._c._get(f"/api/v1/policies/{policy_id}"))

    def update(self, policy_id: str, **fields: Any) -> Policy:
        """Partial update of a policy."""
        return Policy(**self._c._patch(f"/api/v1/policies/{policy_id}", json=fields))

    def delete(self, policy_id: str) -> dict[str, Any]:
        """Delete a policy."""
        return self._c._delete(f"/api/v1/policies/{policy_id}")

    def duplicate(self, policy_id: str, *, new_name: str | None = None, **kwargs: Any) -> Policy:
        """Duplicate an existing policy."""
        payload: dict[str, Any] = {**kwargs}
        if new_name:
            payload["name"] = new_name
        return Policy(**self._c._post(f"/api/v1/policies/{policy_id}/duplicate", json=payload))

    # -- Validation & Evaluation ----------------------------------------

    def validate(self, *, cedar_text: str | None = None, rego_text: str | None = None, **kwargs: Any) -> PolicyValidation:
        """Validate Cedar/Rego policy syntax without saving."""
        payload: dict[str, Any] = {**kwargs}
        if cedar_text:
            payload["cedar_text"] = cedar_text
        if rego_text:
            payload["rego_text"] = rego_text
        return PolicyValidation(**self._c._post("/api/v1/policies/validate", json=payload))

    def evaluate(
        self,
        *,
        principal: str,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> PolicyDecision:
        """Evaluate a policy decision."""
        payload: dict[str, Any] = {
            "principal": principal,
            "action": action,
            "resource": resource,
            **kwargs,
        }
        if context:
            payload["context"] = context
        return PolicyDecision(**self._c._post("/api/v1/policies/evaluate", json=payload))

    def list_evaluations(self, *, limit: int = 50, **filters: Any) -> list[PolicyEvaluation]:
        """Get recent policy evaluation results."""
        params: dict[str, Any] = {"limit": limit, **filters}
        resp = self._c._get("/api/v1/policies/evaluations", params=params)
        items = resp.get("data", resp.get("evaluations", []))
        return [PolicyEvaluation(**e) for e in items]

    # -- Mode -----------------------------------------------------------

    def set_mode(self, *, mode: str, **kwargs: Any) -> dict[str, Any]:
        """Switch policy enforcement mode (enforce/shadow/disabled)."""
        payload: dict[str, Any] = {"mode": mode, **kwargs}
        return self._c._patch("/api/v1/policies/mode", json=payload)


class PolicyAsyncAPI:
    """Asynchronous policy operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def create(self, *, name: str, cedar_text: str | None = None, rego_text: str | None = None, **kwargs: Any) -> Policy:
        payload: dict[str, Any] = {"name": name, **kwargs}
        if cedar_text:
            payload["cedar_text"] = cedar_text
        if rego_text:
            payload["rego_text"] = rego_text
        return Policy(**await self._c._post("/api/v1/policies", json=payload))

    async def list(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Policy]:
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = await self._c._get("/api/v1/policies", params=params)
        items = resp.get("data", resp.get("policies", []))
        return PaginatedResponse[Policy](
            data=[Policy(**p) for p in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    async def get(self, policy_id: str) -> Policy:
        return Policy(**await self._c._get(f"/api/v1/policies/{policy_id}"))

    async def update(self, policy_id: str, **fields: Any) -> Policy:
        return Policy(**await self._c._patch(f"/api/v1/policies/{policy_id}", json=fields))

    async def delete(self, policy_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/policies/{policy_id}")

    async def duplicate(self, policy_id: str, *, new_name: str | None = None, **kwargs: Any) -> Policy:
        payload: dict[str, Any] = {**kwargs}
        if new_name:
            payload["name"] = new_name
        return Policy(**await self._c._post(f"/api/v1/policies/{policy_id}/duplicate", json=payload))

    async def validate(self, *, cedar_text: str | None = None, rego_text: str | None = None, **kwargs: Any) -> PolicyValidation:
        payload: dict[str, Any] = {**kwargs}
        if cedar_text:
            payload["cedar_text"] = cedar_text
        if rego_text:
            payload["rego_text"] = rego_text
        return PolicyValidation(**await self._c._post("/api/v1/policies/validate", json=payload))

    async def evaluate(self, *, principal: str, action: str, resource: str, context: dict[str, Any] | None = None, **kwargs: Any) -> PolicyDecision:
        payload: dict[str, Any] = {"principal": principal, "action": action, "resource": resource, **kwargs}
        if context:
            payload["context"] = context
        return PolicyDecision(**await self._c._post("/api/v1/policies/evaluate", json=payload))

    async def list_evaluations(self, *, limit: int = 50, **filters: Any) -> list[PolicyEvaluation]:
        params: dict[str, Any] = {"limit": limit, **filters}
        resp = await self._c._get("/api/v1/policies/evaluations", params=params)
        items = resp.get("data", resp.get("evaluations", []))
        return [PolicyEvaluation(**e) for e in items]

    async def set_mode(self, *, mode: str, **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": mode, **kwargs}
        return await self._c._patch("/api/v1/policies/mode", json=payload)
