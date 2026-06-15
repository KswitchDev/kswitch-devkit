"""Identity API — SPIFFE identities, service identities, trust domains."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    IdentityStats,
    ServiceIdentity,
    SpiffeIdentity,
    TrustDomain,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class IdentityAPI:
    """Synchronous identity operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- SPIFFE ---------------------------------------------------------

    def create_spiffe(self, agent_id: str, **kwargs: Any) -> SpiffeIdentity:
        """Create a SPIFFE identity for an agent."""
        return SpiffeIdentity(**self._c._post(f"/api/v1/agents/{agent_id}/spiffe", json=kwargs))

    def get_spiffe(self, agent_id: str) -> SpiffeIdentity:
        """Get SPIFFE identity details for an agent."""
        return SpiffeIdentity(**self._c._get(f"/api/v1/agents/{agent_id}/spiffe"))

    def rotate_spiffe(self, agent_id: str) -> SpiffeIdentity:
        """Rotate an agent's SPIFFE SVID."""
        return SpiffeIdentity(**self._c._patch(f"/api/v1/agents/{agent_id}/spiffe"))

    def revoke_spiffe(self, agent_id: str) -> dict[str, Any]:
        """Revoke an agent's SPIFFE identity."""
        return self._c._delete(f"/api/v1/agents/{agent_id}/spiffe")

    def list_spiffe(self, **params: Any) -> list[SpiffeIdentity]:
        """List all SPIFFE identities."""
        resp = self._c._get("/api/v1/identities/spiffe", params=params)
        items = resp.get("data", resp.get("identities", []))
        return [SpiffeIdentity(**i) for i in items]

    # -- Service Identities ---------------------------------------------

    def list_service_identities(self, agent_id: str) -> list[ServiceIdentity]:
        """List service identities for an agent."""
        resp = self._c._get(f"/api/v1/agents/{agent_id}/identities")
        items = resp.get("data", resp.get("identities", []))
        return [ServiceIdentity(**i) for i in items]

    def create_service_identity(self, agent_id: str, **kwargs: Any) -> ServiceIdentity:
        """Create a service identity for an agent."""
        return ServiceIdentity(**self._c._post(f"/api/v1/agents/{agent_id}/identities", json=kwargs))

    def update_service_identity(self, agent_id: str, identity_id: str, **kwargs: Any) -> ServiceIdentity:
        """Update a service identity."""
        return ServiceIdentity(**self._c._patch(f"/api/v1/agents/{agent_id}/identities/{identity_id}", json=kwargs))

    def delete_service_identity(self, agent_id: str, identity_id: str) -> dict[str, Any]:
        """Delete a service identity."""
        return self._c._delete(f"/api/v1/agents/{agent_id}/identities/{identity_id}")

    # -- Trust Domains --------------------------------------------------

    def list_trust_domains(self) -> list[TrustDomain]:
        """List all configured trust domains."""
        resp = self._c._get("/api/v1/trust-domains")
        items = resp.get("data", resp.get("trust_domains", []))
        return [TrustDomain(**d) for d in items]

    def create_trust_domain(self, *, name: str, **kwargs: Any) -> TrustDomain:
        """Create a new trust domain."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        return TrustDomain(**self._c._post("/api/v1/trust-domains", json=payload))

    def get_trust_domain(self, domain_name: str) -> TrustDomain:
        """Get a trust domain by name."""
        return TrustDomain(**self._c._get(f"/api/v1/trust-domains/{domain_name}"))

    def update_trust_domain(self, domain_name: str, **kwargs: Any) -> TrustDomain:
        """Update a trust domain."""
        return TrustDomain(**self._c._patch(f"/api/v1/trust-domains/{domain_name}", json=kwargs))

    def delete_trust_domain(self, domain_name: str) -> dict[str, Any]:
        """Delete a trust domain."""
        return self._c._delete(f"/api/v1/trust-domains/{domain_name}")

    # -- Stats & Rotation -----------------------------------------------

    def get_stats(self) -> IdentityStats:
        """Get identity statistics."""
        return IdentityStats(**self._c._get("/api/v1/identities/stats"))

    def list_expiring(self, *, days: int = 30) -> dict[str, Any]:
        """List identities expiring within N days."""
        return self._c._get("/api/v1/identities/expiring", params={"days": days})

    def get_rotation_status(self) -> dict[str, Any]:
        """Get identity rotation scheduler status."""
        return self._c._get("/api/v1/identities/rotation-status")

    def rotate_all(self) -> dict[str, Any]:
        """Trigger rotation of all expiring identities."""
        return self._c._post("/api/v1/identities/rotate-all")

    # -- WIMSE ----------------------------------------------------------

    def get_wimse_threat_model(self) -> dict[str, Any]:
        """Get the WIMSE threat model."""
        return self._c._get("/api/v1/wimse/threat-model")


class IdentityAsyncAPI:
    """Asynchronous identity operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def create_spiffe(self, agent_id: str, **kwargs: Any) -> SpiffeIdentity:
        return SpiffeIdentity(**await self._c._post(f"/api/v1/agents/{agent_id}/spiffe", json=kwargs))

    async def get_spiffe(self, agent_id: str) -> SpiffeIdentity:
        return SpiffeIdentity(**await self._c._get(f"/api/v1/agents/{agent_id}/spiffe"))

    async def rotate_spiffe(self, agent_id: str) -> SpiffeIdentity:
        return SpiffeIdentity(**await self._c._patch(f"/api/v1/agents/{agent_id}/spiffe"))

    async def revoke_spiffe(self, agent_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/agents/{agent_id}/spiffe")

    async def list_spiffe(self, **params: Any) -> list[SpiffeIdentity]:
        resp = await self._c._get("/api/v1/identities/spiffe", params=params)
        items = resp.get("data", resp.get("identities", []))
        return [SpiffeIdentity(**i) for i in items]

    async def list_service_identities(self, agent_id: str) -> list[ServiceIdentity]:
        resp = await self._c._get(f"/api/v1/agents/{agent_id}/identities")
        items = resp.get("data", resp.get("identities", []))
        return [ServiceIdentity(**i) for i in items]

    async def create_service_identity(self, agent_id: str, **kwargs: Any) -> ServiceIdentity:
        return ServiceIdentity(**await self._c._post(f"/api/v1/agents/{agent_id}/identities", json=kwargs))

    async def update_service_identity(self, agent_id: str, identity_id: str, **kwargs: Any) -> ServiceIdentity:
        return ServiceIdentity(**await self._c._patch(f"/api/v1/agents/{agent_id}/identities/{identity_id}", json=kwargs))

    async def delete_service_identity(self, agent_id: str, identity_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/agents/{agent_id}/identities/{identity_id}")

    async def list_trust_domains(self) -> list[TrustDomain]:
        resp = await self._c._get("/api/v1/trust-domains")
        items = resp.get("data", resp.get("trust_domains", []))
        return [TrustDomain(**d) for d in items]

    async def create_trust_domain(self, *, name: str, **kwargs: Any) -> TrustDomain:
        payload: dict[str, Any] = {"name": name, **kwargs}
        return TrustDomain(**await self._c._post("/api/v1/trust-domains", json=payload))

    async def get_trust_domain(self, domain_name: str) -> TrustDomain:
        return TrustDomain(**await self._c._get(f"/api/v1/trust-domains/{domain_name}"))

    async def update_trust_domain(self, domain_name: str, **kwargs: Any) -> TrustDomain:
        return TrustDomain(**await self._c._patch(f"/api/v1/trust-domains/{domain_name}", json=kwargs))

    async def delete_trust_domain(self, domain_name: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/trust-domains/{domain_name}")

    async def get_stats(self) -> IdentityStats:
        return IdentityStats(**await self._c._get("/api/v1/identities/stats"))

    async def list_expiring(self, *, days: int = 30) -> dict[str, Any]:
        return await self._c._get("/api/v1/identities/expiring", params={"days": days})

    async def get_rotation_status(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/identities/rotation-status")

    async def rotate_all(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/identities/rotate-all")

    async def get_wimse_threat_model(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/wimse/threat-model")
