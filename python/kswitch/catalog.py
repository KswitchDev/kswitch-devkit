"""Catalog API — skills, tools, sync sources, onboarding, scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import PaginatedResponse, Skill, SyncSource, Tool

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class CatalogAPI:
    """Synchronous catalog operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- Skills ---------------------------------------------------------

    def list_skills(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Skill]:
        """List skills catalog entries."""
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = self._c._get("/api/v1/skills-catalog", params=params)
        items = resp.get("data", resp.get("skills", []))
        return PaginatedResponse[Skill](
            data=[Skill(**s) for s in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    def get_skill(self, skill_id: str) -> Skill:
        """Get a skill by ID."""
        return Skill(**self._c._get(f"/api/v1/skills-catalog/{skill_id}"))

    def create_skill(self, *, name: str, **kwargs: Any) -> Skill:
        """Create a new skill catalog entry."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        return Skill(**self._c._post("/api/v1/skills-catalog", json=payload))

    def delete_skill(self, skill_id: str) -> dict[str, Any]:
        """Delete a skill catalog entry."""
        return self._c._delete(f"/api/v1/skills-catalog/{skill_id}")

    def approve_skill(self, skill_id: str, **kwargs: Any) -> dict[str, Any]:
        """Approve a pending skill."""
        return self._c._post(f"/api/v1/skills-catalog/{skill_id}/approve", json=kwargs)

    def reject_skill(self, skill_id: str, **kwargs: Any) -> dict[str, Any]:
        """Reject a pending skill."""
        return self._c._post(f"/api/v1/skills-catalog/{skill_id}/reject", json=kwargs)

    def autocomplete_skills(self, *, query: str, **params: Any) -> dict[str, Any]:
        """Autocomplete skills by name."""
        return self._c._get("/api/v1/skills-catalog/autocomplete", params={"q": query, **params})

    def infer_skills(self, **kwargs: Any) -> dict[str, Any]:
        """Analyse code/config to infer skills."""
        return self._c._post("/api/v1/skills-inference/analyse", json=kwargs)

    # -- Tools ----------------------------------------------------------

    def list_tools(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Tool]:
        """List tools catalog entries."""
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = self._c._get("/api/v1/tools-catalog", params=params)
        items = resp.get("data", resp.get("tools", []))
        return PaginatedResponse[Tool](
            data=[Tool(**t) for t in items],
            total=resp.get("total"),
            page=resp.get("page"),
            page_size=resp.get("page_size"),
        )

    def get_tool(self, tool_id: str) -> Tool:
        """Get a tool by ID."""
        return Tool(**self._c._get(f"/api/v1/tools-catalog/{tool_id}"))

    def create_tool(self, *, name: str, **kwargs: Any) -> Tool:
        """Create a new tool catalog entry."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        return Tool(**self._c._post("/api/v1/tools-catalog", json=payload))

    def delete_tool(self, tool_id: str) -> dict[str, Any]:
        """Delete a tool catalog entry."""
        return self._c._delete(f"/api/v1/tools-catalog/{tool_id}")

    def approve_tool(self, tool_id: str, **kwargs: Any) -> dict[str, Any]:
        """Approve a pending tool."""
        return self._c._post(f"/api/v1/tools-catalog/{tool_id}/approve", json=kwargs)

    def reject_tool(self, tool_id: str, **kwargs: Any) -> dict[str, Any]:
        """Reject a pending tool."""
        return self._c._post(f"/api/v1/tools-catalog/{tool_id}/reject", json=kwargs)

    def autocomplete_tools(self, *, query: str, **params: Any) -> dict[str, Any]:
        """Autocomplete tools by name."""
        return self._c._get("/api/v1/tools-catalog/autocomplete", params={"q": query, **params})

    def backfill_tools(self, **kwargs: Any) -> dict[str, Any]:
        """Backfill tool catalog from MCP server declarations."""
        return self._c._post("/api/v1/tools-catalog/backfill", json=kwargs)

    def sync_tools(self) -> dict[str, Any]:
        """Sync tools catalog from connected MCP servers."""
        return self._c._post("/api/v1/tools-catalog/sync")

    # -- Sync Sources ---------------------------------------------------

    def list_sync_sources(self) -> list[SyncSource]:
        """List all sync sources."""
        resp = self._c._get("/api/v1/sync-sources")
        items = resp.get("data", resp.get("sources", []))
        return [SyncSource(**s) for s in items]

    def create_sync_source(self, *, name: str, **kwargs: Any) -> SyncSource:
        """Add a new sync source."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        return SyncSource(**self._c._post("/api/v1/sync-sources", json=payload))

    def delete_sync_source(self, source_id: str) -> dict[str, Any]:
        """Delete a sync source."""
        return self._c._delete(f"/api/v1/sync-sources/{source_id}")

    def trigger_sync_source(self, source_id: str) -> dict[str, Any]:
        """Trigger sync for a specific source."""
        return self._c._post(f"/api/v1/sync-sources/{source_id}/sync")

    def approve_sync_source(self, source_id: str, **kwargs: Any) -> dict[str, Any]:
        """Approve a pending sync source."""
        return self._c._post(f"/api/v1/sync-sources/{source_id}/approve", json=kwargs)

    def reject_sync_source(self, source_id: str, **kwargs: Any) -> dict[str, Any]:
        """Reject a pending sync source."""
        return self._c._post(f"/api/v1/sync-sources/{source_id}/reject", json=kwargs)

    # -- Registry Sync --------------------------------------------------

    def trigger_registry_sync(self) -> dict[str, Any]:
        """Trigger full registry sync."""
        return self._c._post("/api/v1/registry-sync/trigger")

    def sync_skills_from_registry(self, **kwargs: Any) -> dict[str, Any]:
        """Sync skills from registry."""
        return self._c._post("/api/v1/registry-sync/skills", json=kwargs)

    def get_sync_status(self) -> dict[str, Any]:
        """Get registry sync status."""
        return self._c._get("/api/v1/registry-sync/status")

    # -- Pending & Audit ------------------------------------------------

    def list_pending_catalog(self) -> dict[str, Any]:
        """List all pending catalog items awaiting approval."""
        return self._c._get("/api/v1/pending-catalog")

    def get_catalog_audit(self, **params: Any) -> dict[str, Any]:
        """Get catalog audit log."""
        return self._c._get("/api/v1/catalog-audit", params=params)

    # -- Scanner --------------------------------------------------------

    def get_scanner_stats(self) -> dict[str, Any]:
        """Get scanner statistics."""
        return self._c._get("/api/v1/scanner/stats")

    def trigger_scan(self, **kwargs: Any) -> dict[str, Any]:
        """Trigger a repository scan."""
        return self._c._post("/api/v1/scanner/scan", json=kwargs)

    def list_scan_runs(self, **params: Any) -> dict[str, Any]:
        """List scan run history."""
        return self._c._get("/api/v1/scanner/runs", params=params)

    def get_scan_run(self, scan_id: str) -> dict[str, Any]:
        """Get a specific scan run."""
        return self._c._get(f"/api/v1/scanner/runs/{scan_id}")

    def get_scan_findings(self, scan_id: str) -> dict[str, Any]:
        """Get findings for a scan run."""
        return self._c._get(f"/api/v1/scanner/runs/{scan_id}/findings")

    def update_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update a scan finding."""
        return self._c._patch(f"/api/v1/scanner/findings/{finding_id}", json=kwargs)

    def link_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        """Link a scan finding to an agent."""
        return self._c._post(f"/api/v1/scanner/findings/{finding_id}/link", json=kwargs)

    # -- Onboarding -----------------------------------------------------

    def get_onboard_status(self) -> dict[str, Any]:
        """Get onboarding service status."""
        return self._c._get("/api/v1/onboard/status")

    def run_onboard(self, **kwargs: Any) -> dict[str, Any]:
        """Run onboarding for a repository."""
        return self._c._post("/api/v1/onboard/run", json=kwargs)

    def get_onboard_results(self) -> dict[str, Any]:
        """Get onboarding results."""
        return self._c._get("/api/v1/onboard/results")

    def start_onboard_service(self, **kwargs: Any) -> dict[str, Any]:
        """Start the onboarding service."""
        return self._c._post("/api/v1/onboard/service/start", json=kwargs)

    def stop_onboard_service(self, **kwargs: Any) -> dict[str, Any]:
        """Stop the onboarding service."""
        return self._c._post("/api/v1/onboard/service/stop", json=kwargs)

    def list_onboard_repos(self) -> dict[str, Any]:
        """List onboarding repositories."""
        return self._c._get("/api/v1/onboard/repos")

    def add_onboard_repo(self, **kwargs: Any) -> dict[str, Any]:
        """Add a repository to onboarding."""
        return self._c._post("/api/v1/onboard/repos", json=kwargs)

    def delete_onboard_repo(self, repo_id: str) -> dict[str, Any]:
        """Remove a repository from onboarding."""
        return self._c._delete(f"/api/v1/onboard/repos/{repo_id}")

    def update_onboard_repo(self, repo_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update an onboarding repository."""
        return self._c._patch(f"/api/v1/onboard/repos/{repo_id}", json=kwargs)


class CatalogAsyncAPI:
    """Asynchronous catalog operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def list_skills(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Skill]:
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = await self._c._get("/api/v1/skills-catalog", params=params)
        items = resp.get("data", resp.get("skills", []))
        return PaginatedResponse[Skill](data=[Skill(**s) for s in items], total=resp.get("total"), page=resp.get("page"), page_size=resp.get("page_size"))

    async def get_skill(self, skill_id: str) -> Skill:
        return Skill(**await self._c._get(f"/api/v1/skills-catalog/{skill_id}"))

    async def create_skill(self, *, name: str, **kwargs: Any) -> Skill:
        payload: dict[str, Any] = {"name": name, **kwargs}
        return Skill(**await self._c._post("/api/v1/skills-catalog", json=payload))

    async def delete_skill(self, skill_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/skills-catalog/{skill_id}")

    async def approve_skill(self, skill_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/skills-catalog/{skill_id}/approve", json=kwargs)

    async def reject_skill(self, skill_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/skills-catalog/{skill_id}/reject", json=kwargs)

    async def autocomplete_skills(self, *, query: str, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/skills-catalog/autocomplete", params={"q": query, **params})

    async def infer_skills(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/skills-inference/analyse", json=kwargs)

    async def list_tools(self, *, page: int = 1, page_size: int = 50, **filters: Any) -> PaginatedResponse[Tool]:
        params: dict[str, Any] = {"page": page, "page_size": page_size, **filters}
        resp = await self._c._get("/api/v1/tools-catalog", params=params)
        items = resp.get("data", resp.get("tools", []))
        return PaginatedResponse[Tool](data=[Tool(**t) for t in items], total=resp.get("total"), page=resp.get("page"), page_size=resp.get("page_size"))

    async def get_tool(self, tool_id: str) -> Tool:
        return Tool(**await self._c._get(f"/api/v1/tools-catalog/{tool_id}"))

    async def create_tool(self, *, name: str, **kwargs: Any) -> Tool:
        payload: dict[str, Any] = {"name": name, **kwargs}
        return Tool(**await self._c._post("/api/v1/tools-catalog", json=payload))

    async def delete_tool(self, tool_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/tools-catalog/{tool_id}")

    async def approve_tool(self, tool_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/tools-catalog/{tool_id}/approve", json=kwargs)

    async def reject_tool(self, tool_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/tools-catalog/{tool_id}/reject", json=kwargs)

    async def autocomplete_tools(self, *, query: str, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/tools-catalog/autocomplete", params={"q": query, **params})

    async def backfill_tools(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/tools-catalog/backfill", json=kwargs)

    async def sync_tools(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/tools-catalog/sync")

    async def list_sync_sources(self) -> list[SyncSource]:
        resp = await self._c._get("/api/v1/sync-sources")
        items = resp.get("data", resp.get("sources", []))
        return [SyncSource(**s) for s in items]

    async def create_sync_source(self, *, name: str, **kwargs: Any) -> SyncSource:
        payload: dict[str, Any] = {"name": name, **kwargs}
        return SyncSource(**await self._c._post("/api/v1/sync-sources", json=payload))

    async def delete_sync_source(self, source_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/sync-sources/{source_id}")

    async def trigger_sync_source(self, source_id: str) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/sync-sources/{source_id}/sync")

    async def approve_sync_source(self, source_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/sync-sources/{source_id}/approve", json=kwargs)

    async def reject_sync_source(self, source_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/sync-sources/{source_id}/reject", json=kwargs)

    async def trigger_registry_sync(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/registry-sync/trigger")

    async def sync_skills_from_registry(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/registry-sync/skills", json=kwargs)

    async def get_sync_status(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/registry-sync/status")

    async def list_pending_catalog(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/pending-catalog")

    async def get_catalog_audit(self, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/catalog-audit", params=params)

    async def get_scanner_stats(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/scanner/stats")

    async def trigger_scan(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/scanner/scan", json=kwargs)

    async def list_scan_runs(self, **params: Any) -> dict[str, Any]:
        return await self._c._get("/api/v1/scanner/runs", params=params)

    async def get_scan_run(self, scan_id: str) -> dict[str, Any]:
        return await self._c._get(f"/api/v1/scanner/runs/{scan_id}")

    async def get_scan_findings(self, scan_id: str) -> dict[str, Any]:
        return await self._c._get(f"/api/v1/scanner/runs/{scan_id}/findings")

    async def update_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._patch(f"/api/v1/scanner/findings/{finding_id}", json=kwargs)

    async def link_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/scanner/findings/{finding_id}/link", json=kwargs)

    async def get_onboard_status(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/onboard/status")

    async def run_onboard(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/onboard/run", json=kwargs)

    async def get_onboard_results(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/onboard/results")

    async def start_onboard_service(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/onboard/service/start", json=kwargs)

    async def stop_onboard_service(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/onboard/service/stop", json=kwargs)

    async def list_onboard_repos(self) -> dict[str, Any]:
        return await self._c._get("/api/v1/onboard/repos")

    async def add_onboard_repo(self, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post("/api/v1/onboard/repos", json=kwargs)

    async def delete_onboard_repo(self, repo_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/onboard/repos/{repo_id}")

    async def update_onboard_repo(self, repo_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._patch(f"/api/v1/onboard/repos/{repo_id}", json=kwargs)
