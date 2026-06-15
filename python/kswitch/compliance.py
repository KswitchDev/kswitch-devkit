"""Compliance API — toxic combos, boundary analysis, risk scoring."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import (
    BoundaryAnalysis,
    FleetRiskSummary,
    RiskScore,
    ToxicComboDashboard,
    ToxicComboResult,
    ToxicComboRule,
)

if TYPE_CHECKING:
    from .client import KSwitchAsyncClient, KSwitchClient


class ComplianceAPI:
    """Synchronous compliance operations."""

    def __init__(self, client: KSwitchClient) -> None:
        self._c = client

    # -- Toxic Combos ---------------------------------------------------

    def evaluate_toxic_combos(self, agent_id: str) -> ToxicComboResult:
        """Evaluate an agent for toxic skill/permission combinations."""
        return ToxicComboResult(**self._c._post(f"/api/v1/agents/{agent_id}/evaluate-toxic-combos"))

    def evaluate_all(self) -> dict[str, Any]:
        """Run toxic combo evaluation across all agents."""
        return self._c._post("/api/v1/toxic-combos/evaluate-all")

    def get_toxic_combo_history(self, agent_id: str) -> dict[str, Any]:
        """Get toxic combo evaluation history for an agent."""
        return self._c._get(f"/api/v1/agents/{agent_id}/toxic-combo-history")

    def create_waiver(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
        """Create a toxic combo waiver for an agent."""
        return self._c._post(f"/api/v1/agents/{agent_id}/toxic-combo-waiver", json=kwargs)

    # -- Toxic Combo Rules ----------------------------------------------

    def list_rules(self, **params: Any) -> list[ToxicComboRule]:
        """List all toxic combo rules."""
        resp = self._c._get("/api/v1/toxic-combos/rules", params=params)
        items = resp.get("data", resp.get("rules", []))
        return [ToxicComboRule(**r) for r in items]

    def create_rule(self, *, name: str, **kwargs: Any) -> ToxicComboRule:
        """Create a new toxic combo rule."""
        payload: dict[str, Any] = {"name": name, **kwargs}
        return ToxicComboRule(**self._c._post("/api/v1/toxic-combos/rules", json=payload))

    def get_rule(self, rule_id: str) -> ToxicComboRule:
        """Get a toxic combo rule by ID."""
        return ToxicComboRule(**self._c._get(f"/api/v1/toxic-combos/rules/{rule_id}"))

    def update_rule(self, rule_id: str, **kwargs: Any) -> ToxicComboRule:
        """Update a toxic combo rule."""
        return ToxicComboRule(**self._c._patch(f"/api/v1/toxic-combos/rules/{rule_id}", json=kwargs))

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        """Delete a toxic combo rule."""
        return self._c._delete(f"/api/v1/toxic-combos/rules/{rule_id}")

    # -- Dashboard ------------------------------------------------------

    def get_dashboard(self) -> ToxicComboDashboard:
        """Get the toxic combo compliance dashboard."""
        return ToxicComboDashboard(**self._c._get("/api/v1/toxic-combos/dashboard"))

    # -- Boundary Analysis ----------------------------------------------

    def analyze_boundaries(self, agent_id: str) -> BoundaryAnalysis:
        """Analyze boundary crossings for an agent."""
        return BoundaryAnalysis(**self._c._get(f"/api/v1/boundary-analysis/{agent_id}"))

    # -- Risk Scoring (convenience — wraps compliance + boundary) -------

    def assess_risk(self, agent_id: str) -> RiskScore:
        """Composite risk assessment for an agent.

        Combines toxic combo evaluation + boundary analysis into a score.
        This is a client-side convenience that calls two endpoints.
        """
        toxic = self.evaluate_toxic_combos(agent_id)
        boundary = self.analyze_boundaries(agent_id)

        score = 0
        score += len(toxic.violations) * 100
        score += len(boundary.tier_violations) * 50
        score += len(boundary.division_violations) * 30
        score += len(boundary.data_classification_violations) * 40

        if score == 0:
            level = "clean"
        elif score < 50:
            level = "low"
        elif score < 150:
            level = "medium"
        elif score < 300:
            level = "high"
        else:
            level = "critical"

        return RiskScore(
            agent_id=agent_id,
            score=score,
            level=level,
            toxic_violations=len(toxic.violations),
            boundary_crossings=(
                len(boundary.tier_violations)
                + len(boundary.division_violations)
                + len(boundary.data_classification_violations)
            ),
        )


class ComplianceAsyncAPI:
    """Asynchronous compliance operations."""

    def __init__(self, client: KSwitchAsyncClient) -> None:
        self._c = client

    async def evaluate_toxic_combos(self, agent_id: str) -> ToxicComboResult:
        return ToxicComboResult(**await self._c._post(f"/api/v1/agents/{agent_id}/evaluate-toxic-combos"))

    async def evaluate_all(self) -> dict[str, Any]:
        return await self._c._post("/api/v1/toxic-combos/evaluate-all")

    async def get_toxic_combo_history(self, agent_id: str) -> dict[str, Any]:
        return await self._c._get(f"/api/v1/agents/{agent_id}/toxic-combo-history")

    async def create_waiver(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
        return await self._c._post(f"/api/v1/agents/{agent_id}/toxic-combo-waiver", json=kwargs)

    async def list_rules(self, **params: Any) -> list[ToxicComboRule]:
        resp = await self._c._get("/api/v1/toxic-combos/rules", params=params)
        items = resp.get("data", resp.get("rules", []))
        return [ToxicComboRule(**r) for r in items]

    async def create_rule(self, *, name: str, **kwargs: Any) -> ToxicComboRule:
        payload: dict[str, Any] = {"name": name, **kwargs}
        return ToxicComboRule(**await self._c._post("/api/v1/toxic-combos/rules", json=payload))

    async def get_rule(self, rule_id: str) -> ToxicComboRule:
        return ToxicComboRule(**await self._c._get(f"/api/v1/toxic-combos/rules/{rule_id}"))

    async def update_rule(self, rule_id: str, **kwargs: Any) -> ToxicComboRule:
        return ToxicComboRule(**await self._c._patch(f"/api/v1/toxic-combos/rules/{rule_id}", json=kwargs))

    async def delete_rule(self, rule_id: str) -> dict[str, Any]:
        return await self._c._delete(f"/api/v1/toxic-combos/rules/{rule_id}")

    async def get_dashboard(self) -> ToxicComboDashboard:
        return ToxicComboDashboard(**await self._c._get("/api/v1/toxic-combos/dashboard"))

    async def analyze_boundaries(self, agent_id: str) -> BoundaryAnalysis:
        return BoundaryAnalysis(**await self._c._get(f"/api/v1/boundary-analysis/{agent_id}"))

    async def assess_risk(self, agent_id: str) -> RiskScore:
        toxic = await self.evaluate_toxic_combos(agent_id)
        boundary = await self.analyze_boundaries(agent_id)
        score = 0
        score += len(toxic.violations) * 100
        score += len(boundary.tier_violations) * 50
        score += len(boundary.division_violations) * 30
        score += len(boundary.data_classification_violations) * 40
        if score == 0:
            level = "clean"
        elif score < 50:
            level = "low"
        elif score < 150:
            level = "medium"
        elif score < 300:
            level = "high"
        else:
            level = "critical"
        return RiskScore(
            agent_id=agent_id, score=score, level=level,
            toxic_violations=len(toxic.violations),
            boundary_crossings=(
                len(boundary.tier_violations)
                + len(boundary.division_violations)
                + len(boundary.data_classification_violations)
            ),
        )
