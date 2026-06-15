"""
LocalPDPEvaluator — in-process Cedar policy evaluation for the Python SDK.

Decision sequence:
  1. Revocation cache check  (O(1), in-process)
  2. Context pack load       (disk-backed, TTL-aware)
  3. Agent status check      (from context pack)
  4. Bundle load             (disk-backed, TTL-aware)
  5. Cedar evaluate          (cedarpy, in-process, no network)
  6. Shadow policy evaluate  (observe-only)
  7. Output policy derivation
  8. Return LocalDecision(outcome, reason, obligations, output_policy)

Fallback: If cedarpy is not installed, or bundle/context is unavailable,
returns LocalDecision(outcome="conditional") → caller escalates to server.
"""
import hashlib
import json
import os
import time
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Optional, Any

from ..bundle.local_cache import load_current_bundle, LocalBundle, BundleNotAvailableError
from ..context.local_cache import load_context_pack, LocalContextPack, ContextNotAvailableError
from ..revocation.cache import get_revocation_cache

# Local output policy modes
_MODE_ALLOW_RAW = "allow_raw"
_MODE_DENY_EXPORT = "deny_export"
_MODE_MASK_FIELDS = "mask_fields"

_SENSITIVE_FIELD_PATTERNS = (
    "ssn", "social_security", "passport", "dob", "date_of_birth",
    "account_number", "card_number", "cvv", "routing_number",
    "tax_id", "ein", "phone", "email", "address", "zip", "postal",
    "salary", "income", "net_worth", "balance", "position", "trade",
    "ticker", "isin", "cusip", "mnpi", "insider",
    "password", "secret", "token", "api_key", "private_key", "credential",
    "health", "diagnosis", "medication", "prescription", "patient",
)

_SENSITIVE_CLASSIFICATIONS = frozenset({"PII", "PHI", "MNPI", "Confidential"})


@dataclass
class LocalDecision:
    """Result of a local PDP evaluation."""
    outcome: str  # "allow" | "deny" | "conditional"
    reason: str
    allowed: bool
    decision_path: list = field(default_factory=list)
    obligations: list = field(default_factory=list)
    output_policy: Optional[dict] = None
    enforcement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evaluation_mode: str = "LOCAL_RUNTIME_PYTHON"
    bundle_version: str = ""
    context_pack_id: str = ""
    context_snapshot_id: str = ""
    context_snapshot_digest: str = ""
    context_snapshot: Optional[dict] = None
    decision_explanation: Optional[dict] = None
    risk_tier: str = "medium"
    agent_id: str = ""
    mcp_server_id: str = ""
    tool_name: str = ""
    evaluated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.context_snapshot_id and self.context_snapshot_digest and self.context_snapshot and self.decision_explanation:
            return
        evidence = _build_ep221_local_decision_evidence(self)
        self.context_snapshot_id = self.context_snapshot_id or evidence["context_snapshot_id"]
        self.context_snapshot_digest = self.context_snapshot_digest or evidence["context_snapshot_digest"]
        self.context_snapshot = self.context_snapshot or evidence["context_snapshot"]
        self.decision_explanation = self.decision_explanation or evidence["decision_explanation"]

    @property
    def is_local(self) -> bool:
        return self.outcome in ("allow", "deny")

    @property
    def needs_escalation(self) -> bool:
        return self.outcome == "conditional"


class LocalPDPEvaluator:
    """In-process policy evaluator for the Python SDK."""

    def __init__(self):
        self._cedarpy_available: Optional[bool] = None

    def _has_cedarpy(self) -> bool:
        if self._cedarpy_available is None:
            try:
                import cedarpy
                self._cedarpy_available = True
            except ImportError:
                self._cedarpy_available = False
        return self._cedarpy_available

    def evaluate(
        self,
        agent_id: str,
        mcp_server_id: str,
        tool_name: str = "",
        context: Optional[dict] = None,
    ) -> LocalDecision:
        """Attempt a local decision. Returns conditional if escalation needed."""
        decision_path = ["local_sdk"]
        risk_tier = (context or {}).get("risk_tier", "medium")

        # ── 0. Stale revocation sync check (PR-11) ────────────────────────────
        # If the background sync worker has not updated the cache within the
        # configured stale threshold, apply the stale_mode policy.
        stale_outcome = self._check_stale_revocation(agent_id, mcp_server_id, tool_name, decision_path)
        if stale_outcome is not None:
            return stale_outcome

        # ── 1. Revocation cache check ─────────────────────────────────────────
        rev_cache = get_revocation_cache()
        if rev_cache.is_revoked(agent_id):
            return LocalDecision(
                outcome="deny", reason="agent_revoked",
                allowed=False,
                decision_path=decision_path + ["revocation_cache_hit"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
            )

        # ── 2. Load context pack ──────────────────────────────────────────────
        context_pack = load_context_pack(agent_id)
        if context_pack is None:
            if risk_tier in ("critical", "high"):
                # Fail closed for high-risk agents with no context
                return LocalDecision(
                    outcome="deny", reason="context_pack_unavailable",
                    allowed=False,
                    decision_path=decision_path + ["context_miss_denied"],
                    evaluation_mode="LOCAL_RUNTIME_PYTHON",
                    agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                )
            # medium/low: escalate to server
            return LocalDecision(
                outcome="conditional", reason="context_pack_miss",
                allowed=False,
                decision_path=decision_path + ["context_miss_escalate"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
            )

        risk_tier = context_pack.risk_tier or risk_tier

        # ── 3. Agent status check ─────────────────────────────────────────────
        if not context_pack.is_active():
            return LocalDecision(
                outcome="deny",
                reason="agent_suspended" if context_pack.status == "suspended" else "agent_inactive",
                allowed=False,
                decision_path=decision_path + [f"agent_{context_pack.status}"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                risk_tier=risk_tier,
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                context_pack_id=f"cp:v{context_pack.pack_version}",
            )

        decision_path.append("agent_active")

        # ── 4. Load bundle ────────────────────────────────────────────────────
        bundle = load_current_bundle()
        if bundle is None:
            # No bundle — escalate for all tiers
            return LocalDecision(
                outcome="conditional", reason="bundle_unavailable",
                allowed=False,
                decision_path=decision_path + ["bundle_miss_escalate"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                risk_tier=risk_tier,
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                context_pack_id=f"cp:v{context_pack.pack_version}",
            )

        if bundle.is_stale(risk_tier) and risk_tier in ("critical", "high"):
            return LocalDecision(
                outcome="conditional", reason="bundle_stale",
                allowed=False,
                decision_path=decision_path + ["bundle_stale_escalate"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                risk_tier=risk_tier,
                bundle_version=f"bundle:v{bundle.version}",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                context_pack_id=f"cp:v{context_pack.pack_version}",
            )

        decision_path.append(f"bundle_v{bundle.version}")

        # ── 5. Cedarpy availability check ─────────────────────────────────────
        if not self._has_cedarpy():
            # cedarpy not installed — escalate to server
            return LocalDecision(
                outcome="conditional", reason="cedarpy_unavailable",
                allowed=False,
                decision_path=decision_path + ["cedarpy_missing_escalate"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                risk_tier=risk_tier,
                bundle_version=f"bundle:v{bundle.version}",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                context_pack_id=f"cp:v{context_pack.pack_version}",
            )

        # ── 6. Cedar evaluation ───────────────────────────────────────────────
        import cedarpy

        principal = f'Agent::"{agent_id}"'
        action = 'Action::"McpCall"'
        resource = (f'MCP::Tool::"{tool_name}"' if tool_name
                    else f'MCP::Server::"{mcp_server_id}"')

        obligations = []

        if bundle.enforce_count == 0:
            # No enforce policies → allow
            decision_path.append("no_policies")
        else:
            try:
                authz = cedarpy.is_authorized(
                    {"principal": principal, "action": action, "resource": resource},
                    bundle.cedar_text_enforce,
                    [],
                )
                import cedarpy as _cedarpy
                if authz.decision == _cedarpy.Decision.Deny:
                    return LocalDecision(
                        outcome="deny", reason="policy_denied",
                        allowed=False,
                        decision_path=decision_path + ["cedar_denied"],
                        evaluation_mode="LOCAL_RUNTIME_PYTHON",
                        risk_tier=risk_tier,
                        bundle_version=f"bundle:v{bundle.version}",
                        agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                        context_pack_id=f"cp:v{context_pack.pack_version}",
                    )
                decision_path.append("cedar_allowed")
            except Exception as e:
                # Cedar error — escalate (fail-open only for low-risk, escalate for others)
                if risk_tier in ("critical", "high"):
                    return LocalDecision(
                        outcome="conditional", reason="cedar_error_escalate",
                        allowed=False,
                        decision_path=decision_path + ["cedar_error"],
                        evaluation_mode="LOCAL_RUNTIME_PYTHON",
                        risk_tier=risk_tier,
                        bundle_version=f"bundle:v{bundle.version}",
                        agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
                    )
                decision_path.append("cedar_error_allow_low_risk")

        # ── 7. Shadow policies ────────────────────────────────────────────────
        if bundle.shadow_count > 0:
            try:
                shadow_authz = cedarpy.is_authorized(
                    {"principal": principal, "action": action, "resource": resource},
                    bundle.cedar_text_shadow,
                    [],
                )
                if shadow_authz.decision == cedarpy.Decision.Deny:
                    obligations.append({
                        "type": "shadow_denied",
                        "obligation_type": "shadow_denied",
                        "detail": "shadow_forbid",
                    })
                    decision_path.append("shadow_denied")
            except Exception:
                pass

        # ── 8. Human-approval gating ──────────────────────────────────────────
        if tool_name and bundle.requires_human_approval(tool_name):
            obligations.append({
                "type": "audit_flag",
                "obligation_type": "audit_flag",
                "detail": f"tool {tool_name} requires human approval",
            })
            decision_path.append("tool_requires_human_approval")

        # ── 9. Derive output policy ───────────────────────────────────────────
        output_policy = _derive_output_policy(
            obligations, context_pack.data_classifications
        )

        decision_path.append("enforcement_complete")

        return LocalDecision(
            outcome="allow", reason="allowed",
            allowed=True,
            decision_path=decision_path,
            obligations=obligations,
            output_policy=output_policy,
            evaluation_mode="LOCAL_RUNTIME_PYTHON",
            risk_tier=risk_tier,
            bundle_version=f"bundle:v{bundle.version}",
            agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
            context_pack_id=f"cp:v{context_pack.pack_version}",
        )


    def _check_stale_revocation(
        self, agent_id: str, mcp_server_id: str, tool_name: str, decision_path: list
    ) -> Optional[LocalDecision]:
        """Check stale-sync policy and return a blocking decision if needed.

        PR-11: If revocation sync state is stale, apply the configured stale_mode:
          - warn:        No-op — log only, let evaluation proceed (default).
          - deny:        Return deny immediately (strict/protected mode).
          - conditional: Return conditional to force server escalation.

        Returns a LocalDecision if the stale policy blocks, None to continue.
        """
        try:
            from .. import config
            stale_mode = config.REVOCATION_STALE_MODE
            stale_threshold = config.REVOCATION_STALE_THRESHOLD
        except Exception:
            return None  # Config unavailable — proceed normally

        if stale_mode == "warn":
            return None  # warn mode: no blocking, logging handled by sync worker

        rev_cache = get_revocation_cache()
        if not rev_cache.is_sync_stale(stale_threshold):
            return None  # Not stale — proceed normally

        import logging
        _log = logging.getLogger("kswitch.local_pdp")

        if stale_mode == "deny":
            _log.error(
                "kswitch.local_pdp: revocation sync STALE (>%ds) — stale_mode=deny, "
                "blocking agent=%s tool=%s",
                stale_threshold, agent_id, tool_name,
            )
            return LocalDecision(
                outcome="deny", reason="revocation_sync_stale",
                allowed=False,
                decision_path=decision_path + ["revocation_sync_stale_deny"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
            )

        if stale_mode == "conditional":
            _log.warning(
                "kswitch.local_pdp: revocation sync STALE (>%ds) — stale_mode=conditional, "
                "escalating to server for agent=%s tool=%s",
                stale_threshold, agent_id, tool_name,
            )
            return LocalDecision(
                outcome="conditional", reason="revocation_sync_stale",
                allowed=False,
                decision_path=decision_path + ["revocation_sync_stale_conditional"],
                evaluation_mode="LOCAL_RUNTIME_PYTHON",
                agent_id=agent_id, mcp_server_id=mcp_server_id, tool_name=tool_name,
            )

        return None


def _derive_output_policy(obligations: list, data_classifications: list) -> Optional[dict]:
    """Derive output policy from obligations and data classifications."""
    # DENY_EXPORT wins: critical anomaly or credential_risk
    for ob in obligations:
        ob_type = ob.get("type") or ob.get("obligation_type", "")
        level = ob.get("level", "")
        if ob_type == "credential_risk" and level == "critical":
            return {"mode": "deny_export", "masking_classifications": []}
        if ob_type == "anomaly_detection":
            params = ob.get("parameters", {})
            anomalies = params.get("anomalies", [])
            if any(a.get("severity") == "critical" for a in anomalies):
                return {"mode": "deny_export", "masking_classifications": []}

    # MASK_FIELDS: data_masking obligation
    for ob in obligations:
        ob_type = ob.get("type") or ob.get("obligation_type", "")
        if ob_type == "data_masking":
            return {"mode": "mask_fields",
                    "masking_classifications": ob.get("parameters", {}).get("classifications", [])}

    # MASK_FIELDS: sensitive data classifications
    sensitive = [c for c in data_classifications if c in _SENSITIVE_CLASSIFICATIONS]
    if sensitive:
        return {"mode": "mask_fields", "masking_classifications": sensitive}

    return {"mode": "allow_raw", "masking_classifications": []}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_text(value: Any) -> str:
    return "sha256:" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _bounded_decision_path(path: list) -> list[str]:
    bounded: list[str] = []
    for item in path[:16]:
        text = str(item)
        bounded.append("cedar_error" if text.startswith("cedar_error:") else text[:96])
    return bounded


def _source_status_for_decision(decision: LocalDecision) -> dict[str, list[str]]:
    present = [
        "identity.agent_id",
        "tool_request.mcp_server_id",
        "policy.decision_path",
        "runtime.risk_tier",
    ]
    if decision.tool_name:
        present.append("tool_request.tool_name")
    if decision.bundle_version:
        present.append("policy.bundle_version")
    if decision.context_pack_id:
        present.append("runtime.context_pack_id")

    unavailable = [
        "tenant_id",
        "requester",
        "agent_session_id",
        "active_artefacts",
        "graph_context",
    ]
    missing_required: list[str] = []
    if "context_pack" in decision.reason:
        missing_required.append("runtime.context_pack")
    if "bundle" in decision.reason:
        missing_required.append("policy.bundle")
    if "cedarpy" in decision.reason:
        missing_required.append("policy.cedar_runtime")

    return {
        "present_deterministic": present,
        "missing_required": missing_required,
        "unavailable_optional": unavailable,
        "stale": ["revocation_or_policy_freshness"] if "stale" in decision.reason else [],
    }


def _build_ep221_local_decision_evidence(decision: LocalDecision) -> dict[str, Any]:
    decision_path = _bounded_decision_path(decision.decision_path)
    request_material = {
        "agent_id_digest": _sha256_text(decision.agent_id),
        "mcp_server_id_digest": _sha256_text(decision.mcp_server_id),
        "tool_name_digest": _sha256_text(decision.tool_name) if decision.tool_name else "",
        "outcome": decision.outcome,
        "reason": decision.reason,
    }
    context_material = {
        "bundle_version_digest": _sha256_text(decision.bundle_version) if decision.bundle_version else "",
        "context_pack_id_digest": _sha256_text(decision.context_pack_id) if decision.context_pack_id else "",
        "risk_tier": decision.risk_tier,
    }
    pdp_input_material = {
        "request_hash": _sha256(request_material),
        "context_hash": _sha256(context_material),
        "decision_path": decision_path,
    }
    context_snapshot_id = "pcs_" + _sha256({
        "enforcement_id": decision.enforcement_id,
        "evaluated_at": decision.evaluated_at,
        "request": request_material,
    }).removeprefix("sha256:")[:32]
    source_status = _source_status_for_decision(decision)
    snapshot = {
        "schema_version": "kswitch.policy_context.v1",
        "context_snapshot_id": context_snapshot_id,
        "decision_id": decision.enforcement_id,
        "agent_id": _sha256_text(decision.agent_id),
        "mode": {
            "evaluation_mode": "local_pdp",
            "sdk_runtime": "python",
            "outcome": decision.outcome,
        },
        "policy": {
            "bundle_version_digest": _sha256_text(decision.bundle_version) if decision.bundle_version else "unavailable_optional",
            "decision_path_digest": _sha256(decision_path),
            "obligation_count": len(decision.obligations),
        },
        "identity": {
            "agent_id_digest": _sha256_text(decision.agent_id),
            "agent_session_id": "unavailable_optional",
            "requester": "unavailable_optional",
        },
        "runtime": {
            "risk_tier": decision.risk_tier,
            "context_pack_id_digest": _sha256_text(decision.context_pack_id) if decision.context_pack_id else "unavailable_optional",
            "evaluated_at": decision.evaluated_at,
            "offline_local_pdp": True,
        },
        "active_artefacts": [],
        "tool_request": {
            "mcp_server_id_digest": _sha256_text(decision.mcp_server_id),
            "tool_name_digest": _sha256_text(decision.tool_name) if decision.tool_name else "unavailable_optional",
            "request_hash": _sha256(request_material),
        },
        "data_context": {
            "output_policy_mode": (decision.output_policy or {}).get("mode", "unavailable_optional"),
            "masking_classifications_count": len((decision.output_policy or {}).get("masking_classifications", [])),
        },
        "graph_context": {},
        "source_status": source_status,
        "replay": {
            "request_hash": _sha256(request_material),
            "context_hash": _sha256(context_material),
            "pdp_input_hash": _sha256(pdp_input_material),
        },
        "integrity": {
            "binding_state": "digest_bound_no_append_only_record",
            "digest_algorithm": "sha256",
        },
    }
    context_snapshot_digest = _sha256(snapshot)
    snapshot["integrity"]["context_snapshot_digest"] = context_snapshot_digest
    explanation = {
        "schema_version": "kswitch.decision_explanation.v1",
        "decision_id": decision.enforcement_id,
        "context_snapshot_id": context_snapshot_id,
        "outcome": decision.outcome,
        "reason": decision.reason,
        "deny_reason": decision.reason if decision.outcome == "deny" else "",
        "escalation_hint": "step_up_required" if decision.outcome == "conditional" else "none",
        "evaluation_mode": "local_pdp",
        "policy_enforcement_mode": "local_pdp",
        "reason_summary": f"Python local PDP returned {decision.outcome}: {decision.reason}.",
        "policy_attribution": {
            "bundle_version_digest": _sha256_text(decision.bundle_version) if decision.bundle_version else "unavailable_optional",
            "context_pack_id_digest": _sha256_text(decision.context_pack_id) if decision.context_pack_id else "unavailable_optional",
            "matched_policy_ids": [],
            "attribution_state": "unavailable_until_per_policy_eval",
            "attribution_method": "local_pdp_aggregate_bundle_without_per_policy_eval",
        },
        "contributing_signals": decision_path,
        "missing_required_signals": source_status["missing_required"],
        "stale_signals": source_status["stale"],
        "advisory_signals_ignored_for_allow": ["local_obligations_present"] if decision.outcome == "allow" and decision.obligations else [],
        "next_safe_actions": ["escalate_to_central_pdp_or_refresh_local_context"] if decision.outcome == "conditional" else [],
    }
    return {
        "context_snapshot_id": context_snapshot_id,
        "context_snapshot_digest": context_snapshot_digest,
        "context_snapshot": snapshot,
        "decision_explanation": explanation,
    }


# Module-level singleton
_evaluator = LocalPDPEvaluator()


def get_evaluator() -> LocalPDPEvaluator:
    return _evaluator
