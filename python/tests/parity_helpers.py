"""
Parity normalization helpers — Live Local-vs-Server Parity Integration.

Phase 2: Normalized comparison of local SDK decisions against live server responses.

Normalization rules
-------------------
Fields compared directly:
  - allowed          (bool)
  - reason_class     (first segment of reason string, e.g. "agent_revoked" not "agent_revoked:reason_detail")
  - obligation_types (sorted list of obligation type strings)
  - output_control_mode (string: "allow_raw", "mask_fields", "deny_export", etc.)

Fields normalized / excluded:
  - timestamps       (dynamic — excluded)
  - trace_id / enforcement_id / request_id  (generated UUIDs — excluded)
  - elapsed_ms / timing (dynamic — excluded)
  - decision_path    (implementation-specific — excluded, not semantically meaningful for parity)
  - bundle_version / context_pack_id (may differ between local disk and server compile — excluded)
  - evaluation_mode  (intentionally different: LOCAL_RUNTIME_PYTHON vs server modes — excluded)
  - transport metadata (HTTP headers, status codes — excluded)

If a field is newly discovered to differ in a non-meaningful way, add it here with a reason comment.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional


# ── Normalized parity record ──────────────────────────────────────────────────

@dataclasses.dataclass
class ParityRecord:
    """
    Normalized decision record for parity comparison.

    This is the comparable projection of a decision — it strips all fields
    that are legitimately different between local and server paths, and keeps
    only the semantically meaningful fields.
    """
    allowed: bool
    reason_class: str                   # First segment of reason string
    obligation_types: List[str]         # Sorted list of obligation type identifiers
    output_control_mode: str            # "allow_raw", "mask_fields", "deny_export", etc.
    source: str = ""                    # "local" or "server" — not compared, for diagnostics only

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ParityRecord):
            return NotImplemented
        return (
            self.allowed == other.allowed
            and self.reason_class == other.reason_class
            and self.obligation_types == other.obligation_types
            and self.output_control_mode == other.output_control_mode
        )

    def __repr__(self) -> str:
        return (
            f"ParityRecord("
            f"allowed={self.allowed}, "
            f"reason_class={self.reason_class!r}, "
            f"obligation_types={self.obligation_types!r}, "
            f"output_control_mode={self.output_control_mode!r}, "
            f"source={self.source!r})"
        )


# ── Extraction helpers ────────────────────────────────────────────────────────

def _extract_reason_class(reason: Optional[str]) -> str:
    """
    Extract the stable reason class from a reason string.

    Reason strings may carry extra context after the first segment
    (e.g. "agent_revoked:kill_switch:manual" → "agent_revoked").
    We compare only the first colon-or-space-delimited segment.
    """
    if not reason:
        return "unknown"
    # Normalize to first colon-delimited segment, then first space-delimited
    first = reason.split(":")[0].split(" ")[0].strip().lower()
    return first or "unknown"


def _extract_obligation_types(obligations: Any) -> List[str]:
    """
    Extract sorted obligation type strings from obligations in any representation.

    Handles:
    - List of Obligation dataclass/objects with .obligation_type or .type attribute
    - List of dicts with "obligation_type" or "type" key
    - None / empty
    """
    if not obligations:
        return []
    result = []
    for ob in obligations:
        if isinstance(ob, dict):
            ob_type = ob.get("obligation_type") or ob.get("type") or ""
        else:
            ob_type = getattr(ob, "obligation_type", None) or getattr(ob, "type", "") or ""
        if ob_type:
            result.append(str(ob_type).lower())
    return sorted(result)


def _extract_output_control_mode(output_policy: Any) -> str:
    """
    Extract the output control mode from an output_policy in any representation.

    Handles:
    - OutputPolicy dataclass with .mode attribute
    - Dict with "mode" key
    - None (defaults to "allow_raw")
    """
    if output_policy is None:
        return "allow_raw"
    if isinstance(output_policy, dict):
        return str(output_policy.get("mode", "allow_raw")).lower()
    mode = getattr(output_policy, "mode", "allow_raw")
    return str(mode).lower() if mode else "allow_raw"


# ── Public normalization API ──────────────────────────────────────────────────

def normalize_local_decision(local_decision: Any) -> ParityRecord:
    """
    Normalize a LocalDecision object (from LocalPDPEvaluator) into a ParityRecord.

    Expected input: kswitch.local_pdp.evaluator.LocalDecision dataclass.
    """
    return ParityRecord(
        allowed=bool(local_decision.allowed),
        reason_class=_extract_reason_class(getattr(local_decision, "reason", None)),
        obligation_types=_extract_obligation_types(getattr(local_decision, "obligations", None)),
        output_control_mode=_extract_output_control_mode(getattr(local_decision, "output_policy", None)),
        source="local",
    )


def normalize_server_response(server_response: Dict[str, Any]) -> ParityRecord:
    """
    Normalize a server enforcement response dict into a ParityRecord.

    Expected input: response dict from POST /api/v1/enforce/mcp-call, e.g.:
    {
        "allowed": bool,
        "reason": str,
        "obligations": [...],
        "output_policy": {...} | None,
        "decision_path": [...],
        "evaluation_mode": str,
        ...
    }
    """
    return ParityRecord(
        allowed=bool(server_response.get("allowed", False)),
        reason_class=_extract_reason_class(server_response.get("reason")),
        obligation_types=_extract_obligation_types(server_response.get("obligations")),
        output_control_mode=_extract_output_control_mode(server_response.get("output_policy")),
        source="server",
    )


# ── Comparison and diff output ────────────────────────────────────────────────

@dataclasses.dataclass
class ParityMismatch:
    """Describes a field-level parity mismatch between local and server decisions."""
    field: str
    local_value: Any
    server_value: Any

    def __str__(self) -> str:
        return f"  MISMATCH [{self.field}]: local={self.local_value!r}  server={self.server_value!r}"


def compare_parity_records(
    local: ParityRecord,
    server: ParityRecord,
) -> List[ParityMismatch]:
    """
    Compare local and server ParityRecords field by field.

    Returns a list of ParityMismatch objects for every field that differs.
    An empty list means full parity.
    """
    mismatches = []

    if local.allowed != server.allowed:
        mismatches.append(ParityMismatch("allowed", local.allowed, server.allowed))

    if local.reason_class != server.reason_class:
        mismatches.append(ParityMismatch("reason_class", local.reason_class, server.reason_class))

    if local.obligation_types != server.obligation_types:
        mismatches.append(ParityMismatch("obligation_types", local.obligation_types, server.obligation_types))

    if local.output_control_mode != server.output_control_mode:
        mismatches.append(ParityMismatch("output_control_mode", local.output_control_mode, server.output_control_mode))

    return mismatches


def assert_parity(
    local: ParityRecord,
    server: ParityRecord,
    scenario: str = "",
) -> None:
    """
    Assert full parity between local and server normalized records.

    On mismatch, raises AssertionError with a human-readable diff that
    identifies exactly which fields drifted and what the values are.

    This diff output is the primary tool for diagnosing rollout drift.
    """
    mismatches = compare_parity_records(local, server)
    if not mismatches:
        return

    label = f" [{scenario}]" if scenario else ""
    lines = [
        f"PARITY FAILURE{label}: {len(mismatches)} field(s) drifted between local and server paths.",
        "",
        f"  Local  : {local}",
        f"  Server : {server}",
        "",
        "Field-level differences:",
    ]
    for m in mismatches:
        lines.append(str(m))
    lines.append("")
    lines.append("Likely sources of drift:")
    for m in mismatches:
        lines.append(f"  - {m.field}: check policy configuration, bundle compilation, or serialization")

    raise AssertionError("\n".join(lines))


# ── Convenience: normalize and assert in one call ─────────────────────────────

def assert_local_vs_server_parity(
    local_decision: Any,
    server_response: Dict[str, Any],
    scenario: str = "",
) -> None:
    """
    Full pipeline: normalize both sides, then assert parity.

    Usage:
        assert_local_vs_server_parity(local_decision, server_json, "local allow")
    """
    local_rec = normalize_local_decision(local_decision)
    server_rec = normalize_server_response(server_response)
    assert_parity(local_rec, server_rec, scenario=scenario)
