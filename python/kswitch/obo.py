"""OBO and local Envoy policy evidence contract helpers.

This module captures the wire contract proven by the ATCP OBO harness:

* the human/agent/MCP actor chain;
* the scoped on-behalf-of resource request;
* the local Envoy ext_authz policy evidence emitted by OPA and Cedar;
* the KSwitch central enforcement reference used for audit/escalation; and
* proof-level sender-constraint evidence.

The helpers are intentionally small and dependency-free. They do not decide
policy; they make the evidence shape portable across Python, TypeScript, Go,
MCP servers, Envoy filters, and app adapters.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

OBO_ACTOR_CHAIN_HEADER = "X-OBO-Actor-Chain"
OBO_REQUESTED_SCOPE_HEADER = "X-OBO-Requested-Scope"
OBO_SENDER_CONSTRAINT_HEADER = "X-OBO-Sender-Constraint"
KSWITCH_ENFORCEMENT_DECISION_HEADER = "X-KSwitch-Enforcement-Decision"
KSWITCH_ENFORCEMENT_ID_HEADER = "X-KSwitch-Enforcement-Id"
KSWITCH_POLICY_DECISION_HEADER = "X-KSwitch-Policy-Decision"
KSWITCH_POLICY_EVIDENCE_HEADER = "X-KSwitch-Policy-Evidence"
KSWITCH_POLICY_BUNDLE_HEADER = "X-KSwitch-Policy-Bundle"

EXPECTED_POLICY_PEP = "envoy_ext_authz"
EXPECTED_POLICY_TRANSPORT = "envoy_http_ext_authz"
EXPECTED_POLICY_ENFORCEMENT_POINT = "local_envoy_sidecar"
EXPECTED_POLICY_PDP_MODE = "opa_and_cedar_must_allow"


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def encode_json_header(payload: Mapping[str, Any]) -> str:
    """Encode a JSON object for an HTTP header using URL-safe base64."""

    return base64.urlsafe_b64encode(_canonical_json(payload).encode()).decode()


def decode_json_header(value: str | None) -> dict[str, Any]:
    """Decode a URL-safe base64 JSON HTTP header.

    Both padded and unpadded base64url values are accepted.
    """

    if not value:
        return {}
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        loaded = json.loads(decoded)
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def sha256_b64url(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def get_header(headers: Mapping[str, Any], name: str) -> str:
    """Fetch a header by name using case-insensitive matching."""

    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


@dataclass(frozen=True)
class PolicyEngineEvidence:
    allow: bool
    engine: str
    policy_id: str = ""
    deny_reasons: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> "PolicyEngineEvidence":
        data = dict(payload or {})
        deny_reasons = tuple(str(item) for item in data.get("deny_reasons") or data.get("deny") or ())
        return cls(
            allow=bool(data.get("allow")),
            engine=str(data.get("engine") or ""),
            policy_id=str(data.get("policy_id") or ""),
            deny_reasons=deny_reasons,
            raw=data,
        )


@dataclass(frozen=True)
class PolicyEvidence:
    allow: bool
    pep: str
    resource_id: str
    required_scope: str
    requested_scope: str = ""
    pep_transport: str = ""
    enforcement_point: str = ""
    pdp_mode: str = ""
    bundle_version: str = ""
    bundle_sha256: str = ""
    opa: PolicyEngineEvidence = field(default_factory=lambda: PolicyEngineEvidence(False, "opa"))
    cedar: PolicyEngineEvidence = field(default_factory=lambda: PolicyEngineEvidence(False, "cedar"))
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> "PolicyEvidence":
        data = dict(payload or {})
        return cls(
            allow=bool(data.get("allow")),
            pep=str(data.get("pep") or ""),
            pep_transport=str(data.get("pep_transport") or ""),
            enforcement_point=str(data.get("enforcement_point") or ""),
            pdp_mode=str(data.get("pdp_mode") or ""),
            resource_id=str(data.get("resource_id") or ""),
            required_scope=str(data.get("required_scope") or ""),
            requested_scope=str(data.get("requested_scope") or ""),
            bundle_version=str(data.get("bundle_version") or ""),
            bundle_sha256=str(data.get("bundle_sha256") or ""),
            opa=PolicyEngineEvidence.from_mapping(data.get("opa") if isinstance(data.get("opa"), Mapping) else None),
            cedar=PolicyEngineEvidence.from_mapping(data.get("cedar") if isinstance(data.get("cedar"), Mapping) else None),
            raw=data,
        )

    def allows(self, *, resource_id: str | None = None, required_scope: str | None = None) -> bool:
        if not self.allow:
            return False
        if self.pep != EXPECTED_POLICY_PEP:
            return False
        if resource_id is not None and self.resource_id != resource_id:
            return False
        if required_scope is not None and self.required_scope != required_scope:
            return False
        return self.opa.allow and self.cedar.allow


def policy_evidence_from_headers(headers: Mapping[str, Any]) -> PolicyEvidence:
    return PolicyEvidence.from_mapping(decode_json_header(get_header(headers, KSWITCH_POLICY_EVIDENCE_HEADER)))


def kswitch_decision_from_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    return decode_json_header(get_header(headers, KSWITCH_ENFORCEMENT_DECISION_HEADER))


def actor_chain_from_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    return decode_json_header(get_header(headers, OBO_ACTOR_CHAIN_HEADER))


def sender_constraint_from_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    return decode_json_header(get_header(headers, OBO_SENDER_CONSTRAINT_HEADER))


def build_actor_chain(
    *,
    human_subject: str,
    agent_spiffe_id: str,
    mcp_spiffe_id: str,
    broker_spiffe_id: str = "",
    human_sub: str = "",
    human_email: str = "",
    prompt: str = "",
) -> dict[str, Any]:
    actors = [
        {"role": "agent", "spiffe_id": agent_spiffe_id},
        {"role": "mcp", "spiffe_id": mcp_spiffe_id},
    ]
    if broker_spiffe_id:
        actors.append({"role": "broker", "spiffe_id": broker_spiffe_id})
    chain: dict[str, Any] = {
        "sub": human_sub,
        "human_subject": human_subject,
        "human": {
            "sub": human_sub,
            "subject": human_subject,
            "email": human_email,
            "prompt": prompt,
        },
        "actor": {"role": "agent", "spiffe_id": agent_spiffe_id, "action": "interpreted human prompt"},
        "executor": {"role": "mcp", "spiffe_id": mcp_spiffe_id, "action": "executed resource call"},
        "actors": actors,
        "standards": {
            "obo": "RFC 8693 token exchange",
            "workload_identity": "SPIFFE/SPIRE JWT-SVID",
            "wimse_profile": "WIMSE workload identity and authorization-evidence profile candidate",
        },
    }
    if broker_spiffe_id:
        chain["broker"] = {
            "role": "obo-broker",
            "spiffe_id": broker_spiffe_id,
            "action": "validated actor/executor and exchanged token",
        }
    return chain


def build_sender_constraint(
    *,
    agent_spiffe_id: str,
    executor_spiffe_id: str,
    resource_audience: str,
    broker_spiffe_id: str = "",
    agent_jwt_svid: str = "",
    executor_jwt_svid: str = "",
) -> dict[str, Any]:
    constraint: dict[str, Any] = {
        "type": "svid-bound-proof",
        "confirmation_method": "jwt-svid-sha256",
        "actor_spiffe_id": agent_spiffe_id,
        "executor_spiffe_id": executor_spiffe_id,
        "broker_spiffe_id": broker_spiffe_id,
        "resource_audience": resource_audience,
    }
    if agent_jwt_svid:
        constraint["agent_svid_sha256"] = sha256_b64url(agent_jwt_svid)
    if executor_jwt_svid:
        constraint["mcp_svid_sha256"] = sha256_b64url(executor_jwt_svid)
    return constraint


def build_obo_headers(
    *,
    actor_chain: Mapping[str, Any],
    requested_scope: str,
    sender_constraint: Mapping[str, Any] | None = None,
    kswitch_decision: Mapping[str, Any] | None = None,
    kswitch_enforcement_id: str = "",
) -> dict[str, str]:
    headers = {
        OBO_ACTOR_CHAIN_HEADER: encode_json_header(actor_chain),
        OBO_REQUESTED_SCOPE_HEADER: requested_scope,
    }
    if sender_constraint:
        headers[OBO_SENDER_CONSTRAINT_HEADER] = encode_json_header(sender_constraint)
    if kswitch_decision:
        headers[KSWITCH_ENFORCEMENT_DECISION_HEADER] = encode_json_header(kswitch_decision)
    if kswitch_enforcement_id:
        headers[KSWITCH_ENFORCEMENT_ID_HEADER] = kswitch_enforcement_id
    return headers


__all__ = [
    "OBO_ACTOR_CHAIN_HEADER",
    "OBO_REQUESTED_SCOPE_HEADER",
    "OBO_SENDER_CONSTRAINT_HEADER",
    "KSWITCH_ENFORCEMENT_DECISION_HEADER",
    "KSWITCH_ENFORCEMENT_ID_HEADER",
    "KSWITCH_POLICY_DECISION_HEADER",
    "KSWITCH_POLICY_EVIDENCE_HEADER",
    "KSWITCH_POLICY_BUNDLE_HEADER",
    "EXPECTED_POLICY_PEP",
    "EXPECTED_POLICY_TRANSPORT",
    "EXPECTED_POLICY_ENFORCEMENT_POINT",
    "EXPECTED_POLICY_PDP_MODE",
    "PolicyEngineEvidence",
    "PolicyEvidence",
    "actor_chain_from_headers",
    "build_actor_chain",
    "build_obo_headers",
    "build_sender_constraint",
    "decode_json_header",
    "encode_json_header",
    "get_header",
    "kswitch_decision_from_headers",
    "policy_evidence_from_headers",
    "sender_constraint_from_headers",
    "sha256_b64url",
]
