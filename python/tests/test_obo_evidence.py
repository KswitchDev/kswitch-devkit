from __future__ import annotations

from kswitch.obo import (
    EXPECTED_POLICY_PEP,
    KSWITCH_POLICY_EVIDENCE_HEADER,
    OBO_ACTOR_CHAIN_HEADER,
    PolicyEvidence,
    actor_chain_from_headers,
    build_actor_chain,
    build_obo_headers,
    build_sender_constraint,
    decode_json_header,
    encode_json_header,
    policy_evidence_from_headers,
)


def test_json_header_round_trips_with_padding() -> None:
    encoded = encode_json_header({"b": 2, "a": 1})
    assert encoded.endswith("=")
    assert decode_json_header(encoded) == {"a": 1, "b": 2}
    assert decode_json_header(encoded.rstrip("=")) == {"a": 1, "b": 2}


def test_actor_chain_headers_round_trip_case_insensitive() -> None:
    chain = build_actor_chain(
        human_subject="analyst.obo@example.test",
        human_sub="user-123",
        human_email="analyst.obo@example.test",
        agent_spiffe_id="spiffe://kswitch.ai/obo/agent/prompt-agent",
        mcp_spiffe_id="spiffe://kswitch.ai/obo/mcp/payments-x",
        broker_spiffe_id="spiffe://kswitch.ai/obo/broker/token-exchange",
        prompt="read payments",
    )
    constraint = build_sender_constraint(
        agent_spiffe_id="spiffe://kswitch.ai/obo/agent/prompt-agent",
        executor_spiffe_id="spiffe://kswitch.ai/obo/mcp/payments-x",
        broker_spiffe_id="spiffe://kswitch.ai/obo/broker/token-exchange",
        resource_audience="payments-modern-api",
        agent_jwt_svid="agent.jwt.svid",
        executor_jwt_svid="mcp.jwt.svid",
    )
    headers = build_obo_headers(actor_chain=chain, requested_scope="payments:read", sender_constraint=constraint)

    lower_headers = {key.lower(): value for key, value in headers.items()}
    parsed = actor_chain_from_headers(lower_headers)
    assert parsed["human"]["subject"] == "analyst.obo@example.test"
    assert parsed["actor"]["spiffe_id"] == "spiffe://kswitch.ai/obo/agent/prompt-agent"
    assert parsed["executor"]["spiffe_id"] == "spiffe://kswitch.ai/obo/mcp/payments-x"
    assert OBO_ACTOR_CHAIN_HEADER in headers


def test_policy_evidence_requires_envoy_opa_and_cedar_allow() -> None:
    raw = {
        "allow": True,
        "pep": EXPECTED_POLICY_PEP,
        "pep_transport": "envoy_http_ext_authz",
        "enforcement_point": "local_envoy_sidecar",
        "pdp_mode": "opa_and_cedar_must_allow",
        "resource_id": "payments-modern-api",
        "required_scope": "payments:read",
        "bundle_version": "obo-policy-bundle-local-v1",
        "bundle_sha256": "abc123",
        "opa": {"allow": True, "engine": "opa", "policy_id": "opa-obo-structural-v1"},
        "cedar": {"allow": True, "engine": "cedar", "policy_id": "cedar-obo-payments-read-v1"},
    }
    evidence = PolicyEvidence.from_mapping(raw)
    assert evidence.allows(resource_id="payments-modern-api", required_scope="payments:read")

    headers = {KSWITCH_POLICY_EVIDENCE_HEADER.lower(): encode_json_header(raw)}
    parsed = policy_evidence_from_headers(headers)
    assert parsed.allows(resource_id="payments-modern-api", required_scope="payments:read")

    denied = PolicyEvidence.from_mapping({**raw, "cedar": {"allow": False, "engine": "cedar"}})
    assert not denied.allows(resource_id="payments-modern-api", required_scope="payments:read")
