import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  EXPECTED_POLICY_PEP,
  KSWITCH_POLICY_EVIDENCE_HEADER,
  OBO_ACTOR_CHAIN_HEADER,
  actorChainFromHeaders,
  buildActorChain,
  buildOBOHeaders,
  buildSenderConstraint,
  decodeJsonHeader,
  encodeJsonHeader,
  policyEvidenceAllows,
  policyEvidenceFrom,
  policyEvidenceFromHeaders,
} from "../src/obo.ts";

describe("OBO Envoy evidence contract", () => {
  it("round trips padded and unpadded JSON headers", () => {
    const encoded = encodeJsonHeader({ b: 2, a: 1 });
    assert.equal(encoded.endsWith("="), true);
    assert.deepEqual(decodeJsonHeader(encoded), { a: 1, b: 2 });
    assert.deepEqual(decodeJsonHeader(encoded.replace(/=+$/, "")), { a: 1, b: 2 });
  });

  it("round trips actor-chain headers case-insensitively", () => {
    const actorChain = buildActorChain({
      humanSubject: "analyst.obo@example.test",
      humanSub: "user-123",
      humanEmail: "analyst.obo@example.test",
      agentSpiffeId: "spiffe://kswitch.ai/obo/agent/prompt-agent",
      mcpSpiffeId: "spiffe://kswitch.ai/obo/mcp/payments-x",
      brokerSpiffeId: "spiffe://kswitch.ai/obo/broker/token-exchange",
      prompt: "read payments",
    });
    const senderConstraint = buildSenderConstraint({
      agentSpiffeId: "spiffe://kswitch.ai/obo/agent/prompt-agent",
      executorSpiffeId: "spiffe://kswitch.ai/obo/mcp/payments-x",
      brokerSpiffeId: "spiffe://kswitch.ai/obo/broker/token-exchange",
      resourceAudience: "payments-modern-api",
      agentJwtSvid: "agent.jwt.svid",
      executorJwtSvid: "mcp.jwt.svid",
    });
    const headers = buildOBOHeaders({
      actorChain,
      requestedScope: "payments:read",
      senderConstraint,
    });
    const lowerHeaders = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
    );

    const parsed = actorChainFromHeaders(lowerHeaders);
    assert.equal((parsed["human"] as Record<string, unknown>)["subject"], "analyst.obo@example.test");
    assert.equal((parsed["actor"] as Record<string, unknown>)["spiffe_id"], "spiffe://kswitch.ai/obo/agent/prompt-agent");
    assert.equal((parsed["executor"] as Record<string, unknown>)["spiffe_id"], "spiffe://kswitch.ai/obo/mcp/payments-x");
    assert.ok(headers[OBO_ACTOR_CHAIN_HEADER]);
  });

  it("requires Envoy, OPA, and Cedar allow evidence", () => {
    const raw = {
      allow: true,
      pep: EXPECTED_POLICY_PEP,
      pep_transport: "envoy_http_ext_authz",
      enforcement_point: "local_envoy_sidecar",
      pdp_mode: "opa_and_cedar_must_allow",
      resource_id: "payments-modern-api",
      required_scope: "payments:read",
      bundle_version: "obo-policy-bundle-local-v1",
      bundle_sha256: "abc123",
      opa: { allow: true, engine: "opa", policy_id: "opa-obo-structural-v1" },
      cedar: { allow: true, engine: "cedar", policy_id: "cedar-obo-payments-read-v1" },
    };
    const evidence = policyEvidenceFrom(raw);
    assert.equal(policyEvidenceAllows(evidence, { resourceId: "payments-modern-api", requiredScope: "payments:read" }), true);

    const parsed = policyEvidenceFromHeaders({
      [KSWITCH_POLICY_EVIDENCE_HEADER.toLowerCase()]: encodeJsonHeader(raw),
    });
    assert.equal(policyEvidenceAllows(parsed, { resourceId: "payments-modern-api", requiredScope: "payments:read" }), true);

    const denied = policyEvidenceFrom({
      ...raw,
      cedar: { allow: false, engine: "cedar" },
    });
    assert.equal(policyEvidenceAllows(denied, { resourceId: "payments-modern-api", requiredScope: "payments:read" }), false);
  });
});
