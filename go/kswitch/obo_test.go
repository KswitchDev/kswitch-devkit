package kswitch

import (
	"strings"
	"testing"
)

func TestOBOJSONHeaderRoundTrip(t *testing.T) {
	encoded, err := EncodeJSONHeader(map[string]any{"b": float64(2), "a": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" || encoded[len(encoded)-1:] != "=" {
		t.Fatalf("expected padded base64url header, got %q", encoded)
	}
	decoded := DecodeJSONHeader(encoded)
	if decoded["a"] != float64(1) || decoded["b"] != float64(2) {
		t.Fatalf("decoded = %#v", decoded)
	}
	decoded = DecodeJSONHeader(encoded[:len(encoded)-1])
	if decoded["a"] != float64(1) || decoded["b"] != float64(2) {
		t.Fatalf("decoded unpadded = %#v", decoded)
	}
}

func TestOBOActorChainHeadersRoundTrip(t *testing.T) {
	chain := BuildActorChain(BuildActorChainOptions{
		HumanSubject:   "analyst.obo@example.test",
		HumanSub:       "user-123",
		HumanEmail:     "analyst.obo@example.test",
		AgentSpiffeID:  "spiffe://kswitch.ai/obo/agent/prompt-agent",
		MCPSpiffeID:    "spiffe://kswitch.ai/obo/mcp/payments-x",
		BrokerSpiffeID: "spiffe://kswitch.ai/obo/broker/token-exchange",
		Prompt:         "read payments",
	})
	constraint := BuildSenderConstraint(BuildSenderConstraintOptions{
		AgentSpiffeID:    "spiffe://kswitch.ai/obo/agent/prompt-agent",
		ExecutorSpiffeID: "spiffe://kswitch.ai/obo/mcp/payments-x",
		BrokerSpiffeID:   "spiffe://kswitch.ai/obo/broker/token-exchange",
		ResourceAudience: "payments-modern-api",
		AgentJWTSVID:     "agent.jwt.svid",
		ExecutorJWTSVID:  "mcp.jwt.svid",
	})
	headers, err := BuildOBOHeaders(chain, "payments:read", constraint, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	lower := map[string]string{}
	for key, value := range headers {
		lower[strings.ToLower(key)] = value
	}
	parsed := ActorChainFromHeaders(lower)
	human := parsed["human"].(map[string]any)
	actor := parsed["actor"].(map[string]any)
	executor := parsed["executor"].(map[string]any)
	if human["subject"] != "analyst.obo@example.test" {
		t.Fatalf("human = %#v", human)
	}
	if actor["spiffe_id"] != "spiffe://kswitch.ai/obo/agent/prompt-agent" {
		t.Fatalf("actor = %#v", actor)
	}
	if executor["spiffe_id"] != "spiffe://kswitch.ai/obo/mcp/payments-x" {
		t.Fatalf("executor = %#v", executor)
	}
}

func TestPolicyEvidenceRequiresEnvoyOPAAndCedarAllow(t *testing.T) {
	raw := map[string]any{
		"allow":             true,
		"pep":               ExpectedPolicyPEP,
		"pep_transport":     ExpectedPolicyTransport,
		"enforcement_point": ExpectedPolicyEnforcementPoint,
		"pdp_mode":          ExpectedPolicyPDPMode,
		"resource_id":       "payments-modern-api",
		"required_scope":    "payments:read",
		"bundle_version":    "obo-policy-bundle-local-v1",
		"bundle_sha256":     "abc123",
		"opa":               map[string]any{"allow": true, "engine": "opa", "policy_id": "opa-obo-structural-v1"},
		"cedar":             map[string]any{"allow": true, "engine": "cedar", "policy_id": "cedar-obo-payments-read-v1"},
	}
	evidence := PolicyEvidenceFromMap(raw)
	if !evidence.Allows("payments-modern-api", "payments:read") {
		t.Fatalf("expected evidence to allow: %#v", evidence)
	}
	encoded, err := EncodeJSONHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed := PolicyEvidenceFromHeaders(map[string]string{
		strings.ToLower(KSwitchPolicyEvidenceHeader): encoded,
	})
	if !parsed.Allows("payments-modern-api", "payments:read") {
		t.Fatalf("expected parsed evidence to allow: %#v", parsed)
	}
	denied := PolicyEvidenceFromMap(map[string]any{
		"allow":          true,
		"pep":            ExpectedPolicyPEP,
		"resource_id":    "payments-modern-api",
		"required_scope": "payments:read",
		"opa":            map[string]any{"allow": true, "engine": "opa"},
		"cedar":          map[string]any{"allow": false, "engine": "cedar"},
	})
	if denied.Allows("payments-modern-api", "payments:read") {
		t.Fatal("expected cedar deny to fail Allows")
	}
}
