# KSwitch Execution Token Gateway Validation Policy
# L2 Phase 2 — Network Enforcement (Envoy + OPA)
# L2H-4 — SPIFFE binding: peer cert URI SAN must match JWT sub (mTLS mode)
#
# =====================================================================
# TWO-LANE POLICY · READ BEFORE EDITING
# =====================================================================
# This file is the canonical rego for the DOCKER gateway lane
# (`gateway/envoy/envoy.yaml` + `gateway/envoy/envoy-mtls.yaml`). It
# fetches JWKS from a control-plane URL at request time.
#
# A derived variant lives inline in
# `k8s/manifests/gateway/gateway-opa.yaml::ConfigMap::gateway-opa-policy`
# for the Kubernetes gateway lane. The k8s variant adds a
# local-JWKS-snapshot path (data.config.jwks.keys + local_jwks_available)
# so the gateway stays policy-correct when the control plane is offline
# (core-offline resilience: the gateway stays policy-correct when the control plane is unreachable).
#
# Structural parity is enforced by
# `tests/test_ep066_envoy_gateway.py::test_rego_structural_parity_source_vs_k8s`.
# That test asserts: every `allow if` condition, every `reason := "..."`
# code, and every named security-critical rule in THIS file also appears
# in the k8s inline variant. Drift will fail CI.
#
# If you change security-critical rules here, you MUST mirror the
# change in `k8s/manifests/gateway/gateway-opa.yaml` (same package,
# same rule names). Any intentional k8s-only addition belongs in a
# block clearly labelled `# k8s-lane addition (D3a ...)`.
# =====================================================================
#
# Validates ES256-signed execution tokens at the network boundary.
# Called by Envoy ext_authz filter before any request reaches the upstream.
#
# Design decisions (fixed — do not change):
#   - Signing algorithm: ES256 (ECDSA P-256)
#   - Key distribution: JWKS from KSwitch control plane
#   - req_hash: mandatory for CRITICAL and HIGH risk tiers
#   - Nonce: NOT enforced at gateway (SDK is primary nonce control)
#   - Failure mode: fail closed (OPA down or JWKS fetch failure = deny)
#   - SPIFFE binding: optional when x-spiffe-id absent (non-mTLS), mandatory when present
#
# Envoy ext_authz input shape:
#   input.attributes.request.http.headers.authorization = "Bearer <jwt>"
#   input.attributes.request.http.headers["x-spiffe-id"] = "spiffe://..." (mTLS only)
#   input.attributes.request.http.path = "/api/v1/enforce/mcp-call"
#   input.attributes.request.http.method = "POST"
#
# SPIFFE binding flow (L2H-3 → L2H-4):
#   Envoy Lua filter → strips client x-spiffe-id → extracts URI SAN from peer cert →
#   sets x-spiffe-id header → OPA derives expected SPIFFE ID from JWT sub →
#   denies if they do not match.
#
#   Derivation: spiffe://{trust_domain}/agent/{sanitised_sub}
#   where sanitised_sub = regex.replace(sub, "[^a-zA-Z0-9._-]", "-")

package kswitch.gateway

import rego.v1

# ── Configuration ────────────────────────────────────────────────────────────

# JWKS endpoint URL — set via data.config or env
default jwks_url := "https://localhost:5001/api/v1/jwks"

jwks_url := data.config.jwks_url if {
	data.config.jwks_url
}

# Expected issuer / audience (overridable via data.config)
default expected_issuer := "kswitch"

expected_issuer := data.config.expected_issuer if {
	data.config.expected_issuer
}

default expected_audience := "kswitch-control-plane"

expected_audience := data.config.expected_audience if {
	data.config.expected_audience
}

# ── Decision ─────────────────────────────────────────────────────────────────

default allow := false

# Main allow rule — all conditions must hold
# spiffe_binding_ok is a no-op when x-spiffe-id header is absent (non-mTLS mode)
# source_principal_valid is a no-op when input.attributes.source.principal is absent
allow if {
	signature_valid
	claims_valid
	not token_expired
	req_hash_ok
	spiffe_binding_ok
	source_principal_valid
}

# ── Structured response for Envoy ────────────────────────────────────────────

result := {
	"allow": allow,
	"reason": reason,
	"token_sub": token_sub,
	"token_policy_id": token_policy_id,
	"source_principal": source_principal,
}

# ── Reason derivation (else-chain to avoid conflict) ─────────────────────────

default reason := "token_missing"

reason := "valid" if {
	allow
} else := "jwks_fetch_failed" if {
	bearer_token != ""
	jwks_error
} else := "invalid_signature" if {
	bearer_token != ""
	not signature_valid
} else := "claims_invalid" if {
	signature_valid
	not claims_valid
} else := "expired" if {
	signature_valid
	claims_valid
	token_expired
} else := "req_hash_missing" if {
	signature_valid
	claims_valid
	not token_expired
	not req_hash_ok
} else := "spiffe_binding_mismatch" if {
	signature_valid
	claims_valid
	not token_expired
	req_hash_ok
	not spiffe_binding_ok
} else := "source_principal_mismatch" if {
	signature_valid
	claims_valid
	not token_expired
	req_hash_ok
	spiffe_binding_ok
	not source_principal_valid
}

# ── Token extraction ─────────────────────────────────────────────────────────

bearer_token := t if {
	auth_header := input.attributes.request.http.headers.authorization
	startswith(auth_header, "Bearer ")
	t := substring(auth_header, 7, -1)
	t != ""
}

default bearer_token := ""

# ── JWT decode (unverified — for header/payload inspection) ──────────────────

decoded := io.jwt.decode(bearer_token) if {
	bearer_token != ""
}

default decoded := [{}, {}, ""]

token_header := decoded[0]

token_payload := decoded[1]

# ── JWKS fetch with caching ──────────────────────────────────────────────────
#
# Explicit opt-in posture applied to the
# control-plane OIDC client for the gateway JWKS fetch. Default is TLS-
# verify-on; the caller MUST set `data.config.dev_insecure_tls = true` in
# the OPA policy data bundle to disable verification. This is documented
# as dev-only (self-signed mkcert against a local control plane). In
# production, never set this key — the control plane must serve JWKS over
# a CA-trusted certificate.
#
# Grounding: reports/security-fix-path-2026-04-24.md §S1-D

jwks_http_opts := opts if {
	data.config.dev_insecure_tls == true
	opts := {
		"url": jwks_url,
		"method": "GET",
		"cache": true,
		"raise_error": false,
		"tls_insecure_skip_verify": true,
	}
} else := {
	"url": jwks_url,
	"method": "GET",
	"cache": true,
	"raise_error": false,
}

jwks_response := http.send(jwks_http_opts)

jwks_keys := jwks_response.body.keys if {
	jwks_response.status_code == 200
	jwks_response.body.keys
}

default jwks_keys := []

# Detect JWKS fetch failure
jwks_error if {
	bearer_token != ""
	not jwks_response.status_code
}

jwks_error if {
	bearer_token != ""
	jwks_response.status_code != 200
}

# ── Key lookup by kid ────────────────────────────────────────────────────────

# Find the matching key from JWKS by kid
matching_key := k if {
	some k in jwks_keys
	k.kid == token_header.kid
}

# ── Signature verification (ES256 via JWK) ───────────────────────────────────
# OPA's io.jwt.verify_es256 accepts a JWK JSON string as the key parameter.

signature_valid if {
	bearer_token != ""
	matching_key
	io.jwt.verify_es256(bearer_token, json.marshal(matching_key))
}

default signature_valid := false

# ── Claims validation ────────────────────────────────────────────────────────

claims_valid if {
	token_payload.iss == expected_issuer
	_aud_matches
}

default claims_valid := false

# Audience can be a string or array
_aud_matches if {
	token_payload.aud == expected_audience
}

_aud_matches if {
	is_array(token_payload.aud)
	some a in token_payload.aud
	a == expected_audience
}

# ── Expiry check ─────────────────────────────────────────────────────────────

token_expired if {
	now_seconds := time.now_ns() / 1000000000
	token_payload.exp < now_seconds
}

default token_expired := false

# ── req_hash enforcement for CRITICAL and HIGH risk tiers ────────────────────

req_hash_ok if {
	not risk_tier_requires_hash
}

req_hash_ok if {
	risk_tier_requires_hash
	token_payload.req_hash
	token_payload.req_hash != ""
}

risk_tier_requires_hash if {
	token_payload.risk_tier == "critical"
}

risk_tier_requires_hash if {
	token_payload.risk_tier == "high"
}

# ── Token claim accessors ────────────────────────────────────────────────────

token_sub := token_payload.sub if {
	signature_valid
}

default token_sub := ""

token_policy_id := token_payload.policy_id if {
	signature_valid
}

default token_policy_id := ""

# ── SPIFFE binding (L2H-4) ───────────────────────────────────────────────────
# When mTLS is active, Envoy's Lua filter sets x-spiffe-id from the peer cert
# URI SAN (after stripping any client-supplied value to prevent spoofing).
#
# If x-spiffe-id is present it MUST equal the SPIFFE ID derived from the JWT sub.
# If absent (non-mTLS / plain HTTP mode) the check is a no-op — backward compatible.
#
# Derivation (design decision — simplified path):
#   expected = "spiffe://" + trust_domain + "/agent/" + sanitise(sub)
#   sanitise(s) = regex.replace(s, "[^a-zA-Z0-9._-]", "-")
#
# Example: sub="agent:fraud-detector-v3@bank.internal"
#   → "spiffe://kswitch.ai/agent/agent-fraud-detector-v3-bank.internal"

default spiffe_trust_domain := "kswitch.ai"

spiffe_trust_domain := data.config.spiffe_trust_domain if {
	data.config.spiffe_trust_domain
}

# Derive expected SPIFFE ID from the verified JWT sub
derived_spiffe_id := concat("", [
	"spiffe://",
	spiffe_trust_domain,
	"/agent/",
	regex.replace(token_payload.sub, `[^a-zA-Z0-9._\-]`, "-"),
]) if {
	signature_valid
	token_payload.sub != ""
}

# x-spiffe-id header — set by Lua filter from verified peer cert URI SAN
peer_spiffe_id := input.attributes.request.http.headers["x-spiffe-id"] if {
	input.attributes.request.http.headers["x-spiffe-id"] != ""
}

# No peer cert header → non-mTLS mode → binding check is a no-op
spiffe_binding_ok if {
	not peer_spiffe_id
}

# Peer cert present → IDs must match
spiffe_binding_ok if {
	peer_spiffe_id
	derived_spiffe_id
	peer_spiffe_id == derived_spiffe_id
}

default spiffe_binding_ok := false

# ── Source principal binding (L2H-4 belt-and-suspenders) ─────────────────────
# input.attributes.source.principal is set directly by Envoy from the mTLS peer
# certificate URI SAN — independent of the Lua-set x-spiffe-id header.
# This provides a second, authoritative SPIFFE binding that does not require
# the Lua filter to be in the filter chain.
#
# When absent (non-mTLS): no-op — backward compatible.
# When present: must equal derived_spiffe_id (same derivation as spiffe_binding_ok).

# Sanitised sub component — shared across both SPIFFE binding checks
sub_name := regex.replace(token_payload.sub, `[^a-zA-Z0-9._\-]`, "-") if {
	signature_valid
	token_payload.sub != ""
}

# Source principal directly from Envoy mTLS attributes (non-empty only)
source_principal := input.attributes.source.principal if {
	input.attributes.source.principal != ""
}

# No source principal in CheckRequest → non-mTLS mode → no-op
source_principal_valid if {
	not source_principal
}

# Source principal present → must match the derived SPIFFE ID from JWT sub
source_principal_valid if {
	source_principal
	derived_spiffe_id
	source_principal == derived_spiffe_id
}

default source_principal_valid := false
