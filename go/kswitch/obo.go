package kswitch

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const (
	OBOActorChainHeader              = "X-OBO-Actor-Chain"
	OBORequestedScopeHeader          = "X-OBO-Requested-Scope"
	OBOSenderConstraintHeader        = "X-OBO-Sender-Constraint"
	KSwitchEnforcementDecisionHeader = "X-KSwitch-Enforcement-Decision"
	KSwitchEnforcementIDHeader       = "X-KSwitch-Enforcement-Id"
	KSwitchPolicyDecisionHeader      = "X-KSwitch-Policy-Decision"
	KSwitchPolicyEvidenceHeader      = "X-KSwitch-Policy-Evidence"
	KSwitchPolicyBundleHeader        = "X-KSwitch-Policy-Bundle"

	ExpectedPolicyPEP              = "envoy_ext_authz"
	ExpectedPolicyTransport        = "envoy_http_ext_authz"
	ExpectedPolicyEnforcementPoint = "local_envoy_sidecar"
	ExpectedPolicyPDPMode          = "opa_and_cedar_must_allow"
)

// PolicyEngineEvidence is one local PDP engine result inside the OBO evidence.
type PolicyEngineEvidence struct {
	Allow       bool           `json:"allow"`
	Engine      string         `json:"engine"`
	PolicyID    string         `json:"policy_id,omitempty"`
	DenyReasons []string       `json:"deny_reasons,omitempty"`
	Raw         map[string]any `json:"-"`
}

// PolicyEvidence is the Envoy ext_authz evidence contract shared by SDKs.
type PolicyEvidence struct {
	Allow            bool                 `json:"allow"`
	PEP              string               `json:"pep"`
	PEPTransport     string               `json:"pep_transport,omitempty"`
	EnforcementPoint string               `json:"enforcement_point,omitempty"`
	PDPMode          string               `json:"pdp_mode,omitempty"`
	ResourceID       string               `json:"resource_id"`
	RequiredScope    string               `json:"required_scope"`
	RequestedScope   string               `json:"requested_scope,omitempty"`
	BundleVersion    string               `json:"bundle_version,omitempty"`
	BundleSHA256     string               `json:"bundle_sha256,omitempty"`
	OPA              PolicyEngineEvidence `json:"opa"`
	Cedar            PolicyEngineEvidence `json:"cedar"`
	Raw              map[string]any       `json:"-"`
}

// BuildActorChainOptions configures a portable OBO actor-chain object.
type BuildActorChainOptions struct {
	HumanSubject   string
	AgentSpiffeID  string
	MCPSpiffeID    string
	BrokerSpiffeID string
	HumanSub       string
	HumanEmail     string
	Prompt         string
}

// BuildSenderConstraintOptions configures proof-level SVID-bound evidence.
type BuildSenderConstraintOptions struct {
	AgentSpiffeID    string
	ExecutorSpiffeID string
	ResourceAudience string
	BrokerSpiffeID   string
	AgentJWTSVID     string
	ExecutorJWTSVID  string
}

// EncodeJSONHeader serializes a JSON object for an HTTP header using URL-safe base64.
func EncodeJSONHeader(payload map[string]any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(raw), nil
}

// DecodeJSONHeader decodes padded or unpadded URL-safe base64 JSON.
func DecodeJSONHeader(value string) map[string]any {
	if value == "" {
		return map[string]any{}
	}
	decoded, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	}
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(decoded, &out); err != nil {
		return map[string]any{}
	}
	if out == nil {
		return map[string]any{}
	}
	return out
}

// GetHeader fetches a header by name using case-insensitive matching.
func GetHeader(headers map[string]string, name string) string {
	wanted := strings.ToLower(name)
	for key, value := range headers {
		if strings.ToLower(key) == wanted {
			return value
		}
	}
	return ""
}

// SHA256B64URL hashes a string and returns an unpadded base64url digest.
func SHA256B64URL(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// PolicyEngineEvidenceFromMap normalizes one engine decision object.
func PolicyEngineEvidenceFromMap(raw map[string]any) PolicyEngineEvidence {
	if raw == nil {
		raw = map[string]any{}
	}
	return PolicyEngineEvidence{
		Allow:       boolValue(raw["allow"]),
		Engine:      stringValue(raw["engine"]),
		PolicyID:    stringValue(raw["policy_id"]),
		DenyReasons: stringSliceValue(firstPresent(raw, "deny_reasons", "deny")),
		Raw:         raw,
	}
}

// PolicyEvidenceFromMap normalizes Envoy/OPA/Cedar evidence from JSON.
func PolicyEvidenceFromMap(raw map[string]any) PolicyEvidence {
	if raw == nil {
		raw = map[string]any{}
	}
	return PolicyEvidence{
		Allow:            boolValue(raw["allow"]),
		PEP:              stringValue(raw["pep"]),
		PEPTransport:     stringValue(raw["pep_transport"]),
		EnforcementPoint: stringValue(raw["enforcement_point"]),
		PDPMode:          stringValue(raw["pdp_mode"]),
		ResourceID:       stringValue(raw["resource_id"]),
		RequiredScope:    stringValue(raw["required_scope"]),
		RequestedScope:   stringValue(raw["requested_scope"]),
		BundleVersion:    stringValue(raw["bundle_version"]),
		BundleSHA256:     stringValue(raw["bundle_sha256"]),
		OPA:              PolicyEngineEvidenceFromMap(mapValue(raw["opa"])),
		Cedar:            PolicyEngineEvidenceFromMap(mapValue(raw["cedar"])),
		Raw:              raw,
	}
}

// Allows checks the structural local-PDP evidence without making a policy decision.
func (e PolicyEvidence) Allows(resourceID string, requiredScope string) bool {
	if !e.Allow || e.PEP != ExpectedPolicyPEP {
		return false
	}
	if resourceID != "" && e.ResourceID != resourceID {
		return false
	}
	if requiredScope != "" && e.RequiredScope != requiredScope {
		return false
	}
	return e.OPA.Allow && e.Cedar.Allow
}

// PolicyEvidenceFromHeaders extracts Envoy policy evidence from headers.
func PolicyEvidenceFromHeaders(headers map[string]string) PolicyEvidence {
	return PolicyEvidenceFromMap(DecodeJSONHeader(GetHeader(headers, KSwitchPolicyEvidenceHeader)))
}

// ActorChainFromHeaders extracts the OBO actor chain from headers.
func ActorChainFromHeaders(headers map[string]string) map[string]any {
	return DecodeJSONHeader(GetHeader(headers, OBOActorChainHeader))
}

// SenderConstraintFromHeaders extracts proof-level sender binding from headers.
func SenderConstraintFromHeaders(headers map[string]string) map[string]any {
	return DecodeJSONHeader(GetHeader(headers, OBOSenderConstraintHeader))
}

// KSwitchDecisionFromHeaders extracts the central KSwitch enforcement reference.
func KSwitchDecisionFromHeaders(headers map[string]string) map[string]any {
	return DecodeJSONHeader(GetHeader(headers, KSwitchEnforcementDecisionHeader))
}

// BuildActorChain builds a portable human -> agent -> MCP -> broker chain.
func BuildActorChain(opts BuildActorChainOptions) map[string]any {
	actors := []map[string]any{
		{"role": "agent", "spiffe_id": opts.AgentSpiffeID},
		{"role": "mcp", "spiffe_id": opts.MCPSpiffeID},
	}
	if opts.BrokerSpiffeID != "" {
		actors = append(actors, map[string]any{"role": "broker", "spiffe_id": opts.BrokerSpiffeID})
	}
	chain := map[string]any{
		"sub":           opts.HumanSub,
		"human_subject": opts.HumanSubject,
		"human": map[string]any{
			"sub":     opts.HumanSub,
			"subject": opts.HumanSubject,
			"email":   opts.HumanEmail,
			"prompt":  opts.Prompt,
		},
		"actor":    map[string]any{"role": "agent", "spiffe_id": opts.AgentSpiffeID, "action": "interpreted human prompt"},
		"executor": map[string]any{"role": "mcp", "spiffe_id": opts.MCPSpiffeID, "action": "executed resource call"},
		"actors":   actors,
		"standards": map[string]any{
			"obo":               "RFC 8693 token exchange",
			"workload_identity": "SPIFFE/SPIRE JWT-SVID",
			"wimse_profile":     "WIMSE workload identity and authorization-evidence profile candidate",
		},
	}
	if opts.BrokerSpiffeID != "" {
		chain["broker"] = map[string]any{
			"role":      "obo-broker",
			"spiffe_id": opts.BrokerSpiffeID,
			"action":    "validated actor/executor and exchanged token",
		}
	}
	return chain
}

// BuildSenderConstraint builds proof-level SVID-bound sender evidence.
func BuildSenderConstraint(opts BuildSenderConstraintOptions) map[string]any {
	constraint := map[string]any{
		"type":                "svid-bound-proof",
		"confirmation_method": "jwt-svid-sha256",
		"actor_spiffe_id":     opts.AgentSpiffeID,
		"executor_spiffe_id":  opts.ExecutorSpiffeID,
		"broker_spiffe_id":    opts.BrokerSpiffeID,
		"resource_audience":   opts.ResourceAudience,
	}
	if opts.AgentJWTSVID != "" {
		constraint["agent_svid_sha256"] = SHA256B64URL(opts.AgentJWTSVID)
	}
	if opts.ExecutorJWTSVID != "" {
		constraint["mcp_svid_sha256"] = SHA256B64URL(opts.ExecutorJWTSVID)
	}
	return constraint
}

// BuildOBOHeaders encodes the actor-chain, scope, sender, and KSwitch references.
func BuildOBOHeaders(actorChain map[string]any, requestedScope string, senderConstraint map[string]any, kswitchDecision map[string]any, enforcementID string) (map[string]string, error) {
	actorHeader, err := EncodeJSONHeader(actorChain)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		OBOActorChainHeader:     actorHeader,
		OBORequestedScopeHeader: requestedScope,
	}
	if senderConstraint != nil {
		value, err := EncodeJSONHeader(senderConstraint)
		if err != nil {
			return nil, err
		}
		headers[OBOSenderConstraintHeader] = value
	}
	if kswitchDecision != nil {
		value, err := EncodeJSONHeader(kswitchDecision)
		if err != nil {
			return nil, err
		}
		headers[KSwitchEnforcementDecisionHeader] = value
	}
	if enforcementID != "" {
		headers[KSwitchEnforcementIDHeader] = enforcementID
	}
	return headers, nil
}

func firstPresent(raw map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			return value
		}
	}
	return nil
}

func boolValue(value any) bool {
	if v, ok := value.(bool); ok {
		return v
	}
	return false
}

func stringValue(value any) string {
	if v, ok := value.(string); ok {
		return v
	}
	return ""
}

func mapValue(value any) map[string]any {
	if v, ok := value.(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func stringSliceValue(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
