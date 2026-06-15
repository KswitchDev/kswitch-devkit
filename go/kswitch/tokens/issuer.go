// Package tokens — KSwitch Go SDK Execution Token Issuer.
//
// Issues ES256-signed JWTs on ALLOW decisions in the SDK interceptor path.
// Uses Go stdlib crypto/ecdsa — zero external dependencies.
// Startup fails hard on bad key config.
//
// Usage:
//
//	issuer, err := tokens.NewIssuerFromEnv()
//	token, err := issuer.Issue(decision, tokens.IssueOptions{
//	    AgentID:     "agent:fraud-detector@bank",
//	    MCPServerID: "mcp:crm@bank",
//	    ToolName:    "read_customer",
//	})
package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TTL by risk tier (seconds).
var ttlByTier = map[string]int{
	"critical": 10,
	"high":     20,
	"medium":   45,
	"low":      90,
}

// defaultSingleUseClasses are action classes whose tokens are single-use.
var defaultSingleUseClasses = map[string]bool{
	"payment":       true,
	"admin":         true,
	"data_export":   true,
	"human_approval": true,
}

// Decision carries the fields the issuer reads from a governance decision.
// Callers may use any struct; the issuer accesses fields by name via this
// interface. A zero-value Decision is valid and produces safe defaults.
type Decision struct {
	RiskTier          string   `json:"risk_tier"`
	TraceID           string   `json:"trace_id"`
	ID                string   `json:"id"`
	DecisionID        string   `json:"decision_id"`
	PolicyIDsMatched  []string `json:"policy_ids_matched"`
	BundleVersion     string   `json:"bundle_version"`
	ContextPackID     string   `json:"context_pack_id"`
	RevocationVersion string   `json:"revocation_version"`
}

// IssueOptions carries per-call parameters for Issue.
type IssueOptions struct {
	AgentID     string
	MCPServerID string
	ToolName    string
	Context     map[string]any
}

// Issuer signs ES256 execution tokens.
type Issuer struct {
	privateKey      *ecdsa.PrivateKey
	kid             string
	issuer          string
	audience        string
	defaultTTL      int
	singleUseClasses map[string]bool
}

// NewIssuer constructs an Issuer from a PEM-encoded EC P-256 private key.
// Returns an error if the key is missing or not EC P-256.
func NewIssuer(privateKeyPEM, kid, issuerName, audience string, defaultTTL int, singleUseClasses map[string]bool) (*Issuer, error) {
	pem_ := strings.ReplaceAll(privateKeyPEM, `\n`, "\n")
	block, _ := pem.Decode([]byte(pem_))
	if block == nil {
		return nil, fmt.Errorf("KSwitchTokenIssuer: failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try SEC1 format
		ecKey, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("KSwitchTokenIssuer: bad signing key — %w", err)
		}
		key = ecKey
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("KSwitchTokenIssuer: signing key must be EC P-256 (ES256)")
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("KSwitchTokenIssuer: signing key must use curve P-256, got %s", ecKey.Curve.Params().Name)
	}

	if singleUseClasses == nil {
		singleUseClasses = defaultSingleUseClasses
	}
	if defaultTTL <= 0 {
		defaultTTL = 30
	}

	return &Issuer{
		privateKey:       ecKey,
		kid:              kid,
		issuer:           issuerName,
		audience:         audience,
		defaultTTL:       defaultTTL,
		singleUseClasses: singleUseClasses,
	}, nil
}

// NewIssuerFromEnv constructs an Issuer from environment variables.
// Returns an error if KSWITCH_EXECUTION_TOKEN_SIGNING_KEY is not set.
func NewIssuerFromEnv() (*Issuer, error) {
	key := os.Getenv("KSWITCH_EXECUTION_TOKEN_SIGNING_KEY")
	if key == "" {
		return nil, fmt.Errorf("KSWITCH_EXECUTION_TOKEN_SIGNING_KEY not set")
	}

	kid := os.Getenv("KSWITCH_EXECUTION_TOKEN_KID")
	if kid == "" {
		kid = "default"
	}
	iss := os.Getenv("KSWITCH_EXECUTION_TOKEN_ISSUER")
	if iss == "" {
		iss = "kswitch"
	}
	aud := os.Getenv("KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE")
	if aud == "" {
		aud = "kswitch-control-plane"
	}

	ttl := 30
	if v := os.Getenv("KSWITCH_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = n
		}
	}

	singleUse := defaultSingleUseClasses
	if v := os.Getenv("KSWITCH_EXECUTION_TOKEN_SINGLE_USE_CLASSES"); v != "" {
		singleUse = make(map[string]bool)
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				singleUse[c] = true
			}
		}
	}

	return NewIssuer(key, kid, iss, aud, ttl, singleUse)
}

// Issue signs an ES256 JWT for an ALLOW decision.
func (is *Issuer) Issue(decision Decision, opts IssueOptions) (string, error) {
	now := time.Now().Unix()
	riskTier := strings.ToLower(decision.RiskTier)
	if riskTier == "" {
		riskTier = "low"
	}
	ttl, ok := ttlByTier[riskTier]
	if !ok {
		ttl = is.defaultTTL
	}

	actionClass := classifyAction(opts.ToolName)
	singleUse := is.singleUseClasses[actionClass]

	traceID := decision.TraceID
	if traceID == "" {
		traceID = uuid.New().String()
	}
	decisionID := decision.ID
	if decisionID == "" {
		decisionID = decision.DecisionID
	}
	if decisionID == "" {
		decisionID = uuid.New().String()
	}
	policyID := "unknown"
	if len(decision.PolicyIDsMatched) > 0 {
		policyID = decision.PolicyIDsMatched[0]
	}
	bundleVer := decision.BundleVersion
	if bundleVer == "" {
		bundleVer = "0"
	}
	ctxPackID := decision.ContextPackID
	if ctxPackID == "" {
		ctxPackID = "default"
	}
	revVer := decision.RevocationVersion
	if revVer == "" {
		revVer = "0"
	}

	claims := map[string]any{
		"iss":                is.issuer,
		"sub":                opts.AgentID,
		"aud":                is.audience,
		"jti":                uuid.New().String(),
		"iat":                now,
		"exp":                now + int64(ttl),
		"nbf":                now,
		"trace_id":           traceID,
		"decision_id":        decisionID,
		"policy_id":          policyID,
		"bundle_version":     bundleVer,
		"context_pack_id":    ctxPackID,
		"action":             opts.ToolName,
		"resource":           opts.MCPServerID,
		"risk_tier":          riskTier,
		"revocation_version": revVer,
		"sdk_language":       "go",
	}

	// req_hash for CRITICAL and HIGH
	if riskTier == "critical" || riskTier == "high" {
		reqParams := map[string]any{
			"agent_id":      opts.AgentID,
			"mcp_server_id": opts.MCPServerID,
			"tool_name":     opts.ToolName,
		}
		if opts.Context != nil {
			reqParams["context"] = opts.Context
		}
		canonical, err := canonicalJSON(reqParams)
		if err != nil {
			return "", fmt.Errorf("req_hash canonical JSON: %w", err)
		}
		h := sha256.Sum256([]byte(canonical))
		claims["req_hash"] = fmt.Sprintf("%x", h)
	}

	if singleUse {
		claims["single_use"] = true
	}

	// Build header
	header := map[string]any{
		"alg": "ES256",
		"kid": is.kid,
		"typ": "JWT",
	}
	hdrJSON, _ := json.Marshal(header)
	payJSON, _ := json.Marshal(claims)

	hdrB64 := b64url(hdrJSON)
	payB64 := b64url(payJSON)
	signingInput := hdrB64 + "." + payB64

	// Sign with ES256
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, is.privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("ES256 sign: %w", err)
	}

	// Encode r||s as 64-byte big-endian
	rBytes := padTo32(r)
	sBytes := padTo32(s)
	rawSig := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(rawSig)

	return signingInput + "." + sigB64, nil
}

// GetJWKS returns a JWKS containing the public key for this issuer.
func (is *Issuer) GetJWKS() map[string]any {
	pub := is.privateKey.PublicKey
	x := padTo32(pub.X)
	y := padTo32(pub.Y)
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
				"kid": is.kid,
				"use": "sig",
				"alg": "ES256",
			},
		},
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// canonicalJSON produces a canonical JSON string with sorted keys.
func canonicalJSON(v map[string]any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var (
	rePayment       = regexp.MustCompile(`pay|transfer|charge|financial|fund|debit|credit`)
	reAdmin         = regexp.MustCompile(`admin|sudo|privilege|root|grant_role`)
	reDataExport    = regexp.MustCompile(`export|download|extract|dump|transfer_data`)
	reHumanApproval = regexp.MustCompile(`approve|authorize|human_approval|release`)
)

func classifyAction(action string) string {
	a := strings.ToLower(action)
	if rePayment.MatchString(a) {
		return "payment"
	}
	if reAdmin.MatchString(a) {
		return "admin"
	}
	if reDataExport.MatchString(a) {
		return "data_export"
	}
	if reHumanApproval.MatchString(a) {
		return "human_approval"
	}
	return ""
}

