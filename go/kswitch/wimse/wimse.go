// Package wimse implements draft-ietf-wimse-workload-identity-02 delegation
// assertion building with KSwitch extensions.
//
// Signing algorithm: ES256 (ECDSA P-256) universally across all three SDKs,
// the JWKS registry, and the boundary validator. SPIRE issues EC P-256 SVIDs
// by default. Do NOT use Ed25519 -- it is incompatible with ES256 and will
// produce JWTs that fail verification at the boundary validator.
//
// Usage:
//
//	chain := wimse.NewChainBuilder()
//	err := chain.AddHop(wimse.HopOptions{
//	    DelegateeSpiffeID: "spiffe://bank.internal/agent/risk-engine",
//	    Scope:             "payments:read",
//	    Purpose:           "fraud-check",
//	    ResourceContext:   "account:123456",
//	    RootSessionID:     "sess-abc-123",
//	})
//	headerValue, err := chain.ToHeaderValue()
//	// Attach as: X-WIMSE-Delegation-Chain: <headerValue>

package wimse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── Field length limits (enforced before signing) ────────────────────────────

const (
	MaxPurposeLen         = 128
	MaxResourceContextLen = 256
	MaxWorkflowIDLen      = 64
	MaxChainDepth         = 3
	MaxAssertionTTL       = 300 * time.Second
	MaxChainHeaderBytes   = 8192
)

// ── HopOptions ───────────────────────────────────────────────────────────────

// HopOptions configures a single delegation hop in the WIMSE chain.
type HopOptions struct {
	DelegateeSpiffeID string // SPIFFE ID of the agent receiving delegation (required)
	Scope             string // delegated scope string (required)
	Purpose           string // business intent binding (required, max 128 chars)
	ResourceContext   string // data scope binding (required, max 256 chars)
	RootSessionID     string // initiating human session ID (required, propagated unchanged)

	// Optional fields. Empty string means null (omitted / JSON null).
	WorkflowID   string        // workflow correlation ID (max 64 chars)
	ApprovalHash string        // mandatory for Class 4 operations
	TTL          time.Duration // assertion TTL; 0 defaults to MaxAssertionTTL
}

// ── ChainBuilder ─────────────────────────────────────────────────────────────

// ChainBuilder builds and manages a WIMSE delegation chain across multiple hops.
//
// Each call to AddHop fetches a fresh SVID from the local SPIRE agent,
// constructs a WIMSE assertion, signs it with ES256, and appends the resulting
// JWT to the chain. The chain is serialized as a space-separated list of JWTs
// for the X-WIMSE-Delegation-Chain HTTP header.
type ChainBuilder struct {
	chain        []string
	lastJTI      *string // nil at hop 0 (before any hop)
	currentDepth int
}

// NewChainBuilder creates a new empty ChainBuilder.
func NewChainBuilder() *ChainBuilder {
	return &ChainBuilder{}
}

// Depth returns the current chain depth (number of hops added).
func (b *ChainBuilder) Depth() int {
	return b.currentDepth
}

// AddHop adds a delegation hop to the chain. Signs with this workload's SVID
// private key obtained from FetchSVID().
//
// Returns an error if field validation fails, chain depth is exceeded, or the
// SPIRE agent is unavailable.
func (b *ChainBuilder) AddHop(opts HopOptions) error {
	b.currentDepth++
	if b.currentDepth > MaxChainDepth {
		return fmt.Errorf("chain depth %d exceeds maximum %d", b.currentDepth, MaxChainDepth)
	}

	// Validate fields before signing.
	if len(opts.Purpose) > MaxPurposeLen {
		return fmt.Errorf("purpose exceeds %d chars", MaxPurposeLen)
	}
	if len(opts.ResourceContext) > MaxResourceContextLen {
		return fmt.Errorf("resource_context exceeds %d chars", MaxResourceContextLen)
	}
	if opts.WorkflowID != "" && len(opts.WorkflowID) > MaxWorkflowIDLen {
		return fmt.Errorf("workflow_id exceeds %d chars", MaxWorkflowIDLen)
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = MaxAssertionTTL
	}
	if ttl > MaxAssertionTTL {
		return fmt.Errorf("ttl %s exceeds %s max", ttl, MaxAssertionTTL)
	}

	// Atomic fetch: key and ID from the same SVID to avoid rotation race.
	svid, err := FetchSVID()
	if err != nil {
		return fmt.Errorf("SPIRE SVID fetch: %w", err)
	}

	ecKey, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("SVID private key must be EC P-256 for ES256 signing, got %T", svid.PrivateKey)
	}
	if ecKey.Curve != elliptic.P256() {
		return fmt.Errorf("SVID key must use curve P-256, got %s", ecKey.Curve.Params().Name)
	}

	jti := uuid.New().String()
	now := time.Now().Unix()
	ttlSec := int64(ttl.Seconds())

	// Build claims. Use nil interface{} for null fields (NOT empty string "").
	// This was a critical bug fix -- empty string "" is not JSON null.
	claims := map[string]interface{}{
		// Standard WIMSE fields
		"iss": svid.SpiffeID,
		"sub": opts.DelegateeSpiffeID,
		"iat": now,
		"exp": now + ttlSec,
		"jti": jti,
		// Chain binding
		"delegation_depth": b.currentDepth,
		// Scope
		"scope": opts.Scope,
		// Intent binding (mandatory)
		"purpose":          opts.Purpose,
		"resource_context": opts.ResourceContext,
		// Human accountability (mandatory)
		"root_session_id": opts.RootSessionID,
	}

	// parent_jti: nil (JSON null) at hop 1, set at subsequent hops.
	if b.lastJTI == nil {
		claims["parent_jti"] = nil // JSON null
	} else {
		claims["parent_jti"] = *b.lastJTI
	}

	// Optional fields: empty string -> JSON null (omit key entirely would also
	// work, but Python uses explicit null for parent_jti so we match that pattern).
	if opts.WorkflowID != "" {
		claims["workflow_id"] = opts.WorkflowID
	} else {
		claims["workflow_id"] = nil // JSON null, NOT empty string
	}
	if opts.ApprovalHash != "" {
		claims["approval_hash"] = opts.ApprovalHash
	} else {
		claims["approval_hash"] = nil // JSON null, NOT empty string
	}

	// Sign as ES256 JWT with typ=wimse+jwt.
	signedJWT, err := signES256(ecKey, claims)
	if err != nil {
		return fmt.Errorf("ES256 sign: %w", err)
	}

	b.chain = append(b.chain, signedJWT)
	b.lastJTI = &jti
	return nil
}

// ToHeaderValue serializes the chain as space-separated JWTs for the
// X-WIMSE-Delegation-Chain HTTP header.
//
// Returns an error if the serialized chain exceeds the 8 KB header limit.
func (b *ChainBuilder) ToHeaderValue() (string, error) {
	value := strings.Join(b.chain, " ")
	if len([]byte(value)) > MaxChainHeaderBytes {
		return "", fmt.Errorf("chain exceeds %d byte header limit", MaxChainHeaderBytes)
	}
	return value, nil
}

// ── DebugDecodeChain ─────────────────────────────────────────────────────────

// DebugDecodeChain decodes a space-separated JWT chain WITHOUT signature
// verification. UNSAFE -- debug / logging only. Do NOT use decoded payloads
// for access control or trust decisions. The boundary validator performs real
// cryptographic verification.
func DebugDecodeChain(headerValue string) ([]map[string]interface{}, error) {
	tokens := strings.Split(headerValue, " ")
	decoded := make([]map[string]interface{}, 0, len(tokens))
	for _, t := range tokens {
		parts := strings.Split(t, ".")
		if len(parts) != 3 {
			decoded = append(decoded, map[string]interface{}{"_error": "invalid JWT format"})
			continue
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			decoded = append(decoded, map[string]interface{}{"_error": err.Error()})
			continue
		}
		var claims map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			decoded = append(decoded, map[string]interface{}{"_error": err.Error()})
			continue
		}
		decoded = append(decoded, claims)
	}
	return decoded, nil
}

// ── ES256 JWT signing ────────────────────────────────────────────────────────

// signES256 constructs and signs a compact JWT with alg=ES256, typ=wimse+jwt.
// Uses Go stdlib crypto/ecdsa -- no external JWT library required.
func signES256(key *ecdsa.PrivateKey, claims map[string]interface{}) (string, error) {
	header := map[string]string{
		"alg": "ES256",
		"typ": "wimse+jwt",
	}

	hdrJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64

	// ES256: ECDSA with SHA-256.
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	// Encode r||s as 64-byte big-endian (32 bytes each for P-256).
	rBytes := padTo32(r)
	sBytes := padTo32(s)
	rawSig := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(rawSig)

	return signingInput + "." + sigB64, nil
}

// padTo32 pads a big.Int to exactly 32 bytes (big-endian).
func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
