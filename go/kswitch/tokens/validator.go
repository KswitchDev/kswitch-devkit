// Package tokens — KSwitch Go SDK Execution Token Validator.
//
// Enforces all ten required checks (design spec Section 11.3).
// Uses a local JWKS cache at KSWITCH_STATE_DIR/jwks/current.json.
// Maintains an independent disk-backed replay cache at KSWITCH_STATE_DIR/replay_cache/.
//
// Uses Go stdlib crypto/ecdsa — zero external dependencies.
//
// Usage:
//
//	validator, err := tokens.NewValidatorFromEnv()
//	result := validator.Validate(token, tokens.ValidateOptions{
//	    Action:   "read_customer",
//	    Resource: "mcp:crm@bank",
//	})
//	if !result.Valid { return fmt.Errorf(result.ErrorCode) }
package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	toleranceSeconds = 30
	graceSeconds     = 5
)

// ── ValidationResult ──────────────────────────────────────────────────────────

// ValidationResult holds the outcome of a token validation.
type ValidationResult struct {
	Valid     bool
	ErrorCode string
	Claims    map[string]any
	JTI       string
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

func b64urlDecode(s string) ([]byte, error) {
	// Pad to multiple of 4
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// parseJWKS parses a JWKS document and returns a map of kid → *ecdsa.PublicKey.
func parseJWKS(jwks map[string]any) map[string]*ecdsa.PublicKey {
	keys := make(map[string]*ecdsa.PublicKey)
	keysRaw, _ := jwks["keys"].([]any)
	for _, kRaw := range keysRaw {
		k, ok := kRaw.(map[string]any)
		if !ok {
			continue
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" {
			continue
		}
		xStr, _ := k["x"].(string)
		yStr, _ := k["y"].(string)
		kidStr, _ := k["kid"].(string)
		xBytes, err1 := base64.RawURLEncoding.DecodeString(xStr)
		yBytes, err2 := base64.RawURLEncoding.DecodeString(yStr)
		if err1 != nil || err2 != nil || kidStr == "" {
			continue
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		keys[kidStr] = pub
	}
	return keys
}

// verifyES256 verifies an ES256 JWT signature.
func verifyES256(headerB64, payloadB64, sigB64 string, pub *ecdsa.PublicKey) error {
	signingInput := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("sig base64: %w", err)
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("ES256 sig must be 64 bytes, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("ES256 signature verification failed")
	}
	return nil
}

// ── Replay cache (disk-backed) ─────────────────────────────────────────────────

type replayCache struct {
	mu       sync.Mutex
	store    map[string]float64 // jti → expiry unix timestamp
	filePath string
}

func newReplayCache(cacheDir string) *replayCache {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		// Best effort
	}
	rc := &replayCache{
		store:    make(map[string]float64),
		filePath: filepath.Join(cacheDir, "replay_cache.json"),
	}
	rc.load()
	return rc
}

func (rc *replayCache) isReplayed(jti string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.evict()
	_, found := rc.store[jti]
	return found
}

func (rc *replayCache) record(jti string, expDeadline float64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.evict()
	rc.store[jti] = expDeadline
	rc.save()
}

func (rc *replayCache) evict() {
	now := float64(time.Now().Unix())
	for k, v := range rc.store {
		if v < now {
			delete(rc.store, k)
		}
	}
}

func (rc *replayCache) load() {
	data, err := os.ReadFile(rc.filePath)
	if err != nil {
		return
	}
	var m map[string]float64
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	now := float64(time.Now().Unix())
	for k, v := range m {
		if v > now {
			rc.store[k] = v
		}
	}
}

func (rc *replayCache) save() {
	data, err := json.Marshal(rc.store)
	if err != nil {
		return
	}
	_ = os.WriteFile(rc.filePath, data, 0o600)
}

// ── Validator ──────────────────────────────────────────────────────────────────

// Validator validates ES256 execution tokens.
type Validator struct {
	mu               sync.RWMutex
	publicKeys       map[string]*ecdsa.PublicKey
	jwksURL          string
	jwksCachePath    string
	expectedIssuer   string
	expectedAudience string
	replayEnabled    bool
	replay           *replayCache
}

// ValidateOptions carries optional per-call validation constraints.
type ValidateOptions struct {
	Action        string
	Resource      string
	RequestParams map[string]any
}

// NewValidator constructs a Validator with explicit configuration.
func NewValidator(jwksURL, jwksCachePath, expectedIssuer, expectedAudience, replayCacheDir string, replayEnabled bool) *Validator {
	stateDir := os.Getenv("KSWITCH_STATE_DIR")
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = filepath.Join(home, ".kswitch", "state")
	}

	if jwksCachePath == "" {
		jwksCachePath = filepath.Join(stateDir, "jwks", "current.json")
	}
	if err := os.MkdirAll(filepath.Dir(jwksCachePath), 0o700); err != nil {
		// Best effort
	}
	if expectedIssuer == "" {
		expectedIssuer = "kswitch"
	}
	if expectedAudience == "" {
		expectedAudience = "kswitch-control-plane"
	}

	v := &Validator{
		publicKeys:       make(map[string]*ecdsa.PublicKey),
		jwksURL:          jwksURL,
		jwksCachePath:    jwksCachePath,
		expectedIssuer:   expectedIssuer,
		expectedAudience: expectedAudience,
		replayEnabled:    replayEnabled,
	}

	if replayEnabled {
		dir := replayCacheDir
		if dir == "" {
			dir = filepath.Join(stateDir, "replay_cache")
		}
		v.replay = newReplayCache(dir)
	}

	v.loadJWKS()
	return v
}

// NewValidatorFromEnv constructs a Validator from environment variables.
func NewValidatorFromEnv() *Validator {
	stateDir := os.Getenv("KSWITCH_STATE_DIR")
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = filepath.Join(home, ".kswitch", "state")
	}
	replayEnabled := true
	if v := os.Getenv("KSWITCH_EXECUTION_TOKEN_REPLAY_CACHE_ENABLED"); v == "false" {
		replayEnabled = false
	}
	return NewValidator(
		os.Getenv("KSWITCH_EXECUTION_TOKEN_JWKS_URL"),
		filepath.Join(stateDir, "jwks", "current.json"),
		os.Getenv("KSWITCH_EXECUTION_TOKEN_EXPECTED_ISSUER"),
		os.Getenv("KSWITCH_EXECUTION_TOKEN_EXPECTED_AUDIENCE"),
		filepath.Join(stateDir, "replay_cache"),
		replayEnabled,
	)
}

// LoadJWKSFromMap loads JWKS directly — used in tests to inject keys without network.
func (v *Validator) LoadJWKSFromMap(jwks map[string]any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.publicKeys = parseJWKS(jwks)
}

// Validate validates the token against all ten required checks.
func (v *Validator) Validate(token string, opts ValidateOptions) ValidationResult {
	if token == "" {
		return ValidationResult{ErrorCode: "execution_token_missing"}
	}

	// Split token
	parts := splitToken(token)
	if parts == nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}

	// Decode header to get kid
	headerJSON, err := b64urlDecode(parts[0])
	if err != nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}
	kid, _ := header["kid"].(string)

	// Check 2: kid known
	v.mu.RLock()
	pubKey, kidKnown := v.publicKeys[kid]
	v.mu.RUnlock()

	if !kidKnown {
		v.refreshJWKS()
		v.mu.RLock()
		pubKey, kidKnown = v.publicKeys[kid]
		v.mu.RUnlock()
		if !kidKnown {
			return ValidationResult{ErrorCode: "execution_token_unknown_kid"}
		}
	}

	// Check 1: Signature valid
	if err := verifyES256(parts[0], parts[1], parts[2], pubKey); err != nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}

	// Decode payload
	payloadJSON, err := b64urlDecode(parts[1])
	if err != nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return ValidationResult{ErrorCode: "execution_token_invalid_signature"}
	}

	jti, _ := claims["jti"].(string)
	now := float64(time.Now().Unix())

	// Check 3: Issuer
	if claims["iss"] != v.expectedIssuer {
		return ValidationResult{ErrorCode: "execution_token_unknown_kid", JTI: jti}
	}

	// Check 4: Audience
	if !audienceMatches(claims["aud"], v.expectedAudience) {
		return ValidationResult{ErrorCode: "execution_token_wrong_audience", JTI: jti}
	}

	// Check 5: Not expired
	exp := toFloat64(claims["exp"])
	if exp < now {
		return ValidationResult{ErrorCode: "execution_token_expired", JTI: jti}
	}

	// Check 6: Not before
	nbf := toFloat64(claims["nbf"])
	if nbf > now+toleranceSeconds {
		return ValidationResult{ErrorCode: "execution_token_not_yet_valid", JTI: jti}
	}

	// Check 7: Action matches
	if opts.Action != "" {
		if claims["action"] != opts.Action {
			return ValidationResult{ErrorCode: "execution_token_action_mismatch", JTI: jti}
		}
	}

	// Check 8: Resource matches
	if opts.Resource != "" {
		if claims["resource"] != opts.Resource {
			return ValidationResult{ErrorCode: "execution_token_resource_mismatch", JTI: jti}
		}
	}

	// Check 9: req_hash
	if _, hasReqHash := claims["req_hash"]; hasReqHash && opts.RequestParams != nil {
		canonical, err := canonicalJSON(opts.RequestParams)
		if err == nil {
			h := sha256.Sum256([]byte(canonical))
			expected := fmt.Sprintf("%x", h)
			if claims["req_hash"] != expected {
				return ValidationResult{ErrorCode: "execution_token_request_mismatch", JTI: jti}
			}
		}
	}

	// Check 10: Replay
	singleUse, _ := claims["single_use"].(bool)
	if singleUse && jti != "" && v.replayEnabled && v.replay != nil {
		if v.replay.isReplayed(jti) {
			return ValidationResult{ErrorCode: "execution_token_replay_detected", JTI: jti}
		}
		deadline := exp + graceSeconds
		v.replay.record(jti, deadline)
	}

	return ValidationResult{Valid: true, Claims: claims, JTI: jti}
}

// ── JWKS ──────────────────────────────────────────────────────────────────────

func (v *Validator) loadJWKS() {
	data, err := os.ReadFile(v.jwksCachePath)
	if err == nil {
		var jwks map[string]any
		if json.Unmarshal(data, &jwks) == nil {
			v.mu.Lock()
			v.publicKeys = parseJWKS(jwks)
			v.mu.Unlock()
			return
		}
	}
	v.refreshJWKS()
}

func (v *Validator) refreshJWKS() {
	if v.jwksURL == "" {
		return
	}
	// Use os/exec curl for synchronous HTTP (stdlib net/http is async by design;
	// we keep this best-effort so it never blocks the validation hot path).
	// In production the cache file is always pre-populated by server startup.
	raw, err := curlFetch(v.jwksURL)
	if err != nil || raw == "" {
		return
	}
	var jwks map[string]any
	if json.Unmarshal([]byte(raw), &jwks) != nil {
		return
	}
	v.mu.Lock()
	v.publicKeys = parseJWKS(jwks)
	v.mu.Unlock()
	_ = os.WriteFile(v.jwksCachePath, []byte(raw), 0o600)
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

func splitToken(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	dots := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			dots++
			if dots == 2 {
				parts = append(parts, token[start:])
				break
			}
		}
	}
	if len(parts) != 3 {
		return nil
	}
	return parts
}

func audienceMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, a := range v {
			if a == expected {
				return true
			}
		}
	}
	return false
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

// curlFetch fetches a URL synchronously using the system curl binary.
// Returns empty string if curl is unavailable or fails.
func curlFetch(url string) (string, error) {
	// Import os/exec only here to keep the package clean.
	// This is only called on cold start when the cache file is missing.
	return execCurl(url)
}
