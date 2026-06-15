package wimse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// testKey generates a fresh P-256 key pair for testing.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

// mockFetchSVID installs a mock FetchSVID that returns the given key and
// SPIFFE ID. Returns a cleanup function to restore the original.
func mockFetchSVID(key *ecdsa.PrivateKey, spiffeID string) func() {
	orig := fetchSVIDFunc
	fetchSVIDFunc = func() (*SVIDBundle, error) {
		return &SVIDBundle{
			PrivateKey: key,
			SpiffeID:   spiffeID,
		}, nil
	}
	return func() { fetchSVIDFunc = orig }
}

// decodePayload extracts and unmarshals the payload from a compact JWT.
func decodePayload(t *testing.T, jwt string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// decodeHeader extracts and unmarshals the header from a compact JWT.
func decodeHeader(t *testing.T, jwt string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return hdr
}

// defaultOpts returns valid HopOptions for testing.
func defaultOpts() HopOptions {
	return HopOptions{
		DelegateeSpiffeID: "spiffe://bank.internal/agent/risk-engine",
		Scope:             "payments:read",
		Purpose:           "fraud-check",
		ResourceContext:   "account:123456",
		RootSessionID:     "sess-abc-123",
	}
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestPurposeTooLong(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	opts.Purpose = strings.Repeat("x", MaxPurposeLen+1)
	err := chain.AddHop(opts)
	if err == nil {
		t.Fatal("expected error for purpose too long")
	}
	if !strings.Contains(err.Error(), "purpose exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResourceContextTooLong(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	opts.ResourceContext = strings.Repeat("x", MaxResourceContextLen+1)
	err := chain.AddHop(opts)
	if err == nil {
		t.Fatal("expected error for resource_context too long")
	}
	if !strings.Contains(err.Error(), "resource_context exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWorkflowIDTooLong(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	opts.WorkflowID = strings.Repeat("w", MaxWorkflowIDLen+1)
	err := chain.AddHop(opts)
	if err == nil {
		t.Fatal("expected error for workflow_id too long")
	}
	if !strings.Contains(err.Error(), "workflow_id exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTTLExceeded(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	opts.TTL = MaxAssertionTTL + time.Second
	err := chain.AddHop(opts)
	if err == nil {
		t.Fatal("expected error for TTL exceeded")
	}
	if !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChainDepthExceeded(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	for i := 0; i < MaxChainDepth; i++ {
		if err := chain.AddHop(defaultOpts()); err != nil {
			t.Fatalf("hop %d: %v", i+1, err)
		}
	}
	// Hop 4 should fail.
	err := chain.AddHop(defaultOpts())
	if err == nil {
		t.Fatal("expected error for chain depth exceeded")
	}
	if !strings.Contains(err.Error(), "chain depth") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddHopProducesValidJWT(t *testing.T) {
	key := testKey(t)
	spiffeID := "spiffe://bank.internal/agent/payments"
	cleanup := mockFetchSVID(key, spiffeID)
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	opts.WorkflowID = "wf-001"
	opts.ApprovalHash = "abc123"
	err := chain.AddHop(opts)
	if err != nil {
		t.Fatalf("AddHop: %v", err)
	}

	headerVal, err := chain.ToHeaderValue()
	if err != nil {
		t.Fatalf("ToHeaderValue: %v", err)
	}

	// Should be a single JWT.
	jwts := strings.Split(headerVal, " ")
	if len(jwts) != 1 {
		t.Fatalf("expected 1 JWT, got %d", len(jwts))
	}

	// Check header.
	hdr := decodeHeader(t, jwts[0])
	if hdr["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", hdr["alg"])
	}
	if hdr["typ"] != "wimse+jwt" {
		t.Errorf("typ = %v, want wimse+jwt", hdr["typ"])
	}

	// Check claims.
	claims := decodePayload(t, jwts[0])
	if claims["iss"] != spiffeID {
		t.Errorf("iss = %v, want %s", claims["iss"], spiffeID)
	}
	if claims["sub"] != opts.DelegateeSpiffeID {
		t.Errorf("sub = %v, want %s", claims["sub"], opts.DelegateeSpiffeID)
	}
	if claims["scope"] != opts.Scope {
		t.Errorf("scope = %v, want %s", claims["scope"], opts.Scope)
	}
	if claims["purpose"] != opts.Purpose {
		t.Errorf("purpose = %v, want %s", claims["purpose"], opts.Purpose)
	}
	if claims["resource_context"] != opts.ResourceContext {
		t.Errorf("resource_context = %v, want %s", claims["resource_context"], opts.ResourceContext)
	}
	if claims["root_session_id"] != opts.RootSessionID {
		t.Errorf("root_session_id = %v, want %s", claims["root_session_id"], opts.RootSessionID)
	}
	if claims["workflow_id"] != "wf-001" {
		t.Errorf("workflow_id = %v, want wf-001", claims["workflow_id"])
	}
	if claims["approval_hash"] != "abc123" {
		t.Errorf("approval_hash = %v, want abc123", claims["approval_hash"])
	}
	// delegation_depth should be 1.
	if depth, ok := claims["delegation_depth"].(float64); !ok || int(depth) != 1 {
		t.Errorf("delegation_depth = %v, want 1", claims["delegation_depth"])
	}
	// jti should be present.
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti should be set")
	}
	// iat and exp should be present.
	if claims["iat"] == nil {
		t.Error("iat should be set")
	}
	if claims["exp"] == nil {
		t.Error("exp should be set")
	}
}

func TestParentJTINilAtHop1(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("AddHop: %v", err)
	}

	headerVal, _ := chain.ToHeaderValue()
	claims := decodePayload(t, strings.Split(headerVal, " ")[0])

	// parent_jti must be JSON null (decoded as nil in Go).
	val, exists := claims["parent_jti"]
	if !exists {
		t.Fatal("parent_jti key should exist in claims")
	}
	if val != nil {
		t.Errorf("parent_jti at hop 1 = %v, want nil (JSON null)", val)
	}
}

func TestParentJTISetAtHop2(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("hop 1: %v", err)
	}
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("hop 2: %v", err)
	}

	headerVal, _ := chain.ToHeaderValue()
	jwts := strings.Split(headerVal, " ")
	if len(jwts) != 2 {
		t.Fatalf("expected 2 JWTs, got %d", len(jwts))
	}

	hop1Claims := decodePayload(t, jwts[0])
	hop2Claims := decodePayload(t, jwts[1])

	// hop2 parent_jti should match hop1 jti.
	hop1JTI := hop1Claims["jti"]
	hop2ParentJTI := hop2Claims["parent_jti"]
	if hop2ParentJTI == nil {
		t.Fatal("hop 2 parent_jti should not be nil")
	}
	if hop1JTI != hop2ParentJTI {
		t.Errorf("hop2 parent_jti = %v, want %v (hop1 jti)", hop2ParentJTI, hop1JTI)
	}
}

func TestChainDepthIncrements(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	if chain.Depth() != 0 {
		t.Errorf("initial depth = %d, want 0", chain.Depth())
	}

	for i := 1; i <= MaxChainDepth; i++ {
		if err := chain.AddHop(defaultOpts()); err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
		if chain.Depth() != i {
			t.Errorf("depth after hop %d = %d, want %d", i, chain.Depth(), i)
		}
	}

	// Verify delegation_depth in each JWT.
	headerVal, _ := chain.ToHeaderValue()
	jwts := strings.Split(headerVal, " ")
	for i, jwt := range jwts {
		claims := decodePayload(t, jwt)
		depth := int(claims["delegation_depth"].(float64))
		if depth != i+1 {
			t.Errorf("jwt[%d] delegation_depth = %d, want %d", i, depth, i+1)
		}
	}
}

func TestMaxDepthEnforcement(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	for i := 0; i < MaxChainDepth; i++ {
		if err := chain.AddHop(defaultOpts()); err != nil {
			t.Fatalf("hop %d: %v", i+1, err)
		}
	}

	// Hop MaxChainDepth+1 must fail.
	err := chain.AddHop(defaultOpts())
	if err == nil {
		t.Fatal("expected error at hop 4")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestToHeaderValueSpaceSeparated(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	chain := NewChainBuilder()
	for i := 0; i < 2; i++ {
		if err := chain.AddHop(defaultOpts()); err != nil {
			t.Fatalf("hop %d: %v", i+1, err)
		}
	}

	headerVal, err := chain.ToHeaderValue()
	if err != nil {
		t.Fatalf("ToHeaderValue: %v", err)
	}

	jwts := strings.Split(headerVal, " ")
	if len(jwts) != 2 {
		t.Fatalf("expected 2 space-separated JWTs, got %d", len(jwts))
	}

	// Each part should have 3 dot-separated segments.
	for i, jwt := range jwts {
		if len(strings.Split(jwt, ".")) != 3 {
			t.Errorf("jwt[%d] is not a valid compact JWT", i)
		}
	}
}

func TestHeaderSizeEnforcement(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/a")
	defer cleanup()

	// Build a chain and then manually inject an oversized JWT to test the limit.
	chain := NewChainBuilder()
	// Inject fake large JWTs directly into the chain field.
	bigJWT := strings.Repeat("A", MaxChainHeaderBytes+1)
	chain.chain = append(chain.chain, bigJWT)

	_, err := chain.ToHeaderValue()
	if err == nil {
		t.Fatal("expected error for oversized header")
	}
	if !strings.Contains(err.Error(), "header limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDebugDecodeChainRoundTrips(t *testing.T) {
	key := testKey(t)
	spiffeID := "spiffe://test/agent/decoder"
	cleanup := mockFetchSVID(key, spiffeID)
	defer cleanup()

	chain := NewChainBuilder()
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("AddHop: %v", err)
	}
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("AddHop: %v", err)
	}

	headerVal, err := chain.ToHeaderValue()
	if err != nil {
		t.Fatalf("ToHeaderValue: %v", err)
	}

	decoded, err := DebugDecodeChain(headerVal)
	if err != nil {
		t.Fatalf("DebugDecodeChain: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 decoded payloads, got %d", len(decoded))
	}

	for i, d := range decoded {
		if _, ok := d["_error"]; ok {
			t.Errorf("decoded[%d] has error: %v", i, d["_error"])
		}
		if d["iss"] != spiffeID {
			t.Errorf("decoded[%d] iss = %v, want %s", i, d["iss"], spiffeID)
		}
		if d["purpose"] != "fraud-check" {
			t.Errorf("decoded[%d] purpose = %v, want fraud-check", i, d["purpose"])
		}
	}
}

func TestEmptyOptionalFieldsMarshalAsNull(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/null-check")
	defer cleanup()

	chain := NewChainBuilder()
	opts := defaultOpts()
	// Leave WorkflowID and ApprovalHash as empty strings (default).
	opts.WorkflowID = ""
	opts.ApprovalHash = ""
	if err := chain.AddHop(opts); err != nil {
		t.Fatalf("AddHop: %v", err)
	}

	headerVal, _ := chain.ToHeaderValue()
	jwt := strings.Split(headerVal, " ")[0]

	// Decode raw JSON payload to check for null vs empty string.
	parts := strings.Split(jwt, ".")
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// Check raw JSON: workflow_id and approval_hash should be null, not "".
	payStr := string(payBytes)
	if strings.Contains(payStr, `"workflow_id":""`) {
		t.Error("workflow_id is empty string, should be null")
	}
	if strings.Contains(payStr, `"approval_hash":""`) {
		t.Error("approval_hash is empty string, should be null")
	}

	// Also verify via parsed claims.
	var claims map[string]interface{}
	if err := json.Unmarshal(payBytes, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims["workflow_id"] != nil {
		t.Errorf("workflow_id = %v (%T), want nil", claims["workflow_id"], claims["workflow_id"])
	}
	if claims["approval_hash"] != nil {
		t.Errorf("approval_hash = %v (%T), want nil", claims["approval_hash"], claims["approval_hash"])
	}
	// parent_jti at hop 1 should also be nil.
	if claims["parent_jti"] != nil {
		t.Errorf("parent_jti = %v (%T), want nil", claims["parent_jti"], claims["parent_jti"])
	}
}

func TestDepthReturnsCurrentDepth(t *testing.T) {
	key := testKey(t)
	cleanup := mockFetchSVID(key, "spiffe://test/agent/depth")
	defer cleanup()

	chain := NewChainBuilder()
	if chain.Depth() != 0 {
		t.Errorf("Depth() = %d before any hop, want 0", chain.Depth())
	}
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("AddHop: %v", err)
	}
	if chain.Depth() != 1 {
		t.Errorf("Depth() = %d after 1 hop, want 1", chain.Depth())
	}
	if err := chain.AddHop(defaultOpts()); err != nil {
		t.Fatalf("AddHop: %v", err)
	}
	if chain.Depth() != 2 {
		t.Errorf("Depth() = %d after 2 hops, want 2", chain.Depth())
	}
}

func TestSPIREUnavailableError(t *testing.T) {
	// Restore the default fetchSVIDFunc which should fail (no socket).
	orig := fetchSVIDFunc
	fetchSVIDFunc = defaultFetchSVID
	defer func() { fetchSVIDFunc = orig }()

	chain := NewChainBuilder()
	err := chain.AddHop(defaultOpts())
	if err == nil {
		t.Fatal("expected error when SPIRE is unavailable")
	}
	if !strings.Contains(err.Error(), "SPIRE") {
		t.Fatalf("unexpected error: %v", err)
	}
}
