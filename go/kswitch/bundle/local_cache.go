// Package bundle provides a disk-backed local policy bundle cache for the Go SDK.
//
// Bundle file: {stateDir}/bundle/current.bundle  (JSON)
//
// Bundle JSON schema (identical to Python and TypeScript SDKs):
//
//	{
//	  "version": 5,
//	  "bundle_id": "bundle:v5",
//	  "compiled_at": "2026-03-28T21:00:00Z",
//	  "cedar_text_enforce": "permit(...);",
//	  "cedar_text_shadow": "",
//	  "enforce_count": 3,
//	  "shadow_count": 0,
//	  "tool_count": 2,
//	  "tool_index": {"initiate_payment": {"requires_human_approval": false}},
//	  "signature": "sha256:<hex>"
//	}
//
// Signature verification matches Python LocalBundleCache._verify_signature():
// sha256 of JSON (sort_keys=True) over all fields except "signature".
package bundle

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Bundle max-age in seconds by risk tier (mirrors Python/TypeScript).
var bundleMaxAge = map[string]float64{
	"critical": 60,
	"high":     300,
	"medium":   900,
	"low":      3600,
}

// ErrBundleNotAvailable is returned when no valid local bundle exists.
var ErrBundleNotAvailable = errors.New("local bundle not available")

// ToolMeta holds per-tool metadata stored in the bundle's tool_index.
type ToolMeta struct {
	RequiresHumanApproval bool `json:"requires_human_approval"`
}

// LocalBundle is the in-process representation of a signed policy bundle.
// Fields match the JSON schema produced by the server bundle compiler.
type LocalBundle struct {
	Version          int                 `json:"version"`
	BundleID         string              `json:"bundle_id"`
	CompiledAt       string              `json:"compiled_at"`
	CedarTextEnforce string              `json:"cedar_text_enforce"`
	CedarTextShadow  string              `json:"cedar_text_shadow"`
	EnforceCount     int                 `json:"enforce_count"`
	ShadowCount      int                 `json:"shadow_count"`
	ToolCount        int                 `json:"tool_count"`
	ToolIndex        map[string]ToolMeta `json:"tool_index"`
	Signature        string              `json:"signature"`

	loadedAt time.Time // set on load, not persisted
}

// IsStale returns true if the bundle age exceeds the threshold for riskTier.
func (b *LocalBundle) IsStale(riskTier string) bool {
	maxAge, ok := bundleMaxAge[riskTier]
	if !ok {
		maxAge = bundleMaxAge["medium"]
	}
	return time.Since(b.loadedAt).Seconds() > maxAge
}

// HasTool returns true if the bundle's tool_index contains toolName.
func (b *LocalBundle) HasTool(toolName string) bool {
	_, ok := b.ToolIndex[toolName]
	return ok
}

// RequiresHumanApproval returns true if the tool is flagged for human approval.
func (b *LocalBundle) RequiresHumanApproval(toolName string) bool {
	meta, ok := b.ToolIndex[toolName]
	return ok && meta.RequiresHumanApproval
}

// LocalBundleCache is a disk-backed bundle cache with signature verification.
// Safe for concurrent use.
type LocalBundleCache struct {
	dir    string
	mu     sync.RWMutex
	bundle *LocalBundle
}

// NewLocalBundleCache creates a cache using the given directory.
// If dir is empty, DefaultBundleDir() is used.
func NewLocalBundleCache(dir string) *LocalBundleCache {
	if dir == "" {
		dir = DefaultBundleDir()
	}
	return &LocalBundleCache{dir: dir}
}

// DefaultBundleDir returns the default bundle storage directory.
// Resolution order:
//  1. $KSWITCH_STATE_DIR/bundle
//  2. $HOME/.kswitch/bundle
func DefaultBundleDir() string {
	if s := os.Getenv("KSWITCH_STATE_DIR"); s != "" {
		return filepath.Join(s, "bundle")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kswitch", "bundle")
}

func (c *LocalBundleCache) bundlePath() string {
	return filepath.Join(c.dir, "current.bundle")
}

// Load reads the bundle from disk, verifies signature, and updates the cache.
// Returns ErrBundleNotAvailable if the file is missing, corrupt, or fails verification.
func (c *LocalBundleCache) Load() (*LocalBundle, error) {
	path := c.bundlePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBundleNotAvailable, path)
		}
		return nil, fmt.Errorf("%w: read error: %v", ErrBundleNotAvailable, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: JSON parse error: %v", ErrBundleNotAvailable, err)
	}

	if !verifySignature(raw) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrBundleNotAvailable)
	}

	var bundle LocalBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: unmarshal error: %v", ErrBundleNotAvailable, err)
	}
	if bundle.ToolIndex == nil {
		bundle.ToolIndex = make(map[string]ToolMeta)
	}
	bundle.loadedAt = time.Now()

	c.mu.Lock()
	c.bundle = &bundle
	c.mu.Unlock()

	return &bundle, nil
}

// GetOrLoad returns the cached bundle or loads from disk.
// Returns nil (not an error) if no bundle is available.
func (c *LocalBundleCache) GetOrLoad() *LocalBundle {
	c.mu.RLock()
	cached := c.bundle
	c.mu.RUnlock()
	if cached != nil {
		return cached
	}
	b, _ := c.Load()
	return b
}

// Invalidate clears the in-memory cache. Next call will reload from disk.
func (c *LocalBundleCache) Invalidate() {
	c.mu.Lock()
	c.bundle = nil
	c.mu.Unlock()
}

// Store writes bundle JSON to disk atomically (write-to-.tmp, then rename).
// This mirrors Python os.replace() / TypeScript fs.renameSync().
func (c *LocalBundleCache) Store(bundleData map[string]any) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return fmt.Errorf("bundle store: mkdir: %w", err)
	}
	b, err := json.MarshalIndent(bundleData, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle store: marshal: %w", err)
	}
	dest := c.bundlePath()
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("bundle store: write tmp: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("bundle store: rename: %w", err)
	}
	c.Invalidate()
	return nil
}

// GetVersion returns the cached bundle version, or 0 if unavailable.
func (c *LocalBundleCache) GetVersion() int {
	b := c.GetOrLoad()
	if b == nil {
		return 0
	}
	return b.Version
}

// verifySignature verifies bundle integrity using sha256 of content fields.
// Mirrors Python LocalBundleCache._verify_signature():
//   - No signature: accepted in dev mode, rejected in production.
//   - Signature: sha256 of JSON(sort_keys=True) of all fields except "signature".
func verifySignature(raw map[string]json.RawMessage) bool {
	sigRaw, hasSig := raw["signature"]
	var storedSig string
	if hasSig {
		_ = json.Unmarshal(sigRaw, &storedSig)
	}

	if storedSig == "" {
		// No signature: accept in dev, reject in production.
		return os.Getenv("KSWITCH_ENV") != "production"
	}

	// Build sorted content map excluding "signature".
	// Use a stable JSON encoding: marshal as ordered-key map via sorted keys.
	content := make(map[string]json.RawMessage, len(raw)-1)
	for k, v := range raw {
		if k != "signature" {
			content[k] = v
		}
	}
	// json.Marshal on a map produces keys in sorted order (Go spec: maps are marshalled
	// with keys sorted lexicographically). This matches Python json.dumps(sort_keys=True).
	encoded, err := json.Marshal(content)
	if err != nil {
		return false
	}
	expected := "sha256:" + fmt.Sprintf("%x", sha256.Sum256(encoded))
	return storedSig == expected
}

// ── Module-level singleton ────────────────────────────────────────────────────

var (
	defaultCache     *LocalBundleCache
	defaultCacheMu   sync.Mutex
	defaultCacheOnce sync.Once
)

func getDefaultCache() *LocalBundleCache {
	defaultCacheOnce.Do(func() {
		defaultCache = NewLocalBundleCache("")
	})
	return defaultCache
}

// LoadCurrentBundle loads the current bundle from the default cache.
// Returns nil if no bundle is available.
func LoadCurrentBundle() *LocalBundle {
	return getDefaultCache().GetOrLoad()
}

// GetBundleCache returns the module-level default bundle cache.
func GetBundleCache() *LocalBundleCache {
	return getDefaultCache()
}

// SetBundleCache replaces the module-level default cache (for testing).
func SetBundleCache(c *LocalBundleCache) {
	defaultCacheMu.Lock()
	defaultCache = c
	// Reset once so the next GetBundleCache call returns the new cache.
	defaultCacheOnce = sync.Once{}
	defaultCacheOnce.Do(func() {}) // mark as done so getDefaultCache returns defaultCache
	defaultCacheMu.Unlock()
}
