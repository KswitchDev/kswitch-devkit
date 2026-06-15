// Package kscontext provides a disk-backed local agent context cache for the Go SDK.
// (Named kscontext to avoid shadowing Go's standard library "context" package.)
//
// Context pack file: {stateDir}/context/{sanitized_agent_id}.contextpack  (JSON)
//
// Context pack JSON schema (identical to Python and TypeScript SDKs):
//
//	{
//	  "agent_id": "agent:fraud-detector@bank.internal",
//	  "status": "active",
//	  "risk_tier": "high",
//	  "data_classifications": ["PII"],
//	  "is_revoked": false,
//	  "compiled_at": "2026-03-28T21:00:00Z",
//	  "pack_version": 3
//	}
package kscontext

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Context pack TTLs in seconds by risk tier (mirrors Python/TypeScript).
var contextPackTTL = map[string]float64{
	"critical": 5,
	"high":     30,
	"medium":   120,
	"low":      300,
}

// ErrContextNotAvailable is returned when no valid context pack exists for an agent.
var ErrContextNotAvailable = errors.New("context pack not available")

// LocalContextPack is the in-process representation of an agent context pack.
type LocalContextPack struct {
	AgentID             string   `json:"agent_id"`
	Status              string   `json:"status"`
	RiskTier            string   `json:"risk_tier"`
	DataClassifications []string `json:"data_classifications"`
	IsRevoked           bool     `json:"is_revoked"`
	CompiledAt          string   `json:"compiled_at"`
	PackVersion         int      `json:"pack_version"`

	loadedAt time.Time // set on load, not persisted
}

// IsActive returns true if the agent is in an active status and not revoked.
// Mirrors Python: status in ("active", "declared", "pending") and not is_revoked.
func (p *LocalContextPack) IsActive() bool {
	active := p.Status == "active" || p.Status == "declared" || p.Status == "pending"
	return active && !p.IsRevoked
}

// IsStale returns true if the pack age exceeds the TTL for its risk tier.
func (p *LocalContextPack) IsStale() bool {
	ttl, ok := contextPackTTL[strings.ToLower(p.RiskTier)]
	if !ok {
		ttl = contextPackTTL["medium"]
	}
	return time.Since(p.loadedAt).Seconds() > ttl
}

// sanitizeAgentID converts an agent ID to a safe filename component.
// Mirrors Python _sanitize_agent_id().
func sanitizeAgentID(agentID string) string {
	r := strings.NewReplacer(
		":", "_",
		"/", "_",
		"@", "_at_",
		".", "_",
	)
	return r.Replace(agentID)
}

// LocalContextCache is a disk-backed context pack cache. Safe for concurrent use.
type LocalContextCache struct {
	dir   string
	mu    sync.RWMutex
	packs map[string]*LocalContextPack
}

// NewLocalContextCache creates a cache using the given directory.
// If dir is empty, DefaultContextDir() is used.
func NewLocalContextCache(dir string) *LocalContextCache {
	if dir == "" {
		dir = DefaultContextDir()
	}
	return &LocalContextCache{
		dir:   dir,
		packs: make(map[string]*LocalContextPack),
	}
}

// DefaultContextDir returns the default context pack storage directory.
// Resolution order:
//  1. $KSWITCH_STATE_DIR/context
//  2. $HOME/.kswitch/context
func DefaultContextDir() string {
	if s := os.Getenv("KSWITCH_STATE_DIR"); s != "" {
		return filepath.Join(s, "context")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kswitch", "context")
}

func (c *LocalContextCache) packPath(agentID string) string {
	return filepath.Join(c.dir, sanitizeAgentID(agentID)+".contextpack")
}

// Load reads a context pack from disk for the given agent ID.
// Returns ErrContextNotAvailable if the file is missing or corrupt.
func (c *LocalContextCache) Load(agentID string) (*LocalContextPack, error) {
	path := c.packPath(agentID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w for %s: %s", ErrContextNotAvailable, agentID, path)
		}
		return nil, fmt.Errorf("%w: read error: %v", ErrContextNotAvailable, err)
	}

	var pack LocalContextPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("%w: JSON parse error: %v", ErrContextNotAvailable, err)
	}
	if pack.DataClassifications == nil {
		pack.DataClassifications = []string{}
	}
	pack.loadedAt = time.Now()

	c.mu.Lock()
	c.packs[agentID] = &pack
	c.mu.Unlock()

	return &pack, nil
}

// GetOrLoad returns the cached pack (if not stale) or loads from disk.
// Returns nil (not an error) if no pack is available.
func (c *LocalContextCache) GetOrLoad(agentID string) *LocalContextPack {
	c.mu.RLock()
	cached, ok := c.packs[agentID]
	c.mu.RUnlock()
	if ok && !cached.IsStale() {
		return cached
	}
	pack, _ := c.Load(agentID)
	return pack
}

// Store writes a context pack JSON to disk atomically and invalidates the cache.
// Mirrors Python LocalContextCache.store(): atomic write via .tmp rename.
func (c *LocalContextCache) Store(agentID string, packData map[string]any) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return fmt.Errorf("context store: mkdir: %w", err)
	}
	packData["agent_id"] = agentID
	b, err := json.MarshalIndent(packData, "", "  ")
	if err != nil {
		return fmt.Errorf("context store: marshal: %w", err)
	}
	dest := c.packPath(agentID)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("context store: write tmp: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("context store: rename: %w", err)
	}
	c.mu.Lock()
	delete(c.packs, agentID)
	c.mu.Unlock()
	return nil
}

// Invalidate removes the cached pack for the given agent. Next call reloads from disk.
func (c *LocalContextCache) Invalidate(agentID string) {
	c.mu.Lock()
	delete(c.packs, agentID)
	c.mu.Unlock()
}

// ── Module-level singleton ────────────────────────────────────────────────────

var (
	defaultCache     *LocalContextCache
	defaultCacheMu   sync.Mutex
	defaultCacheOnce sync.Once
)

func getDefaultCache() *LocalContextCache {
	defaultCacheOnce.Do(func() {
		defaultCache = NewLocalContextCache("")
	})
	return defaultCache
}

// LoadContextPack loads the context pack for agentID from the default cache.
// Returns nil if no pack is available.
func LoadContextPack(agentID string) *LocalContextPack {
	return getDefaultCache().GetOrLoad(agentID)
}

// GetContextCache returns the module-level default context cache.
func GetContextCache() *LocalContextCache {
	return getDefaultCache()
}

// SetContextCache replaces the module-level default cache (for testing).
func SetContextCache(c *LocalContextCache) {
	defaultCacheMu.Lock()
	defaultCache = c
	defaultCacheOnce = sync.Once{}
	defaultCacheOnce.Do(func() {})
	defaultCacheMu.Unlock()
}
