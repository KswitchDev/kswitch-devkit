// Package revocation provides a local O(1) revocation cache for the Go SDK.
//
// The cache is checked BEFORE any bundle/context evaluation.
// A revoked agent is denied without further evaluation.
//
// Disk persistence: {stateDir}/revocation/revoked.json (survives process restart).
// Sync: background RevocationSyncWorker polls the server and calls ApplyServerState().
//
// This mirrors Python LocalRevocationCache and TypeScript LocalRevocationCache
// exactly, including the JSON schema, staleness tracking, and diagnostics.
package revocation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const revocationExpiry = 86400 * time.Second // 24 hours

// RevocationEntry records when an agent was revoked and why.
type RevocationEntry struct {
	RevokedAt float64 `json:"revoked_at"` // Unix timestamp
	Reason    string  `json:"reason"`
}

// Diagnostics holds sync state metadata for observability.
type Diagnostics struct {
	ServerVersion    *int    `json:"server_version"`
	LastSyncedAt     float64 `json:"last_synced_at"`
	LastSyncFailure  string  `json:"last_sync_failure"`
	SyncFailureCount int     `json:"sync_failure_count"`
	BlanketKillActive bool   `json:"blanket_kill_active"`
	RevokedCount     int     `json:"revoked_count"`
	LoadedFromDisk   bool    `json:"loaded_from_disk"`
}

// LocalRevocationCache is a thread-safe in-process revocation cache with disk persistence.
// Mirrors Python LocalRevocationCache exactly.
type LocalRevocationCache struct {
	dir    string
	mu     sync.RWMutex
	revoked       map[string]RevocationEntry
	blanketActive bool
	loaded        bool
	// Sync metadata (PR-11)
	serverVersion    *int
	lastSyncedAt     time.Time
	syncedOnce       bool
	lastSyncFailure  string
	syncFailureCount int
}

// NewLocalRevocationCache creates a cache with the given storage directory.
// If dir is empty, DefaultRevocationDir() is used.
func NewLocalRevocationCache(dir string) *LocalRevocationCache {
	if dir == "" {
		dir = DefaultRevocationDir()
	}
	return &LocalRevocationCache{
		dir:     dir,
		revoked: make(map[string]RevocationEntry),
	}
}

// DefaultRevocationDir returns the default revocation storage directory.
// Resolution order:
//  1. $KSWITCH_STATE_DIR/revocation
//  2. $HOME/.kswitch/revocation
func DefaultRevocationDir() string {
	if s := os.Getenv("KSWITCH_STATE_DIR"); s != "" {
		return filepath.Join(s, "revocation")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kswitch", "revocation")
}

func (c *LocalRevocationCache) revocationPath() string {
	return filepath.Join(c.dir, "revoked.json")
}

// LoadFromDisk populates the cache from the persisted JSON file.
// Non-fatal: if the file is missing or corrupt, starts with empty state.
func (c *LocalRevocationCache) LoadFromDisk() {
	path := c.revocationPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return // file missing or unreadable — start fresh
	}

	var persisted struct {
		Revoked       map[string]RevocationEntry `json:"revoked"`
		BlanketActive bool                       `json:"blanket_active"`
		ServerVersion *int                       `json:"server_version"`
		LastSyncedAt  float64                    `json:"last_synced_at"`
	}
	if err := json.Unmarshal(data, &persisted); err != nil {
		return // corrupt — start fresh
	}

	c.mu.Lock()
	if persisted.Revoked != nil {
		c.revoked = persisted.Revoked
	}
	c.blanketActive = persisted.BlanketActive
	c.serverVersion = persisted.ServerVersion
	if persisted.LastSyncedAt > 0 {
		c.lastSyncedAt = time.Unix(int64(persisted.LastSyncedAt), 0)
		c.syncedOnce = true
	}
	c.loaded = true
	c.mu.Unlock()
}

func (c *LocalRevocationCache) ensureLoaded() {
	c.mu.RLock()
	loaded := c.loaded
	c.mu.RUnlock()
	if !loaded {
		c.LoadFromDisk()
		c.mu.Lock()
		c.loaded = true
		c.mu.Unlock()
	}
}

// IsRevoked returns true if the agent is currently revoked (or blanket kill is active).
func (c *LocalRevocationCache) IsRevoked(agentID string) bool {
	c.ensureLoaded()
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.blanketActive {
		return true
	}
	entry, ok := c.revoked[agentID]
	if !ok {
		return false
	}
	// Expire entries older than 24 hours.
	if time.Since(time.Unix(int64(entry.RevokedAt), 0)) > revocationExpiry {
		// Remove expired entry — needs write lock; take it.
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.revoked, agentID)
		c.mu.Unlock()
		c.mu.RLock() // reacquire read lock for defer
		return false
	}
	return true
}

// Revoke adds an agent to the revocation set and persists to disk.
func (c *LocalRevocationCache) Revoke(agentID, reason string) {
	c.ensureLoaded()
	c.mu.Lock()
	c.revoked[agentID] = RevocationEntry{
		RevokedAt: float64(time.Now().Unix()),
		Reason:    reason,
	}
	c.mu.Unlock()
	c.persist()
}

// SetBlanketKill sets the blanket kill flag and persists.
func (c *LocalRevocationCache) SetBlanketKill(active bool) {
	c.mu.Lock()
	c.blanketActive = active
	c.mu.Unlock()
	c.persist()
}

// ClearAgent removes a single agent from the revocation set and persists.
func (c *LocalRevocationCache) ClearAgent(agentID string) {
	c.mu.Lock()
	delete(c.revoked, agentID)
	c.mu.Unlock()
	c.persist()
}

// GetServerVersion returns the last known server revocation version.
func (c *LocalRevocationCache) GetServerVersion() *int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverVersion
}

// ApplyServerState atomically replaces the local revocation state from a server state payload.
// Mirrors Python apply_server_state(). Called by the background sync worker.
//
// state fields: version (int), blanket_kill_active (bool), revoked_agents ([]string).
func (c *LocalRevocationCache) ApplyServerState(state map[string]any) {
	now := time.Now()

	var serverVersion *int
	if v, ok := state["version"]; ok {
		switch vt := v.(type) {
		case float64:
			vi := int(vt)
			serverVersion = &vi
		case int:
			serverVersion = &vt
		}
	}

	blanket := false
	if b, ok := state["blanket_kill_active"]; ok {
		if bv, ok := b.(bool); ok {
			blanket = bv
		}
	}

	var revokedIDs []string
	if ids, ok := state["revoked_agents"]; ok {
		if arr, ok := ids.([]any); ok {
			for _, id := range arr {
				if s, ok := id.(string); ok {
					revokedIDs = append(revokedIDs, s)
				}
			}
		}
	}

	newRevoked := make(map[string]RevocationEntry, len(revokedIDs))
	for _, id := range revokedIDs {
		newRevoked[id] = RevocationEntry{
			RevokedAt: float64(now.Unix()),
			Reason:    "server_sync",
		}
	}

	c.mu.Lock()
	c.revoked = newRevoked
	c.blanketActive = blanket
	c.serverVersion = serverVersion
	c.lastSyncedAt = now
	c.syncedOnce = true
	c.lastSyncFailure = ""
	c.loaded = true
	c.mu.Unlock()

	c.persist()
}

// RecordSyncFailure records a sync failure for diagnostics (does not alter revocation state).
func (c *LocalRevocationCache) RecordSyncFailure(errMsg string) {
	c.mu.Lock()
	c.lastSyncFailure = errMsg
	c.syncFailureCount++
	c.mu.Unlock()
}

// IsSyncStale returns true if the last successful sync was more than thresholdSeconds ago.
// Returns true if never synced and thresholdSeconds > 0.
// Returns false if thresholdSeconds <= 0 (staleness checking disabled).
func (c *LocalRevocationCache) IsSyncStale(thresholdSeconds int) bool {
	if thresholdSeconds <= 0 {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.syncedOnce {
		return true
	}
	return time.Since(c.lastSyncedAt).Seconds() > float64(thresholdSeconds)
}

// GetDiagnostics returns sync state metadata for observability. Never panics.
func (c *LocalRevocationCache) GetDiagnostics() Diagnostics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var lastSyncedAt float64
	if c.syncedOnce {
		lastSyncedAt = float64(c.lastSyncedAt.Unix())
	}
	return Diagnostics{
		ServerVersion:     c.serverVersion,
		LastSyncedAt:      lastSyncedAt,
		LastSyncFailure:   c.lastSyncFailure,
		SyncFailureCount:  c.syncFailureCount,
		BlanketKillActive: c.blanketActive,
		RevokedCount:      len(c.revoked),
		LoadedFromDisk:    c.loaded,
	}
}

// persist saves revocation state to disk (best-effort, atomic rename).
// Mirrors Python _persist(). Errors are silently swallowed.
func (c *LocalRevocationCache) persist() {
	c.mu.RLock()
	data := map[string]any{
		"revoked":        c.revoked,
		"blanket_active": c.blanketActive,
		"updated_at":     float64(time.Now().Unix()),
		"server_version": c.serverVersion,
	}
	if c.syncedOnce {
		data["last_synced_at"] = float64(c.lastSyncedAt.Unix())
	}
	c.mu.RUnlock()

	if c.dir == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	dest := c.revocationPath()
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, dest) // best-effort
}

// ── Module-level singleton ────────────────────────────────────────────────────

var (
	defaultCache     *LocalRevocationCache
	defaultCacheMu   sync.Mutex
	defaultCacheOnce sync.Once
)

func getDefaultCache() *LocalRevocationCache {
	defaultCacheOnce.Do(func() {
		defaultCache = NewLocalRevocationCache("")
	})
	return defaultCache
}

// GetRevocationCache returns the module-level default revocation cache.
func GetRevocationCache() *LocalRevocationCache {
	return getDefaultCache()
}

// SetRevocationCache replaces the module-level default cache (for testing).
func SetRevocationCache(c *LocalRevocationCache) {
	defaultCacheMu.Lock()
	defaultCache = c
	defaultCacheOnce = sync.Once{}
	defaultCacheOnce.Do(func() {})
	defaultCacheMu.Unlock()
}

// ── State server response helper ─────────────────────────────────────────────

// ParseStateResponse parses a server state response into a map[string]any
// suitable for ApplyServerState. Returns an error if r is invalid JSON.
func ParseStateResponse(r []byte) (map[string]any, error) {
	var state map[string]any
	if err := json.Unmarshal(r, &state); err != nil {
		return nil, fmt.Errorf("revocation: parse state response: %w", err)
	}
	return state, nil
}
