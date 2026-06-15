// RevocationSyncWorker — background goroutine keeping the local revocation cache current.
//
// Mirrors Python RevocationSyncWorker and TypeScript RevocationSyncWorker exactly:
//   - Poll GET /api/v1/sdk/revocations/version on interval
//   - If blanket_kill_active flipped: apply immediately (fast path)
//   - If version changed: fetch GET /api/v1/sdk/revocations/state
//   - Apply full state atomically via ApplyServerState()
//
// Go-specific additions:
//   - Uses goroutine + time.Ticker instead of daemon thread
//   - Stop() is idempotent and blocks until the goroutine exits
//   - SyncOnce() is exported for test/manual trigger
//
// Auth (PR-11 closure): Revocation endpoints are authenticated at the application
// layer. Set SyncWorkerConfig.AuthHeader to a valid "Bearer <token>" value.
// Unauthenticated requests receive HTTP 401 and are surfaced as sync failures.
package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	versionPath = "/api/v1/sdk/revocations/version"
	statePath   = "/api/v1/sdk/revocations/state"
)

// HTTPDoer is the minimal interface required by RevocationSyncWorker.
// *http.Client satisfies this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// SyncWorkerConfig holds configuration for the sync worker.
type SyncWorkerConfig struct {
	BaseURL        string               // KSwitch server base URL, e.g. "https://localhost:5001"
	Interval       int                  // Poll interval in seconds (default: 30)
	StaleThreshold int                  // Seconds before state considered stale (default: 150)
	StaleMode      string               // "warn" | "deny" | "conditional" (default: "warn")
	HTTPClient     HTTPDoer             // Defaults to http.DefaultClient
	Cache          *LocalRevocationCache // Defaults to module singleton
	// AuthHeader is the Authorization header value sent with every revocation sync request,
	// e.g. "Bearer <m2m_token>". Required — revocation endpoints are authenticated at the
	// application layer (PR-11 closure). Set this to an M2M client_credentials token or a
	// static service token with Register.Service (or higher) role.
	AuthHeader string
}

// RevocationSyncWorker polls the server and keeps the local revocation cache current.
type RevocationSyncWorker struct {
	baseURL        string
	interval       time.Duration
	staleThreshold int
	staleMode      string
	httpClient     HTTPDoer
	authHeader     string // Authorization header value for authenticated endpoints
	cache          *LocalRevocationCache

	mu           sync.Mutex
	running      bool
	stopCh       chan struct{}
	doneCh       chan struct{}
	startedAt    time.Time

	// Diagnostics
	pollCount  int
	fetchCount int
	lastPollAt time.Time
	lastFetchAt time.Time
	lastError  string
}

// NewRevocationSyncWorker creates a new worker from config.
func NewRevocationSyncWorker(cfg SyncWorkerConfig) *RevocationSyncWorker {
	if cfg.Interval <= 0 {
		cfg.Interval = 30
	}
	if cfg.StaleThreshold <= 0 {
		cfg.StaleThreshold = 150
	}
	if cfg.StaleMode == "" {
		cfg.StaleMode = "warn"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Cache == nil {
		cfg.Cache = GetRevocationCache()
	}
	return &RevocationSyncWorker{
		baseURL:        strings.TrimRight(cfg.BaseURL, "/"),
		interval:       time.Duration(cfg.Interval) * time.Second,
		staleThreshold: cfg.StaleThreshold,
		staleMode:      cfg.StaleMode,
		httpClient:     cfg.HTTPClient,
		authHeader:     cfg.AuthHeader,
		cache:          cfg.Cache,
	}
}

// Start launches the background sync goroutine. Safe to call multiple times.
func (w *RevocationSyncWorker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running {
		return
	}
	w.running = true
	w.startedAt = time.Now()
	w.stopCh = make(chan struct{})
	w.doneCh = make(chan struct{})
	go w.run()
	slog.Info("kswitch.revocation.sync: started",
		"interval", w.interval,
		"stale_threshold", w.staleThreshold,
		"stale_mode", w.staleMode,
	)
}

// Stop signals the background goroutine to exit and blocks until it does.
// Safe to call multiple times.
func (w *RevocationSyncWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	close(w.stopCh)
	doneCh := w.doneCh
	w.mu.Unlock()

	<-doneCh
	slog.Info("kswitch.revocation.sync: stopped")
}

// IsRunning returns true if the background goroutine is active.
func (w *RevocationSyncWorker) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

// SyncOnce performs one sync cycle synchronously (for tests / manual trigger).
// Returns true if a full-state fetch was performed, false if version unchanged.
// Returns an error on unrecoverable failure.
func (w *RevocationSyncWorker) SyncOnce() (bool, error) {
	return w.pollAndMaybeFetch()
}

// Diagnostics returns the current worker and cache status for observability.
func (w *RevocationSyncWorker) Diagnostics() map[string]any {
	cacheDiag := w.cache.GetDiagnostics()

	w.mu.Lock()
	d := map[string]any{
		"running":                    w.running,
		"poll_count":                 w.pollCount,
		"fetch_count":                w.fetchCount,
		"last_error":                 w.lastError,
		"interval_seconds":           int(w.interval.Seconds()),
		"stale_threshold_seconds":    w.staleThreshold,
		"stale_mode":                 w.staleMode,
		"is_stale":                   w.cache.IsSyncStale(w.staleThreshold),
	}
	if !w.startedAt.IsZero() {
		d["started_at"] = w.startedAt.Unix()
	}
	if !w.lastPollAt.IsZero() {
		d["last_poll_at"] = w.lastPollAt.Unix()
	}
	if !w.lastFetchAt.IsZero() {
		d["last_fetch_at"] = w.lastFetchAt.Unix()
	}
	w.mu.Unlock()

	return map[string]any{
		"sync_worker": d,
		"cache":       cacheDiag,
	}
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (w *RevocationSyncWorker) run() {
	defer close(w.doneCh)
	slog.Debug("kswitch.revocation.sync: goroutine started")

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// First poll immediately.
	w.safePoll()

	for {
		select {
		case <-w.stopCh:
			slog.Debug("kswitch.revocation.sync: goroutine exiting")
			return
		case <-ticker.C:
			w.safePoll()
		}
	}
}

func (w *RevocationSyncWorker) safePoll() {
	if _, err := w.pollAndMaybeFetch(); err != nil {
		errStr := fmt.Sprintf("%.120s", err.Error())
		w.mu.Lock()
		w.lastError = errStr
		w.mu.Unlock()
		w.cache.RecordSyncFailure(errStr)
		slog.Warn("kswitch.revocation.sync: poll error", "error", errStr)
		w.checkStaleBehavior()
	}
}

func (w *RevocationSyncWorker) pollAndMaybeFetch() (bool, error) {
	now := time.Now()
	w.mu.Lock()
	w.pollCount++
	w.lastPollAt = now
	w.mu.Unlock()

	// ── Step 1: Cheap version check ──────────────────────────────────────────
	versionData, err := w.getJSON(context.Background(), w.baseURL+versionPath)
	if err != nil {
		return false, fmt.Errorf("version_check_failed: %w", err)
	}

	var serverVersion *int
	if v, ok := versionData["version"]; ok {
		if vf, ok := v.(float64); ok {
			vi := int(vf)
			serverVersion = &vi
		}
	}
	blanket, _ := versionData["blanket_kill_active"].(bool)

	// ── Step 2: Blanket kill fast path ───────────────────────────────────────
	if blanket {
		diag := w.cache.GetDiagnostics()
		if !diag.BlanketKillActive {
			slog.Warn("kswitch.revocation.sync: BLANKET KILL ACTIVE — applying immediately")
			state := map[string]any{
				"version":             serverVersion,
				"blanket_kill_active": true,
				"revoked_agents":      []string{},
			}
			if serverVersion != nil {
				state["version"] = *serverVersion
			}
			w.cache.ApplyServerState(state)
			return true, nil
		}
	}

	// ── Step 3: Version comparison ───────────────────────────────────────────
	localVersion := w.cache.GetServerVersion()
	if localVersion != nil && serverVersion != nil && *localVersion == *serverVersion {
		slog.Debug("kswitch.revocation.sync: version unchanged — skip fetch",
			"version", *serverVersion)
		// Reset staleness clock even on no-op polls.
		w.cache.mu.Lock()
		w.cache.lastSyncedAt = time.Now()
		w.cache.syncedOnce = true
		w.cache.mu.Unlock()
		return false, nil
	}

	// ── Step 4: Full-state fetch ─────────────────────────────────────────────
	var lv, sv string
	if localVersion != nil {
		lv = fmt.Sprintf("%d", *localVersion)
	} else {
		lv = "nil"
	}
	if serverVersion != nil {
		sv = fmt.Sprintf("%d", *serverVersion)
	} else {
		sv = "nil"
	}
	slog.Info("kswitch.revocation.sync: version changed — fetching full state",
		"local", lv, "server", sv)

	stateData, err := w.getJSON(context.Background(), w.baseURL+statePath)
	if err != nil {
		return false, fmt.Errorf("state_fetch_failed: %w", err)
	}

	// ── Step 5: Atomic cache update ──────────────────────────────────────────
	w.cache.ApplyServerState(stateData)

	w.mu.Lock()
	w.fetchCount++
	w.lastFetchAt = time.Now()
	w.lastError = ""
	w.mu.Unlock()

	slog.Info("kswitch.revocation.sync: synced ok",
		"version", stateData["version"],
		"blanket", stateData["blanket_kill_active"],
	)
	return true, nil
}

func (w *RevocationSyncWorker) getJSON(ctx context.Context, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Auth (PR-11 closure): revocation endpoints require application-layer authentication.
	if w.authHeader != "" {
		req.Header.Set("Authorization", w.authHeader)
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("revocation_auth_failed: HTTP 401 from %s — check AuthHeader or SDK token config", url)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}
	return result, nil
}

func (w *RevocationSyncWorker) checkStaleBehavior() {
	if !w.cache.IsSyncStale(w.staleThreshold) {
		return
	}
	switch w.staleMode {
	case "warn":
		slog.Warn("kswitch.revocation.sync: STALE — decisions continue with cached state",
			"threshold_seconds", w.staleThreshold)
	case "deny":
		slog.Error("kswitch.revocation.sync: STALE — stale_mode=deny, all decisions will DENY")
	case "conditional":
		slog.Warn("kswitch.revocation.sync: STALE — stale_mode=conditional, decisions escalate to server")
	}
}

// ── Module-level singleton worker ────────────────────────────────────────────

var (
	globalWorker   *RevocationSyncWorker
	globalWorkerMu sync.Mutex
)

// StartSyncWorker starts (or returns an existing) module-level sync worker.
// Idempotent — safe to call multiple times.
func StartSyncWorker(cfg SyncWorkerConfig) *RevocationSyncWorker {
	globalWorkerMu.Lock()
	defer globalWorkerMu.Unlock()
	if globalWorker != nil && globalWorker.IsRunning() {
		return globalWorker
	}
	globalWorker = NewRevocationSyncWorker(cfg)
	globalWorker.Start()
	return globalWorker
}

// StopSyncWorker stops the module-level sync worker if running.
func StopSyncWorker() {
	globalWorkerMu.Lock()
	defer globalWorkerMu.Unlock()
	if globalWorker != nil {
		globalWorker.Stop()
		globalWorker = nil
	}
}

// GetSyncWorker returns the active module-level sync worker, or nil if not started.
func GetSyncWorker() *RevocationSyncWorker {
	globalWorkerMu.Lock()
	defer globalWorkerMu.Unlock()
	return globalWorker
}
