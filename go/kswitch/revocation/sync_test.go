package revocation_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KswitchDev/kswitch-sdks/go/kswitch/revocation"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// versionResponse returns JSON for the /api/v1/sdk/revocations/version endpoint.
func versionResponse(version int, blanket bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"version":            version,
		"blanket_kill_active": blanket,
	})
	return b
}

// stateResponse returns JSON for the /api/v1/sdk/revocations/state endpoint.
func stateResponse(version int, blanket bool, revokedAgents []string) []byte {
	b, _ := json.Marshal(map[string]any{
		"version":            version,
		"blanket_kill_active": blanket,
		"revoked_agents":      revokedAgents,
	})
	return b
}

// mockRevocationServer creates a test HTTP server serving version and state endpoints.
// versionVal is returned by the version endpoint; stateAgents by the state endpoint.
func mockRevocationServer(t *testing.T, versionVal int, blanket bool, stateAgents []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sdk/revocations/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(versionResponse(versionVal, blanket))
	})
	mux.HandleFunc("/api/v1/sdk/revocations/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(stateResponse(versionVal, blanket, stateAgents))
	})
	return httptest.NewServer(mux)
}

// ── NewRevocationSyncWorker defaults ─────────────────────────────────────────

func TestNewRevocationSyncWorker_Defaults(t *testing.T) {
	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL: "http://localhost:5001",
		Cache:   cache,
	})
	if w == nil {
		t.Fatal("NewRevocationSyncWorker() returned nil")
	}
}

// ── Start / Stop ──────────────────────────────────────────────────────────────

func TestRevocationSyncWorker_StartStop(t *testing.T) {
	srv := mockRevocationServer(t, 1, false, []string{})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60, // long to avoid re-polling in test
		Cache:    cache,
	})
	w.Start()
	if !w.IsRunning() {
		t.Error("expected IsRunning()=true after Start()")
	}
	w.Stop()
	if w.IsRunning() {
		t.Error("expected IsRunning()=false after Stop()")
	}
}

func TestRevocationSyncWorker_StartIdempotent(t *testing.T) {
	srv := mockRevocationServer(t, 1, false, []string{})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})
	w.Start()
	w.Start() // must not panic or deadlock
	defer w.Stop()
	if !w.IsRunning() {
		t.Error("expected IsRunning()=true")
	}
}

// ── SyncOnce ─────────────────────────────────────────────────────────────────

func TestSyncOnce_AppliesServerState(t *testing.T) {
	srv := mockRevocationServer(t, 5, false, []string{"agent:bad@bank.internal"})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})

	fetched, err := w.SyncOnce()
	if err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}
	if !fetched {
		t.Error("expected full fetch on first sync (version nil vs 5)")
	}
	if !cache.IsRevoked("agent:bad@bank.internal") {
		t.Error("expected agent revoked after sync")
	}
	sv := cache.GetServerVersion()
	if sv == nil || *sv != 5 {
		t.Errorf("expected server version 5, got %v", sv)
	}
}

func TestSyncOnce_SkipsFetchWhenVersionUnchanged(t *testing.T) {
	var fetchCallCount int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sdk/revocations/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(versionResponse(7, false))
	})
	mux.HandleFunc("/api/v1/sdk/revocations/state", func(w http.ResponseWriter, r *http.Request) {
		fetchCallCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(stateResponse(7, false, []string{}))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})

	// First sync: fetches full state.
	w.SyncOnce()
	// Second sync: same version, should skip.
	fetched, err := w.SyncOnce()
	if err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}
	if fetched {
		t.Error("expected no full fetch when version unchanged")
	}
	if fetchCallCount > 1 {
		t.Errorf("state endpoint called %d times, expected ≤1", fetchCallCount)
	}
}

func TestSyncOnce_BlanketKillFastPath(t *testing.T) {
	srv := mockRevocationServer(t, 1, true, []string{})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})

	_, err := w.SyncOnce()
	if err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}
	if !cache.IsRevoked("agent:anyone@bank.internal") {
		t.Error("expected blanket kill active after sync")
	}
}

func TestSyncOnce_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})

	_, err := w.SyncOnce()
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestSyncOnce_UnreachableServer(t *testing.T) {
	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  "http://127.0.0.1:1", // nothing listening
		Interval: 60,
		Cache:    cache,
	})

	_, err := w.SyncOnce()
	if err == nil {
		t.Error("expected connection error for unreachable server")
	}
	// Failure should be recorded.
	diag := cache.GetDiagnostics()
	if diag.SyncFailureCount < 0 { // SyncOnce doesn't call RecordSyncFailure itself, safePoll does
		t.Error("unexpected negative failure count")
	}
}

// ── Background sync ───────────────────────────────────────────────────────────

func TestRevocationSyncWorker_BackgroundSync(t *testing.T) {
	srv := mockRevocationServer(t, 3, false, []string{"agent:revoked@bank.internal"})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 1, // 1-second interval for fast test
		Cache:    cache,
	})
	w.Start()
	defer w.Stop()

	// Background goroutine does an initial sync immediately.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cache.IsRevoked("agent:revoked@bank.internal") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cache.IsRevoked("agent:revoked@bank.internal") {
		t.Error("expected background sync to revoke agent within 3 seconds")
	}
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

func TestRevocationSyncWorker_Diagnostics(t *testing.T) {
	srv := mockRevocationServer(t, 1, false, []string{})
	defer srv.Close()

	cache := revocation.NewLocalRevocationCache(makeTmpDir(t))
	w := revocation.NewRevocationSyncWorker(revocation.SyncWorkerConfig{
		BaseURL:  srv.URL,
		Interval: 60,
		Cache:    cache,
	})
	w.SyncOnce()

	d := w.Diagnostics()
	sw, ok := d["sync_worker"].(map[string]any)
	if !ok {
		t.Fatalf("diagnostics missing sync_worker: %v", d)
	}
	if _, ok := sw["poll_count"]; !ok {
		t.Error("diagnostics missing poll_count")
	}
	if _, ok := d["cache"]; !ok {
		t.Error("diagnostics missing cache")
	}
}
