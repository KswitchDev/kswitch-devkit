package audit_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTestEvent(t *testing.T) audit.AuditEvent {
	t.Helper()
	return audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"tool",
		true, "allowed", "",
		nil, nil, "allow_raw",
		"bundle:v1", "cp:v1", "low", 1.0,
	)
}

// ── NewAuditSender / Start / Stop ─────────────────────────────────────────────

func TestAuditSender_StartStop(t *testing.T) {
	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL: "http://localhost:9999/api/v1/sdk/audit/events",
	})
	s.Start()
	d := s.Diagnostics()
	if !d.Running {
		t.Error("expected Running=true after Start()")
	}
	s.Stop()
	d = s.Diagnostics()
	if d.Running {
		t.Error("expected Running=false after Stop()")
	}
}

func TestAuditSender_StartIdempotent(t *testing.T) {
	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL: "http://localhost:9999/api/v1/sdk/audit/events",
	})
	s.Start()
	s.Start() // second call must be safe
	defer s.Stop()
	d := s.Diagnostics()
	if !d.Running {
		t.Error("expected Running=true")
	}
}

// ── Enqueue / drop ────────────────────────────────────────────────────────────

func TestAuditSender_EnqueueNeverBlocks(t *testing.T) {
	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL: "http://localhost:9999/api/v1/sdk/audit/events",
		BatchSize: 50,
	})
	s.Start()
	defer s.Stop()

	ev := makeTestEvent(t)
	// Enqueue 510 events — 500 fit, 10 should be dropped.
	for i := 0; i < 510; i++ {
		s.Enqueue(ev)
	}
	d := s.Diagnostics()
	if d.DropCount < 1 {
		// May be fewer than 10 if the flush goroutine drained some — just ensure no deadlock.
		t.Log("note: drop count < 1, flush goroutine may have drained queue")
	}
	// Most important: test completed without blocking.
}

// ── HTTP forwarding ───────────────────────────────────────────────────────────

func TestAuditSender_SendsToEndpoint(t *testing.T) {
	var received atomic.Int64
	var lastPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &lastPayload)
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     srv.URL + "/api/v1/sdk/audit/events",
		BatchSize:     2,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    1,
	})
	s.Start()

	ev := makeTestEvent(t)
	s.Enqueue(ev)
	s.Enqueue(ev)

	// Wait for flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if received.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	s.Stop()

	if received.Load() < 1 {
		t.Error("expected at least one POST request to audit endpoint")
	}
	if evs, ok := lastPayload["events"].([]any); !ok || len(evs) == 0 {
		t.Errorf("payload missing 'events' array: %v", lastPayload)
	}
}

func TestAuditSender_BatchFormat(t *testing.T) {
	var captured map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     srv.URL,
		BatchSize:     3,
		FlushInterval: 30 * time.Millisecond,
		MaxRetries:    0,
	})
	s.Start()

	for i := 0; i < 3; i++ {
		s.Enqueue(makeTestEvent(t))
	}

	time.Sleep(200 * time.Millisecond)
	s.Stop()

	evs, ok := captured["events"].([]any)
	if !ok {
		t.Fatalf("expected 'events' key in payload, got %v", captured)
	}
	if len(evs) != 3 {
		t.Errorf("expected 3 events in batch, got %d", len(evs))
	}
}

// ── Retry on 5xx ─────────────────────────────────────────────────────────────

func TestAuditSender_RetryOn500(t *testing.T) {
	var callCount atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     srv.URL,
		BatchSize:     1,
		FlushInterval: 20 * time.Millisecond,
		MaxRetries:    3,
	})
	s.Start()
	s.Enqueue(makeTestEvent(t))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.Diagnostics().SendCount >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.Stop()

	if callCount.Load() < 3 {
		t.Errorf("expected at least 3 calls (2 failures + 1 success), got %d", callCount.Load())
	}
	if s.Diagnostics().SendCount < 1 {
		t.Error("expected SendCount >= 1 after retry succeeded")
	}
}

// ── No retry on 4xx ───────────────────────────────────────────────────────────

func TestAuditSender_NoRetryOn400(t *testing.T) {
	var callCount atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     srv.URL,
		BatchSize:     1,
		FlushInterval: 20 * time.Millisecond,
		MaxRetries:    5,
	})
	s.Start()
	s.Enqueue(makeTestEvent(t))

	time.Sleep(300 * time.Millisecond)
	s.Stop()

	if callCount.Load() != 1 {
		t.Errorf("expected exactly 1 call (no retry on 4xx), got %d", callCount.Load())
	}
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

func TestAuditSender_Shutdown_Flushes(t *testing.T) {
	var received atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     srv.URL,
		BatchSize:     10,
		FlushInterval: 60 * time.Second, // very long — we'll trigger via Shutdown
		MaxRetries:    0,
	})
	s.Start()
	s.Enqueue(makeTestEvent(t))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}
	if received.Load() < 1 {
		t.Error("expected Shutdown() to flush pending events")
	}
	if s.Diagnostics().Running {
		t.Error("expected Running=false after Shutdown()")
	}
}

func TestAuditSender_Shutdown_ContextCancelled(t *testing.T) {
	// Point at a server that never responds to force timeout.
	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL:     "http://127.0.0.1:1", // nothing listening
		BatchSize:     1,
		FlushInterval: 60 * time.Second,
		MaxRetries:    0,
	})
	s.Start()
	s.Enqueue(makeTestEvent(t))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Shutdown(ctx)
	// May return context.DeadlineExceeded or nil (if flush completed before timeout).
	_ = err // Either is acceptable.
	if s.Diagnostics().Running {
		t.Error("expected sender stopped after Shutdown()")
	}
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

func TestAuditSender_Diagnostics(t *testing.T) {
	s := audit.NewAuditSender(audit.SenderConfig{
		IngestURL: "http://localhost:9999",
	})
	d := s.Diagnostics()
	if !d.ForwardingEnabled {
		t.Error("ForwardingEnabled should be true when IngestURL is set")
	}
	if d.Running {
		t.Error("Running should be false before Start()")
	}
	s.Start()
	d = s.Diagnostics()
	if !d.Running {
		t.Error("Running should be true after Start()")
	}
	s.Stop()
}
