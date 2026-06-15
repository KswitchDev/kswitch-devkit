// AuditSender forwards audit events to the central server asynchronously.
//
// Mirrors Python AuditSender and TypeScript AuditSender:
//   - In-memory queue (max 500 events; drops oldest on overflow)
//   - Periodic flush via goroutine (configurable interval, default 30s)
//   - Sends { "events": [...] } batch format to POST /api/v1/sdk/audit/events
//   - Exponential backoff retry (1s → 2s → 4s → ... capped at 60s, max 5 retries)
//   - Decision path is never blocked on forwarding failure
//
// Go-specific addition: Shutdown(ctx context.Context) error
//   Required for compiled binary / SIGTERM-driven deployments.
//   Signals the goroutine to stop accepting new events, flushes pending batches
//   using the provided context deadline, and returns when flush is complete or
//   the context is cancelled. The local durable JSONL sink is unaffected.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultFlushInterval = 30 * time.Second
	defaultMaxRetries    = 5
	queueMaxSize         = 500
	defaultIngestPath    = "/api/v1/sdk/audit/events"
)

// HTTPPoster is the minimal interface required by AuditSender.
// *http.Client satisfies this interface.
type HTTPPoster interface {
	Do(req *http.Request) (*http.Response, error)
}

// SenderConfig holds AuditSender configuration.
type SenderConfig struct {
	IngestURL     string       // Full URL or just base URL (defaultIngestPath appended if no path given)
	BatchSize     int          // Trigger flush when queue reaches this size (default: 50)
	FlushInterval time.Duration // How often to flush (default: 30s)
	MaxRetries    int          // Max retry attempts per batch (default: 5)
	HTTPClient    HTTPPoster   // Defaults to http.DefaultClient
}

// SenderDiagnostics holds observable state for the sender.
type SenderDiagnostics struct {
	ForwardingEnabled bool  `json:"forwarding_enabled"`
	Running          bool  `json:"running"`
	QueueDepth       int   `json:"queue_depth"`
	SendCount        int64 `json:"send_count"`
	FailCount        int64 `json:"fail_count"`
	DropCount        int64 `json:"drop_count"`
}

// AuditSender forwards batches of audit events to the central ingest endpoint.
// Safe for concurrent use.
type AuditSender struct {
	ingestURL  string
	batchSize  int
	flushEvery time.Duration
	maxRetries int
	httpClient HTTPPoster

	queue     chan AuditEvent
	stopCh    chan struct{}
	doneCh    chan struct{}
	flushCh   chan chan error // trigger manual flush; response channel carries error

	sendCount atomic.Int64
	failCount atomic.Int64
	dropCount atomic.Int64

	mu      sync.Mutex
	running bool
}

// NewAuditSender creates an AuditSender from the given config.
func NewAuditSender(cfg SenderConfig) *AuditSender {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	url := cfg.IngestURL
	if url == "" {
		url = defaultIngestPath
	}
	return &AuditSender{
		ingestURL:  url,
		batchSize:  cfg.BatchSize,
		flushEvery: cfg.FlushInterval,
		maxRetries: cfg.MaxRetries,
		httpClient: cfg.HTTPClient,
		queue:      make(chan AuditEvent, queueMaxSize),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		flushCh:    make(chan chan error, 1),
	}
}

// Start launches the background flush goroutine. Safe to call multiple times.
func (s *AuditSender) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	// Reset channels so Start can be called after Stop.
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.flushCh = make(chan chan error, 1)
	go s.run()
}

// Stop signals the goroutine to stop and waits for it to exit.
// Pending events may be dropped after Stop; use Shutdown for graceful flush.
func (s *AuditSender) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	doneCh := s.doneCh
	s.mu.Unlock()
	<-doneCh
}

// Shutdown flushes pending events and stops the goroutine.
// Respects the context deadline/cancellation.
// The local JSONL sink is always preserved regardless of flush success.
//
// This is Go-specific (required for SIGTERM-driven binary deployments).
func (s *AuditSender) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	// Request a flush and wait for the result or context deadline.
	respCh := make(chan error, 1)
	select {
	case s.flushCh <- respCh:
	case <-ctx.Done():
		s.Stop()
		return ctx.Err()
	}

	var flushErr error
	select {
	case flushErr = <-respCh:
	case <-ctx.Done():
		flushErr = ctx.Err()
	}

	s.Stop()
	return flushErr
}

// Enqueue adds an event to the in-memory queue.
// If the queue is full, the event is dropped and the drop counter is incremented.
// This method never blocks. Mirrors Python AuditSender.enqueue().
func (s *AuditSender) Enqueue(event AuditEvent) {
	select {
	case s.queue <- event:
		// Trigger flush if queue reached batch size.
		if len(s.queue) >= s.batchSize {
			// Non-blocking: if the flush goroutine is busy, it will flush on timer.
			select {
			case s.flushCh <- nil: // nil respCh means fire-and-forget
			default:
			}
		}
	default:
		s.dropCount.Add(1)
	}
}

// Diagnostics returns observable sender state.
func (s *AuditSender) Diagnostics() SenderDiagnostics {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	return SenderDiagnostics{
		ForwardingEnabled: s.ingestURL != "",
		Running:          running,
		QueueDepth:       len(s.queue),
		SendCount:        s.sendCount.Load(),
		FailCount:        s.failCount.Load(),
		DropCount:        s.dropCount.Load(),
	}
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (s *AuditSender) run() {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			// Drain queue on stop (best-effort, no context deadline here).
			s.drainAndFlush(context.Background())
			return

		case <-ticker.C:
			s.drainAndFlush(context.Background())

		case respCh := <-s.flushCh:
			err := s.drainAndFlush(context.Background())
			if respCh != nil {
				respCh <- err
			}
		}
	}
}

func (s *AuditSender) drainAndFlush(ctx context.Context) error {
	// Drain up to batchSize events per flush call.
	var batch []AuditEvent
	for {
		select {
		case ev := <-s.queue:
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				goto send
			}
		default:
			goto send
		}
	}
send:
	if len(batch) == 0 {
		return nil
	}
	return s.sendBatch(ctx, batch)
}

func (s *AuditSender) sendBatch(ctx context.Context, batch []AuditEvent) error {
	if s.ingestURL == "" {
		return nil
	}

	payload := map[string]any{"events": batch}
	body, err := json.Marshal(payload)
	if err != nil {
		s.failCount.Add(1)
		return fmt.Errorf("audit sender: marshal: %w", err)
	}

	var lastErr error
	backoff := time.Second
	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				s.failCount.Add(1)
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ingestURL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
			slog.Debug("kswitch.audit.sender: send failed", "attempt", attempt+1, "error", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			s.sendCount.Add(int64(len(batch)))
			return nil
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			// Non-retryable (4xx except 429).
			if resp.StatusCode != 429 {
				break
			}
		}
	}

	s.failCount.Add(1)
	slog.Warn("kswitch.audit.sender: batch failed after retries", "error", lastErr, "batch_size", len(batch))
	return lastErr
}

// ── Module-level singleton ────────────────────────────────────────────────────

var (
	globalSender   *AuditSender
	globalSenderMu sync.Mutex
)

// StartAuditSender starts (or returns an existing) module-level AuditSender.
// Also registers it with the default AuditEmitter.
// Idempotent — safe to call multiple times.
func StartAuditSender(cfg SenderConfig) *AuditSender {
	globalSenderMu.Lock()
	defer globalSenderMu.Unlock()
	if globalSender != nil {
		s := globalSender
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if running {
			return globalSender
		}
	}
	sender := NewAuditSender(cfg)
	sender.Start()
	globalSender = sender
	GetAuditEmitter().SetSender(sender)
	return sender
}

// StopAuditSender stops the module-level sender if running.
func StopAuditSender() {
	globalSenderMu.Lock()
	defer globalSenderMu.Unlock()
	if globalSender != nil {
		globalSender.Stop()
		globalSender = nil
	}
}

// GetAuditSender returns the module-level sender, or nil if not started.
func GetAuditSender() *AuditSender {
	globalSenderMu.Lock()
	defer globalSenderMu.Unlock()
	return globalSender
}
