// Package audit provides local audit event emission for the Go SDK.
//
// Audit file: {stateDir}/audit/events.jsonl
//
// Event schema matches Python AuditEmitter and TypeScript AuditEmitter exactly:
//   - event_id, event_type, event_version
//   - agent_id, mcp_server_id, tool_name, action
//   - decision_id, allowed, outcome, reason, decision_path
//   - obligations, output_policy_mode
//   - bundle_version, context_pack_id, risk_tier, runtime_mode ("LOCAL_RUNTIME_GO")
//   - elapsed_ms, evaluated_at
//
// Write order (same as Python/TypeScript):
//   Step 1: JSONL write to local file — always, never skipped.
//   Step 2: Enqueue to AuditSender for central forwarding — optional, non-blocking.
//   A failure in Step 2 never affects Step 1 or the decision path.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	auditFileName = "events.jsonl"
	maxFileSize   = 50 * 1024 * 1024 // 50 MB — rotate after this
	runtimeMode   = "LOCAL_RUNTIME_GO"
)

// AuditEvent is the structured event emitted for every governance decision.
type AuditEvent struct {
	EventID      string   `json:"event_id"`
	EventType    string   `json:"event_type"`
	EventVersion string   `json:"event_version"`
	AgentID      string   `json:"agent_id"`
	MCPServerID  string   `json:"mcp_server_id"`
	ToolName     string   `json:"tool_name"`
	Action       string   `json:"action"`
	DecisionID   string   `json:"decision_id"`
	Allowed      bool     `json:"allowed"`
	Outcome      string   `json:"outcome"`
	Reason       string   `json:"reason"`
	DecisionPath []string `json:"decision_path"`
	Obligations  []any    `json:"obligations"`
	OutputPolicyMode string `json:"output_policy_mode"`
	BundleVersion  string `json:"bundle_version"`
	ContextPackID  string `json:"context_pack_id"`
	RiskTier       string `json:"risk_tier"`
	RuntimeMode    string `json:"runtime_mode"`
	ElapsedMs      float64 `json:"elapsed_ms"`
	EvaluatedAt    string  `json:"evaluated_at"`
}

// BuildAuditEvent constructs an AuditEvent from individual fields.
// Mirrors Python _build_event() and TypeScript buildAuditEvent().
func BuildAuditEvent(
	eventType, agentID, mcpServerID, toolName string,
	allowed bool,
	reason, decisionID string,
	decisionPath []string,
	obligations []any,
	outputPolicyMode string,
	bundleVersion, contextPackID, riskTier string,
	elapsedMs float64,
) AuditEvent {
	outcome := "deny"
	if allowed {
		outcome = "allow"
	}
	if decisionID == "" {
		decisionID = uuid.New().String()
	}
	if decisionPath == nil {
		decisionPath = []string{}
	}
	if obligations == nil {
		obligations = []any{}
	}
	return AuditEvent{
		EventID:          uuid.New().String(),
		EventType:        eventType,
		EventVersion:     "1.0",
		AgentID:          agentID,
		MCPServerID:      mcpServerID,
		ToolName:         toolName,
		Action:           "mcp_call",
		DecisionID:       decisionID,
		Allowed:          allowed,
		Outcome:          outcome,
		Reason:           reason,
		DecisionPath:     decisionPath,
		Obligations:      obligations,
		OutputPolicyMode: outputPolicyMode,
		BundleVersion:    bundleVersion,
		ContextPackID:    contextPackID,
		RiskTier:         riskTier,
		RuntimeMode:      runtimeMode,
		ElapsedMs:        elapsedMs,
		EvaluatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

// Sender is the interface the AuditEmitter uses to forward events centrally.
type Sender interface {
	Enqueue(event AuditEvent)
}

// AuditEmitter writes governance decision events to a local JSONL file and
// optionally forwards them to the central server. Safe for concurrent use.
type AuditEmitter struct {
	dir    string
	mu     sync.Mutex
	sender Sender // optional — nil if central forwarding not configured
}

// NewAuditEmitter creates an emitter writing to dir.
// If dir is empty, DefaultAuditDir() is used.
func NewAuditEmitter(dir string) *AuditEmitter {
	if dir == "" {
		dir = DefaultAuditDir()
	}
	return &AuditEmitter{dir: dir}
}

// DefaultAuditDir returns the default audit log directory.
// Resolution order:
//  1. $KSWITCH_STATE_DIR/audit
//  2. $HOME/.kswitch/audit
func DefaultAuditDir() string {
	if s := os.Getenv("KSWITCH_STATE_DIR"); s != "" {
		return filepath.Join(s, "audit")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kswitch", "audit")
}

func (e *AuditEmitter) filePath() string {
	return filepath.Join(e.dir, auditFileName)
}

// SetSender registers a central audit sender.
// Called by the runtime when central forwarding is configured.
func (e *AuditEmitter) SetSender(s Sender) {
	e.mu.Lock()
	e.sender = s
	e.mu.Unlock()
}

// Emit writes one event to the local JSONL file and optionally forwards it centrally.
// Never returns an error — audit failures must never block the decision path.
func (e *AuditEmitter) Emit(event AuditEvent) {
	// ── Step 1: JSONL write (always, never skipped) ──────────────────────────
	func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Debug("kswitch.audit: JSONL write panic", "error", r)
			}
		}()
		if e.dir == "" {
			return
		}
		if err := os.MkdirAll(e.dir, 0o755); err != nil {
			return
		}
		path := e.filePath()

		// Rotate if too large.
		if info, err := os.Stat(path); err == nil && info.Size() > maxFileSize {
			rotated := fmt.Sprintf("%s.%d", path, time.Now().Unix())
			_ = os.Rename(path, rotated)
		}

		line, err := json.Marshal(event)
		if err != nil {
			return
		}
		e.mu.Lock()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			e.mu.Unlock()
			return
		}
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
		e.mu.Unlock()
	}()

	// ── Step 2: Central forwarding (best-effort, never blocks) ───────────────
	func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Debug("kswitch.audit: sender enqueue panic", "error", r)
			}
		}()
		e.mu.Lock()
		sender := e.sender
		e.mu.Unlock()
		if sender == nil {
			return
		}
		sender.Enqueue(event)
	}()
}

// ── Module-level singleton ────────────────────────────────────────────────────

var (
	defaultEmitter     *AuditEmitter
	defaultEmitterOnce sync.Once
)

func getDefaultEmitter() *AuditEmitter {
	defaultEmitterOnce.Do(func() {
		defaultEmitter = NewAuditEmitter("")
	})
	return defaultEmitter
}

// EmitDecisionEvent emits a governance decision event using the default emitter.
func EmitDecisionEvent(
	eventType, agentID, mcpServerID, toolName string,
	allowed bool,
	reason, decisionID string,
	decisionPath []string,
	obligations []any,
	outputPolicyMode string,
	bundleVersion, contextPackID, riskTier string,
	elapsedMs float64,
) {
	event := BuildAuditEvent(
		eventType, agentID, mcpServerID, toolName,
		allowed, reason, decisionID,
		decisionPath, obligations, outputPolicyMode,
		bundleVersion, contextPackID, riskTier, elapsedMs,
	)
	getDefaultEmitter().Emit(event)
}

// GetAuditEmitter returns the module-level default emitter.
func GetAuditEmitter() *AuditEmitter {
	return getDefaultEmitter()
}

// SetAuditEmitter replaces the module-level default emitter (for testing).
func SetAuditEmitter(em *AuditEmitter) {
	defaultEmitterOnce = sync.Once{}
	defaultEmitterOnce.Do(func() { defaultEmitter = em })
}
