package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KswitchDev/kswitch-sdks/go/kswitch/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeTmpDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kswitch-audit-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open JSONL: %v", err)
	}
	defer f.Close()
	var events []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("JSONL parse error: %v", err)
		}
		events = append(events, ev)
	}
	return events
}

// ── BuildAuditEvent ───────────────────────────────────────────────────────────

func TestBuildAuditEvent_Fields(t *testing.T) {
	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:payments@bank.internal",
		"initiate_payment",
		true,
		"allowed",
		"dec-123",
		[]string{"local_sdk", "cedar_allowed"},
		nil,
		"allow_raw",
		"bundle:v5",
		"cp:v2",
		"medium",
		4.2,
	)

	if ev.EventID == "" {
		t.Error("EventID must not be empty")
	}
	if ev.EventType != "mcp_call_enforcement" {
		t.Errorf("EventType = %q, want mcp_call_enforcement", ev.EventType)
	}
	if ev.EventVersion != "1.0" {
		t.Errorf("EventVersion = %q, want 1.0", ev.EventVersion)
	}
	if ev.AgentID != "agent:test@bank.internal" {
		t.Errorf("AgentID = %q", ev.AgentID)
	}
	if ev.ToolName != "initiate_payment" {
		t.Errorf("ToolName = %q", ev.ToolName)
	}
	if !ev.Allowed {
		t.Error("Allowed should be true")
	}
	if ev.Outcome != "allow" {
		t.Errorf("Outcome = %q, want allow", ev.Outcome)
	}
	if ev.DecisionID != "dec-123" {
		t.Errorf("DecisionID = %q, want dec-123", ev.DecisionID)
	}
	if ev.RuntimeMode != "LOCAL_RUNTIME_GO" {
		t.Errorf("RuntimeMode = %q, want LOCAL_RUNTIME_GO", ev.RuntimeMode)
	}
	if ev.ElapsedMs != 4.2 {
		t.Errorf("ElapsedMs = %v, want 4.2", ev.ElapsedMs)
	}
	if ev.EvaluatedAt == "" {
		t.Error("EvaluatedAt must not be empty")
	}
}

func TestBuildAuditEvent_DenyOutcome(t *testing.T) {
	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"tool",
		false,
		"revoked",
		"",
		nil, nil, "allow_raw",
		"bundle:v1", "cp:v1", "high", 1.0,
	)
	if ev.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny", ev.Outcome)
	}
	if ev.DecisionID == "" {
		t.Error("DecisionID should be auto-generated when empty")
	}
	if ev.DecisionPath == nil {
		t.Error("DecisionPath should never be nil")
	}
	if ev.Obligations == nil {
		t.Error("Obligations should never be nil")
	}
}

// ── AuditEmitter.Emit ─────────────────────────────────────────────────────────

func TestEmit_WritesJSONL(t *testing.T) {
	tmp := makeTmpDir(t)
	em := audit.NewAuditEmitter(tmp)

	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"read_data",
		true,
		"allowed",
		"",
		[]string{"local_sdk"},
		nil,
		"allow_raw",
		"bundle:v1", "cp:v1", "low", 0.5,
	)
	em.Emit(ev)

	events := readJSONL(t, filepath.Join(tmp, "events.jsonl"))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["event_type"] != "mcp_call_enforcement" {
		t.Errorf("event_type = %v", events[0]["event_type"])
	}
	if events[0]["runtime_mode"] != "LOCAL_RUNTIME_GO" {
		t.Errorf("runtime_mode = %v", events[0]["runtime_mode"])
	}
}

func TestEmit_MultipleEvents(t *testing.T) {
	tmp := makeTmpDir(t)
	em := audit.NewAuditEmitter(tmp)

	for i := 0; i < 5; i++ {
		ev := audit.BuildAuditEvent(
			"mcp_call_enforcement",
			"agent:test@bank.internal",
			"mcp:server@bank.internal",
			"tool",
			true, "allowed", "",
			nil, nil, "allow_raw",
			"bundle:v1", "cp:v1", "low", 1.0,
		)
		em.Emit(ev)
	}

	events := readJSONL(t, filepath.Join(tmp, "events.jsonl"))
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestEmit_NoDir_DoesNotPanic(t *testing.T) {
	// An emitter with empty dir should not panic.
	em := audit.NewAuditEmitter("/nonexistent/path/that/cannot/be/created/xyz123")
	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"tool",
		true, "allowed", "",
		nil, nil, "allow_raw",
		"bundle:v1", "cp:v1", "low", 1.0,
	)
	// Must not panic.
	em.Emit(ev)
}

func TestEmit_NilSender_DoesNotPanic(t *testing.T) {
	// Emitter with no sender configured should still work.
	tmp := makeTmpDir(t)
	em := audit.NewAuditEmitter(tmp)
	// No SetSender — sender is nil.
	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"tool",
		false, "denied", "",
		nil, nil, "allow_raw",
		"bundle:v1", "cp:v1", "medium", 2.0,
	)
	em.Emit(ev) // Must not panic.
}

// ── SetSender / forwarding ────────────────────────────────────────────────────

type captureSender struct {
	events []audit.AuditEvent
}

func (s *captureSender) Enqueue(ev audit.AuditEvent) {
	s.events = append(s.events, ev)
}

func TestEmit_ForwardsToSender(t *testing.T) {
	tmp := makeTmpDir(t)
	em := audit.NewAuditEmitter(tmp)
	sender := &captureSender{}
	em.SetSender(sender)

	ev := audit.BuildAuditEvent(
		"mcp_call_enforcement",
		"agent:test@bank.internal",
		"mcp:server@bank.internal",
		"tool",
		true, "allowed", "",
		nil, nil, "allow_raw",
		"bundle:v1", "cp:v1", "low", 1.0,
	)
	em.Emit(ev)

	if len(sender.events) != 1 {
		t.Errorf("expected 1 forwarded event, got %d", len(sender.events))
	}
	if sender.events[0].EventID != ev.EventID {
		t.Errorf("forwarded event ID mismatch: %q vs %q", sender.events[0].EventID, ev.EventID)
	}
}

// ── DefaultAuditDir ───────────────────────────────────────────────────────────

func TestDefaultAuditDir_EnvVar(t *testing.T) {
	tmp := makeTmpDir(t)
	t.Setenv("KSWITCH_STATE_DIR", tmp)
	got := audit.DefaultAuditDir()
	want := filepath.Join(tmp, "audit")
	if got != want {
		t.Errorf("DefaultAuditDir() = %q, want %q", got, want)
	}
}
