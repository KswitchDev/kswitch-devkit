// Package kswitch — KSwitch SDK interceptor (PR-05/PR-06).
//
// Interceptor wraps enforcement + pre-invoke obligation blocking + tool
// invocation + output filtering + obligation reporting into a single
// CheckAndInvoke call. Callers must not bypass this path.
//
// LOCAL RUNTIME PATH (Go Local Runtime):
//   If a LocalPDPEvaluator is registered via WithLocalPDP(), CheckAndInvoke()
//   attempts a local decision first. Only "conditional" outcomes escalate to
//   the server. This eliminates the Flask network call for normal-path ALLOW/DENY.
//
//   Decision flow:
//     1. Local PDP evaluate (no network)
//        a. outcome == "allow" → execute + output guard + audit (no Flask call)
//        b. outcome == "deny"  → EnforcementError (no Flask call)
//        c. outcome == "conditional" → fall through to server enforcement
//     2. Server enforcement (only for conditional)
//        → normal server path unchanged
//
// Bypass prevention contract (unchanged):
//   - Enforcement DENY → EnforcementError (tool never runs)
//   - credential_risk critical/high → ObligationError (tool never runs)
//   - anomaly_detection critical    → ObligationError (tool never runs)
//   - output_policy mode=deny_export → OutputDeniedError (output suppressed)
//   - mask_fields / truncate applied to returned output

package kswitch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch/audit"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/localpdp"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/tokens"
)

// ── Execution token propagation ───────────────────────────────────────────────

// GetActiveExecutionToken returns the execution token stored in ctx by the
// interceptor, or ("", false) if no token is present.
//
// Downstream HTTP clients can call this to attach the token as a Bearer header
// without it being passed explicitly through every layer.
func GetActiveExecutionToken(ctx context.Context) (string, bool) {
	return tokens.FromContext(ctx)
}

// tryIssueToken attempts to issue an execution token for an ALLOW decision.
// Never panics. Returns ("", nil) if tokens are disabled or the key is not set.
func tryIssueToken(decision *EnforcementDecision, agentID, mcpServerID, toolName string, ctx map[string]any) (string, error) {
	enabled := strings.ToLower(os.Getenv("KSWITCH_EXECUTION_TOKENS_ENABLED")) == "true"
	if !enabled {
		return "", nil
	}
	issuer, err := tokens.NewIssuerFromEnv()
	if err != nil {
		return "", nil // key not configured — non-fatal
	}
	dec := tokens.Decision{}
	if decision != nil {
		dec.RiskTier = decision.RiskTier
		dec.BundleVersion = decision.BundleVersion
		dec.ContextPackID = decision.ContextPackID
		dec.ID = decision.EnforcementID
	}
	token, err := issuer.Issue(dec, tokens.IssueOptions{
		AgentID:     agentID,
		MCPServerID: mcpServerID,
		ToolName:    toolName,
		Context:     ctx,
	})
	if err != nil {
		return "", nil // best-effort
	}
	return token, nil
}

// ---------------------------------------------------------------------------
// Interceptor errors
// ---------------------------------------------------------------------------

// EnforcementError is returned when the enforcement decision is DENY.
// The tool function is never called when this error is returned.
type EnforcementError struct {
	Reason   string
	Decision *EnforcementDecision
}

func (e *EnforcementError) Error() string {
	return fmt.Sprintf("MCP call denied: %s", e.Reason)
}

// ObligationError is returned when a pre-invoke obligation mandates blocking.
//
// Triggered by:
//   - credential_risk at level critical or high
//   - anomaly_detection at level critical
type ObligationError struct {
	Reason     string
	Obligation *EnforcementObligation
	Decision   *EnforcementDecision
}

func (e *ObligationError) Error() string {
	return fmt.Sprintf("pre-invoke obligation blocked call: %s", e.Reason)
}

// OutputDeniedError is returned when output_policy.mode == "deny_export".
// The tool ran but its output must not be returned.
type OutputDeniedError struct {
	Message string
}

func (e *OutputDeniedError) Error() string { return e.Message }

// ---------------------------------------------------------------------------
// Interceptor options
// ---------------------------------------------------------------------------

// CheckAndInvokeRequest bundles the inputs for CheckAndInvoke.
type CheckAndInvokeRequest struct {
	AgentID     string
	MCPServerID string
	ToolName    string
	Context     map[string]any
	// ToolFn is the actual tool callable. Its return value must be JSON-serializable.
	ToolFn func() (any, error)
	// ToolFnCtx is like ToolFn but receives the enriched context containing the
	// execution token. If set, it takes precedence over ToolFn.
	// The execution token can be retrieved via tokens.FromContext(ctx) or
	// kswitch.GetActiveExecutionToken(ctx).
	ToolFnCtx func(context.Context) (any, error)
}

// ---------------------------------------------------------------------------
// Interceptor options
// ---------------------------------------------------------------------------

// InterceptorOption is a functional option for NewInterceptor.
type InterceptorOption func(*Interceptor)

// WithLocalPDP registers a LocalPDPEvaluator for local-first enforcement.
// When set, ALLOW/DENY decisions happen locally without a server call.
// Only "conditional" outcomes escalate to the server.
//
// Example:
//
//	evaluator := localpdp.NewLocalPDPEvaluator()
//	interceptor := kswitch.NewInterceptor(client, kswitch.WithLocalPDP(evaluator))
func WithLocalPDP(evaluator *localpdp.LocalPDPEvaluator) InterceptorOption {
	return func(i *Interceptor) {
		i.localPDP = evaluator
	}
}

// ---------------------------------------------------------------------------
// Interceptor
// ---------------------------------------------------------------------------

// Interceptor: enforce → block → invoke → filter → report.
//
//	// Server-only mode (original behaviour):
//	interceptor := kswitch.NewInterceptor(client)
//
//	// Local-first mode (Go local runtime):
//	evaluator := localpdp.NewLocalPDPEvaluator()
//	interceptor := kswitch.NewInterceptor(client, kswitch.WithLocalPDP(evaluator))
//
//	result, err := interceptor.CheckAndInvoke(ctx, &kswitch.CheckAndInvokeRequest{
//	    AgentID:     "agent:fraud-detector@bank.internal",
//	    MCPServerID: "mcp:payment-gateway@bank.internal",
//	    ToolName:    "initiate_payment",
//	    ToolFn:      func() (any, error) { return paymentTool.InitiatePayment(args) },
//	})
type Interceptor struct {
	client   *Client
	localPDP *localpdp.LocalPDPEvaluator // nil if not configured
}

// NewInterceptor creates an Interceptor wrapping the given Client.
// Accepts optional InterceptorOption values (e.g. WithLocalPDP).
// Backward-compatible: NewInterceptor(client) behaves identically to before.
func NewInterceptor(client *Client, opts ...InterceptorOption) *Interceptor {
	in := &Interceptor{client: client}
	for _, opt := range opts {
		opt(in)
	}
	return in
}

// CheckAndInvoke enforces, invokes, and filters in a single safe call.
//
// If a LocalPDPEvaluator is configured:
//   - "allow"/"deny" outcomes are resolved locally (no server call)
//   - "conditional" outcomes escalate to the server
//
// Returns the (possibly filtered) output of ToolFn.
// Returns an error if the call is denied, pre-invoke blocked, or output is denied.
func (in *Interceptor) CheckAndInvoke(ctx context.Context, req *CheckAndInvokeRequest) (any, error) {
	ctx, span := otelStartSpan(ctx, "kswitch.check_and_invoke")
	defer span.End()

	startMs := time.Now()

	// ── Local PDP path ─────────────────────────────────────────────────────
	if in.localPDP != nil {
		localDec := in.localPDP.Evaluate(ctx, req.AgentID, req.MCPServerID, req.ToolName, req.Context)

		if localDec.Outcome == "allow" || localDec.Outcome == "deny" {
			elapsedMs := float64(time.Since(startMs).Microseconds()) / 1000.0

			// Determine audit event type.
			eventType := "enforcement.deny"
			if localDec.Allowed {
				eventType = "enforcement.allow"
			} else if localDec.Reason == "agent_revoked" {
				eventType = "enforcement.revocation_deny"
			}

			// Convert obligations for audit.
			var obsAny []any
			for _, ob := range localDec.Obligations {
				obsAny = append(obsAny, ob)
			}

			outputPolicyMode := ""
			if localDec.OutputPolicy != nil {
				outputPolicyMode = localDec.OutputPolicy.Mode
			}

			audit.EmitDecisionEvent(
				eventType,
				req.AgentID, req.MCPServerID, req.ToolName,
				localDec.Allowed,
				localDec.Reason,
				localDec.EnforcementID,
				localDec.DecisionPath,
				obsAny,
				outputPolicyMode,
				localDec.BundleVersion,
				localDec.ContextPackID,
				localDec.RiskTier,
				elapsedMs,
			)

			if !localDec.Allowed {
				otelSetDeny(span, req.ToolName, localDec.Reason)
				serverDec := localDecisionToEnforcementDecision(localDec)
				return nil, &EnforcementError{Reason: localDec.Reason, Decision: serverDec}
			}

			// Local ALLOW: apply pre-invoke obligations + issue token + invoke + output policy.
			serverDec := localDecisionToEnforcementDecision(localDec)
			if err := enforcePreInvokeObligations(serverDec); err != nil {
				return nil, err
			}

			// Issue execution token (best-effort, never blocks invocation).
			execToken, _ := tryIssueToken(serverDec, req.AgentID, req.MCPServerID, req.ToolName, req.Context)
			if execToken != "" {
				ctx = tokens.WithToken(ctx, execToken)
			}

			otelSetAllow(span, req.ToolName, extractTokenJTI(execToken))

			rawOutput, err := invokeTool(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("tool invocation failed: %w", err)
			}

			var outputPolicy *OutputPolicy
			if localDec.OutputPolicy != nil {
				outputPolicy = &OutputPolicy{
					Mode:                   localDec.OutputPolicy.Mode,
					MaskingClassifications: localDec.OutputPolicy.MaskingClassifications,
				}
			}
			return applyOutputPolicy(rawOutput, outputPolicy)
		}

		// outcome == "conditional" — emit conditional event, fall through to server.
		elapsedMs := float64(time.Since(startMs).Microseconds()) / 1000.0
		audit.EmitDecisionEvent(
			"enforcement.conditional",
			req.AgentID, req.MCPServerID, req.ToolName,
			false,
			localDec.Reason,
			localDec.EnforcementID,
			localDec.DecisionPath,
			nil,
			"",
			localDec.BundleVersion,
			localDec.ContextPackID,
			localDec.RiskTier,
			elapsedMs,
		)
	}

	// ── Server enforcement path (unchanged) ───────────────────────────────────
	// kswitch: allow-unsafe — sdk-internal: server fallback after local PDP conditional/miss
	decision, err := in.client.Enforcement.EnforceMCPCall(ctx, &EnforcementRequest{
		AgentID:     req.AgentID,
		MCPServerID: req.MCPServerID,
		ToolName:    req.ToolName,
		Context:     req.Context,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement request failed: %w", err)
	}

	// ── Check allow/deny ───────────────────────────────────────────────
	if !decision.Allowed {
		reason := decision.Reason
		if reason == "" {
			reason = "denied"
		}
		otelSetDeny(span, req.ToolName, reason)
		return nil, &EnforcementError{Reason: reason, Decision: decision}
	}

	// ── Pre-invoke obligation check ────────────────────────────────────
	if err := enforcePreInvokeObligations(decision); err != nil {
		return nil, err
	}

	// ── Issue execution token (best-effort, never blocks invocation) ───
	execToken, _ := tryIssueToken(decision, req.AgentID, req.MCPServerID, req.ToolName, req.Context)
	if execToken != "" {
		ctx = tokens.WithToken(ctx, execToken)
	}

	otelSetAllow(span, req.ToolName, extractTokenJTI(execToken))

	// ── Invoke tool ────────────────────────────────────────────────────
	rawOutput, err := invokeTool(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("tool invocation failed: %w", err)
	}

	// ── Apply output policy ────────────────────────────────────────────
	filtered, err := applyOutputPolicy(rawOutput, decision.OutputPolicy)
	if err != nil {
		return nil, err
	}

	// ── Report obligations (best-effort) ───────────────────────────────
	go reportObligationsBestEffort(in.client, decision)

	return filtered, nil
}

// invokeTool calls ToolFnCtx(ctx) if set; otherwise falls back to ToolFn().
func invokeTool(ctx context.Context, req *CheckAndInvokeRequest) (any, error) {
	if req.ToolFnCtx != nil {
		return req.ToolFnCtx(ctx)
	}
	return req.ToolFn()
}

// localDecisionToEnforcementDecision converts a LocalDecision to an EnforcementDecision
// shape compatible with the rest of the interceptor pipeline.
func localDecisionToEnforcementDecision(d *localpdp.LocalDecision) *EnforcementDecision {
	obligations := make([]EnforcementObligation, 0, len(d.Obligations))
	for _, ob := range d.Obligations {
		obligations = append(obligations, EnforcementObligation{
			Type:           ob.Type,
			ObligationType: ob.ObligationType,
			Level:          ob.Level,
			Detail:         ob.Detail,
		})
	}
	dec := &EnforcementDecision{
		Allowed:               d.Allowed,
		Reason:                d.Reason,
		Outcome:               d.Outcome,
		DecisionPath:          d.DecisionPath,
		Obligations:           obligations,
		EvaluationMode:        d.EvaluationMode,
		BundleVersion:         d.BundleVersion,
		ContextPackID:         d.ContextPackID,
		ContextSnapshotID:     d.ContextSnapshotID,
		ContextSnapshotDigest: d.ContextSnapshotDigest,
		ContextSnapshot:       d.ContextSnapshot,
		DecisionExplanation:   d.DecisionExplanation,
		EnforcementID:         d.EnforcementID,
	}
	if d.OutputPolicy != nil {
		dec.OutputPolicy = &OutputPolicy{
			Mode:                   d.OutputPolicy.Mode,
			MaskingClassifications: d.OutputPolicy.MaskingClassifications,
		}
	}
	return dec
}

// ---------------------------------------------------------------------------
// Pre-invoke obligation enforcement
// ---------------------------------------------------------------------------

var credBlockLevels = map[string]bool{"critical": true, "high": true}

func enforcePreInvokeObligations(decision *EnforcementDecision) error {
	for i := range decision.Obligations {
		ob := &decision.Obligations[i]
		obType := strings.ToLower(firstNonEmpty(ob.ObligationType, ob.Type))
		level := strings.ToLower(ob.Level)

		if obType == "credential_risk" && credBlockLevels[level] {
			return &ObligationError{
				Reason:     fmt.Sprintf("credential_risk=%s blocks tool invocation", level),
				Obligation: ob,
				Decision:   decision,
			}
		}

		if obType == "anomaly_detection" && level == "critical" {
			return &ObligationError{
				Reason:     "anomaly_detection=critical blocks tool invocation",
				Obligation: ob,
				Decision:   decision,
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Output policy filter
// ---------------------------------------------------------------------------

// sensitiveFieldPatterns mirrors the server-side and Python SDK lists.
var sensitiveFieldPatterns = []string{
	"ssn", "social_security", "passport", "dob", "date_of_birth",
	"account_number", "card_number", "cvv", "routing_number",
	"tax_id", "ein", "phone", "email", "address", "zip", "postal",
	"salary", "income", "net_worth", "balance", "position", "trade",
	"ticker", "isin", "cusip", "mnpi", "insider",
	"password", "secret", "token", "api_key", "private_key", "credential",
	"health", "diagnosis", "medication", "prescription", "patient",
}

func applyOutputPolicy(output any, policy *OutputPolicy) (any, error) {
	if policy == nil {
		return output, nil
	}

	mode := strings.ToLower(policy.Mode)

	switch mode {
	case "allow_raw", "":
		return output, nil

	case "deny_export":
		msg := "Output export denied by governance policy"
		if len(policy.MaskingClassifications) > 0 {
			msg += fmt.Sprintf(" (classifications: %s)", strings.Join(policy.MaskingClassifications, ", "))
		}
		return nil, &OutputDeniedError{Message: msg}

	case "mask_fields":
		return maskOutput(output, policy.MaskingClassifications), nil

	case "truncate":
		maxBytes := 0
		if policy.MaxOutputBytes != nil {
			maxBytes = *policy.MaxOutputBytes
		}
		return truncateOutput(output, maxBytes), nil

	case "summarize_only":
		return map[string]any{
			"_output_mode": "summarize_only",
			"_note":        "Output summarization not yet implemented (PR-09)",
		}, nil

	case "require_release":
		return map[string]any{
			"_output_mode": "require_release",
			"_held":        true,
		}, nil

	default:
		return output, nil
	}
}

func maskOutput(output any, classifications []string) any {
	switch v := output.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for k, val := range v {
			result[k] = redactValue(k, val, classifications)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = maskOutput(item, classifications)
		}
		return result
	default:
		return output
	}
}

func redactValue(key string, value any, classifications []string) any {
	keyLower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))

	isSensitive := false
	for _, pat := range sensitiveFieldPatterns {
		if strings.Contains(keyLower, pat) {
			isSensitive = true
			break
		}
	}
	if !isSensitive {
		for _, cls := range classifications {
			if strings.Contains(keyLower, strings.ToLower(cls)) {
				isSensitive = true
				break
			}
		}
	}

	if isSensitive {
		label := "sensitive"
		if len(classifications) > 0 {
			label = strings.Join(classifications, ", ")
		}
		return fmt.Sprintf("[REDACTED: %s]", label)
	}

	switch v := value.(type) {
	case map[string]any, []any:
		return maskOutput(v, classifications)
	}
	return value
}

func truncateOutput(output any, maxBytes int) any {
	if maxBytes <= 0 {
		return output
	}

	if s, ok := output.(string); ok {
		raw := []byte(s)
		if len(raw) <= maxBytes {
			return s
		}
		// Truncate at valid UTF-8 boundary
		truncated := truncateUTF8(raw, maxBytes)
		return truncated + "…[TRUNCATED]"
	}

	var serialized string
	b, err := json.Marshal(output)
	if err != nil {
		serialized = fmt.Sprintf("%v", output)
	} else {
		serialized = string(b)
	}

	raw := []byte(serialized)
	if len(raw) <= maxBytes {
		return output
	}

	truncated := truncateUTF8(raw, maxBytes)
	return map[string]any{
		"_truncated": true,
		"_max_bytes": maxBytes,
		"_content":   truncated + "…",
	}
}

func truncateUTF8(b []byte, maxBytes int) string {
	if len(b) <= maxBytes {
		return string(b)
	}
	b = b[:maxBytes]
	// Walk back to valid rune boundary
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Obligation reporting
// ---------------------------------------------------------------------------

func reportObligationsBestEffort(client *Client, decision *EnforcementDecision) {
	if decision.EnforcementID == "" {
		return
	}

	obTypes := make([]string, 0, len(decision.Obligations))
	for _, ob := range decision.Obligations {
		obTypes = append(obTypes, firstNonEmpty(ob.ObligationType, ob.Type))
	}

	req := &ObligationReportRequest{
		EnforcementID:  decision.EnforcementID,
		ObligationsMet: obTypes,
	}

	// Use a background context; this goroutine outlives the request.
	ctx := context.Background()
	_, _ = client.Enforcement.ReportObligations(ctx, req) //nolint:errcheck
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// extractTokenJTI extracts the JTI claim from a JWT execution token. Never panics.
func extractTokenJTI(token string) string {
	if token == "" {
		return ""
	}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if jti, ok := claims["jti"].(string); ok {
		return jti
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
