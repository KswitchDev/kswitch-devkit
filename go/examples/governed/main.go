// Example: Governed MCP tool invocation via kswitch.Interceptor.
//
// This is the SUPPORTED production pattern for gating MCP tool calls through
// KSwitch governance policies. It uses the governed invocation path:
//
//	interceptor.CheckAndInvoke() → local PDP → enforce → tool → output filter → audit
//
// The raw path (client.Enforcement.EnforceMCPCall()) is a low-level API that
// does NOT provide local-PDP evaluation, bypass prevention, output filtering,
// or obligation blocking. Use interceptor.CheckAndInvoke() in production.
//
// Usage:
//
//	go run examples/governed/main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch"
	"github.com/KswitchDev/kswitch-devkit/go/kswitch/localpdp"
)

// ── Simulated MCP tool implementations ────────────────────────────────────────

func readRecords(table string, limit int) (map[string]any, error) {
	records := make([]map[string]any, limit)
	for i := range records {
		records[i] = map[string]any{"id": i, "table": table}
	}
	return map[string]any{"records": records}, nil
}

func deleteRecords(table string, ids []int) (map[string]any, error) {
	return map[string]any{"deleted": len(ids), "table": table}, nil
}

// ── Governed invocation (supported path) ──────────────────────────────────────

func main() {
	client := kswitch.NewClient(
		kswitch.WithBaseURL(envOr("KSWITCH_BASE_URL", "http://localhost:5001")),
		kswitch.WithKeycloak(
			envOr("KEYCLOAK_ENDPOINT", "http://localhost:8080"),
			envOr("KEYCLOAK_REALM", "kswitch"),
			os.Getenv("FLEET_CLIENT_ID"),
			os.Getenv("FLEET_CLIENT_SECRET"),
		),
	)

	// Create the governed interceptor with local PDP for in-process enforcement.
	// The interceptor is the primary governed invocation surface for Go.
	evaluator := localpdp.NewLocalPDPEvaluator()
	interceptor := kswitch.NewInterceptor(client, kswitch.WithLocalPDP(evaluator))

	agentID := "agent:fraud-detector@bank.internal"
	mcpServerID := "mcp:database@bank.internal"

	fmt.Println("Checking tool call authorizations via governed interceptor")
	fmt.Println()

	// ── Governed invocations ───────────────────────────────────────────────────
	// CheckAndInvoke() is the ONLY supported production path.
	// Local PDP evaluate → enforce → output filter → audit is automatic.

	type call struct {
		toolName string
		toolFn   func() (any, error)
	}

	calls := []call{
		{
			toolName: "read_records",
			toolFn:   func() (any, error) { return readRecords("customers", 10) },
		},
		{
			toolName: "delete_records",
			toolFn:   func() (any, error) { return deleteRecords("customers", []int{1, 2, 3}) },
		},
	}

	ctx := context.Background()
	for _, c := range calls {
		fmt.Printf("Invoking %s...\n", c.toolName)
		result, err := interceptor.CheckAndInvoke(ctx, &kswitch.CheckAndInvokeRequest{
			AgentID:     agentID,
			MCPServerID: mcpServerID,
			ToolName:    c.toolName,
			ToolFn:      c.toolFn,
		})
		if err != nil {
			var enfErr *kswitch.EnforcementError
			var oblErr *kswitch.ObligationError
			var outErr *kswitch.OutputDeniedError
			switch {
			case errors.As(err, &enfErr):
				fmt.Printf("  DENIED — reason: %s\n", enfErr.Reason)
			case errors.As(err, &oblErr):
				fmt.Printf("  BLOCKED (obligation) — reason: %s\n", oblErr.Reason)
			case errors.As(err, &outErr):
				fmt.Printf("  OUTPUT DENIED — policy prevents export of this result\n")
			default:
				log.Fatalf("unexpected error: %v", err)
			}
		} else {
			fmt.Printf("  ALLOWED — result: %v\n", result)
		}
		fmt.Println()
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
