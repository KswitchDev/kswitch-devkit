// Example: Evaluate toxic combos and policy authorization.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/KswitchDev/kswitch-sdks/go/kswitch"
)

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

	ctx := context.Background()
	agentID := envOr("AGENT_ID", "agent-001")

	// Evaluate toxic combos for a specific agent.
	violations, err := client.Compliance.EvaluateToxicCombos(ctx, agentID)
	if err != nil {
		log.Fatalf("toxic combo eval failed: %v", err)
	}
	if len(violations) == 0 {
		fmt.Printf("Agent %s: no toxic combo violations\n", agentID)
	} else {
		fmt.Printf("Agent %s: %d violation(s) found\n", agentID, len(violations))
		for _, v := range violations {
			fmt.Printf("  - [%s] %s: %s\n", v.Severity, v.RuleName, v.Details)
		}
	}

	// Boundary analysis.
	ba, err := client.Compliance.GetBoundaryAnalysis(ctx, agentID)
	if err != nil {
		log.Fatalf("boundary analysis failed: %v", err)
	}
	fmt.Printf("Boundary crossings: %d\n", ba.TotalCount)

	// AuthZen policy evaluation.
	decision, err := client.AuthZen.Evaluate(ctx, &kswitch.AuthZenRequest{
		Subject: kswitch.AuthZenEntity{
			Type: "agent",
			ID:   agentID,
		},
		Action: kswitch.AuthZenEntity{
			Type: "action",
			ID:   "invoke_tool",
		},
		Resource: kswitch.AuthZenEntity{
			Type: "mcp_tool",
			ID:   "database_query",
		},
	})
	if err != nil {
		log.Fatalf("authzen eval failed: %v", err)
	}
	fmt.Printf("AuthZen decision: %v\n", decision.Decision)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
