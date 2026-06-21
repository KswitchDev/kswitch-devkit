// Example: Kill switch operations.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/KswitchDev/kswitch-devkit/go/kswitch"
)

func main() {
	client := kswitch.NewClient(
		kswitch.WithBaseURL(envOr("KSWITCH_BASE_URL", "http://localhost:5001")),
		kswitch.WithToken(os.Getenv("KSWITCH_AUTH_TOKEN")),
	)

	ctx := context.Background()

	// List kill switch history.
	history, err := client.KillSwitch.GetHistory(ctx)
	if err != nil {
		log.Fatalf("get history failed: %v", err)
	}
	fmt.Printf("Kill switch activations: %d\n", len(history))
	for _, r := range history {
		fmt.Printf("  - %s: scope=%s reason=%q\n", r.ID, r.Scope, r.Reason)
	}

	// List violations.
	violations, err := client.KillSwitch.GetViolations(ctx)
	if err != nil {
		log.Fatalf("get violations failed: %v", err)
	}
	fmt.Printf("Kill switch violations: %d\n", len(violations))

	// Targeted kill (uncomment to execute).
	// result, err := client.KillSwitch.TargetedKill(ctx, &kswitch.TargetedKillRequest{
	// 	AgentIDs: []string{"agent-compromised-001"},
	// 	Reason:   "Security incident: unauthorized data access detected",
	// })
	// if err != nil {
	// 	log.Fatalf("targeted kill failed: %v", err)
	// }
	// fmt.Printf("Targeted kill result: %v\n", result)

	// Initiate blanket kill (requires 2 approvals).
	// req, err := client.KillSwitch.InitiateBlanketKill(ctx, &kswitch.BlanketKillInitiateRequest{
	// 	Reason:      "Critical vulnerability discovered in agent framework",
	// 	InitiatedBy: "security-ops",
	// })
	// if err != nil {
	// 	log.Fatalf("initiate blanket kill failed: %v", err)
	// }
	// fmt.Printf("Blanket kill initiated: %s (approvals: %d/%d)\n",
	// 	req.ID, req.Approvals, req.Required)

	// List pending blanket kills.
	pending, err := client.KillSwitch.ListPendingBlanketKills(ctx)
	if err != nil {
		log.Fatalf("list pending blanket kills failed: %v", err)
	}
	fmt.Printf("Pending blanket kills: %d\n", len(pending))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
