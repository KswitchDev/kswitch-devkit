// Example: Register an agent with KSwitch.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/KswitchDev/kswitch-sdks/go/kswitch"
)

func main() {
	// Create a client — uses static token or Keycloak M2M.
	client := kswitch.NewClient(
		kswitch.WithBaseURL(envOr("KSWITCH_BASE_URL", "http://localhost:5001")),
		kswitch.WithToken(os.Getenv("KSWITCH_AUTH_TOKEN")),
	)

	ctx := context.Background()

	// Register a new agent.
	agent, err := client.Governance.RegisterAgent(ctx, &kswitch.RegisterAgentRequest{
		DisplayName:    "example-data-pipeline",
		RecordType:     "ai_agent",
		RiskTier:       "tier_2",
		OwningDivision: "engineering",
		OwningTeam:     "data-platform",
		Skills:         []string{"data_extraction", "data_transformation"},
		Description:    "Example data pipeline agent registered via Go SDK",
	})
	if err != nil {
		log.Fatalf("register failed: %v", err)
	}

	fmt.Printf("Registered agent: %s (ID: %s, Status: %s)\n",
		agent.DisplayName, agent.ID, agent.Status)

	// Assign skills.
	err = client.Governance.AssignSkills(ctx, agent.ID, &kswitch.AssignSkillsRequest{
		Skills: []string{"data_extraction", "data_transformation", "reporting"},
	})
	if err != nil {
		log.Fatalf("assign skills failed: %v", err)
	}
	fmt.Println("Skills assigned successfully")

	// Check health.
	health, err := client.Governance.HealthCheck(ctx)
	if err != nil {
		log.Fatalf("health check failed: %v", err)
	}
	fmt.Printf("API Health: %s\n", health.Status)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
