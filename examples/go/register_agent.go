package main

import (
	"context"
	"fmt"
	"log"

	"github.com/KswitchDev/kswitch-sdks/packages/go/kswitch"
)

func main() {
	client, err := kswitch.NewClientFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	agent, err := client.Governance.RegisterAgent(context.Background(), &kswitch.RegisterAgentRequest{
		DisplayName:    "customer-onboarding-v1",
		RecordType:     "AGENT",
		RiskTier:       "tier_2",
		OwningDivision: "Retail Banking",
		OwningTeam:     "onboarding-platform",
	})
	if err != nil {
		log.Fatal(err)
	}

	if _, err := client.Governance.ConnectMCPs(context.Background(), fmt.Sprint(agent["id"]), &kswitch.ConnectMCPsRequest{
		MCPIDs: []string{"mcp-kyc", "mcp-customer-data"},
	}); err != nil {
		log.Fatal(err)
	}

	fmt.Println(agent["id"])
}
