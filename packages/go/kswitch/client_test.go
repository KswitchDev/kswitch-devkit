package kswitch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterAgentRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/agents/register" {
			t.Fatalf("path = %s, want /api/v1/agents/register", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization header not set")
		}

		var body RegisterAgentRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.DisplayName != "customer-onboarding-v1" {
			t.Fatalf("display name = %s", body.DisplayName)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"agent-123"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}

	agent, err := client.Governance.RegisterAgent(context.Background(), &RegisterAgentRequest{
		DisplayName:    "customer-onboarding-v1",
		RecordType:     "AGENT",
		RiskTier:       "tier_2",
		OwningDivision: "Retail Banking",
		OwningTeam:     "onboarding-platform",
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent["id"] != "agent-123" {
		t.Fatalf("agent id = %v", agent["id"])
	}
}

func TestAuditEventsQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "agent_id=agent-123&event_type=shadow_denied&limit=25" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"events":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Audit.Events(context.Background(), "agent-123", "shadow_denied", 25); err != nil {
		t.Fatal(err)
	}
}
