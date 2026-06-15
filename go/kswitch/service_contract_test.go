package kswitch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type serviceCall struct {
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Body   map[string]any `json:"body,omitempty"`
}

func TestServiceContractPaths(t *testing.T) {
	var calls []serviceCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := serviceCall{Method: r.Method, Path: r.URL.Path}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&call.Body)
		}
		calls = append(calls, call)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL), WithRetries(1))
	ctx := context.Background()

	if _, err := client.Service.Fetch(ctx, &ServiceFetchRequest{URL: "https://example.com/docs", Purpose: "docs", TaskID: "task-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Service.Search(ctx, &ServiceSearchRequest{Query: "vendor docs", Purpose: "docs", TaskID: "task-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Service.PolicyCheck(ctx, &ServicePolicyCheckRequest{Action: "fetch", Target: map[string]any{"host": "example.com"}, Purpose: "docs", TaskID: "task-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Service.GetPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Service.Health(ctx); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 5 {
		t.Fatalf("got %d calls, want 5: %#v", len(calls), calls)
	}
	assertServiceCall(t, calls[0], "POST", serviceBasePath+"/fetch")
	assertServiceCall(t, calls[1], "POST", serviceBasePath+"/search")
	assertServiceCall(t, calls[2], "POST", serviceBasePath+"/policy_check")
	assertServiceCall(t, calls[3], "GET", serviceBasePath+"/policy")
	assertServiceCall(t, calls[4], "GET", serviceBasePath+"/health")

	if calls[0].Body["max_bytes"].(float64) != 1048576 {
		t.Fatalf("fetch default max_bytes = %#v", calls[0].Body["max_bytes"])
	}
	if calls[1].Body["provider_id"] != "customer_search_default" {
		t.Fatalf("search default provider_id = %#v", calls[1].Body["provider_id"])
	}
	if calls[1].Body["max_results"].(float64) != 10 {
		t.Fatalf("search default max_results = %#v", calls[1].Body["max_results"])
	}
}

func assertServiceCall(t *testing.T, call serviceCall, method, path string) {
	t.Helper()
	if call.Method != method || call.Path != path {
		t.Fatalf("call = %s %s, want %s %s", call.Method, call.Path, method, path)
	}
}
