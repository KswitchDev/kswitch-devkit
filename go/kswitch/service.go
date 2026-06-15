package kswitch

import "context"

const serviceBasePath = "/api/v1/b005/service"

// ServiceService mirrors the B005.2 kswitch_service MCP tool surface.
//
// These methods are transport wrappers. Server-side policy, identity binding,
// audit persistence, and provider dispatch remain authoritative.
type ServiceService struct {
	client *Client
}

type ServiceFetchRequest struct {
	URL      string `json:"url"`
	Purpose  string `json:"purpose"`
	TaskID   string `json:"task_id"`
	MaxBytes int    `json:"max_bytes"`
}

type ServiceSearchRequest struct {
	Query      string `json:"query"`
	Purpose    string `json:"purpose"`
	TaskID     string `json:"task_id"`
	ProviderID string `json:"provider_id"`
	MaxResults int    `json:"max_results"`
}

type ServicePolicyCheckRequest struct {
	Action       string         `json:"action"`
	Target       map[string]any `json:"target"`
	Purpose      string         `json:"purpose"`
	TaskID       string         `json:"task_id"`
	ServiceClass string         `json:"service_class,omitempty"`
}

func (s *ServiceService) Fetch(ctx context.Context, req *ServiceFetchRequest) (map[string]any, error) {
	body := *req
	if body.MaxBytes == 0 {
		body.MaxBytes = 1048576
	}
	var out map[string]any
	err := s.client.do(ctx, "POST", serviceBasePath+"/fetch", &body, &out)
	return out, err
}

func (s *ServiceService) Search(ctx context.Context, req *ServiceSearchRequest) (map[string]any, error) {
	body := *req
	if body.ProviderID == "" {
		body.ProviderID = "customer_search_default"
	}
	if body.MaxResults == 0 {
		body.MaxResults = 10
	}
	var out map[string]any
	err := s.client.do(ctx, "POST", serviceBasePath+"/search", &body, &out)
	return out, err
}

func (s *ServiceService) PolicyCheck(ctx context.Context, req *ServicePolicyCheckRequest) (map[string]any, error) {
	var out map[string]any
	err := s.client.do(ctx, "POST", serviceBasePath+"/policy_check", req, &out)
	return out, err
}

func (s *ServiceService) GetPolicy(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := s.client.do(ctx, "GET", serviceBasePath+"/policy", nil, &out)
	return out, err
}

func (s *ServiceService) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := s.client.do(ctx, "GET", serviceBasePath+"/health", nil, &out)
	return out, err
}
