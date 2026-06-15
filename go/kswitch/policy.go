package kswitch

import (
	"context"
	"fmt"
)

// PolicyService handles Cedar/Rego policy CRUD and evaluation.
type PolicyService struct {
	client *Client
}

// Create creates a new governance policy.
func (s *PolicyService) Create(ctx context.Context, req *CreatePolicyRequest) (*Policy, error) {
	var policy Policy
	err := s.client.do(ctx, "POST", "/api/v1/policies", req, &policy)
	return &policy, err
}

// List returns all governance policies with optional filtering.
func (s *PolicyService) List(ctx context.Context, opts *ListOptions) (*PaginatedResponse[Policy], error) {
	var resp PaginatedResponse[Policy]
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/policies", params, nil, &resp)
	return &resp, err
}

// Get retrieves a specific policy with full Cedar + Rego text.
func (s *PolicyService) Get(ctx context.Context, id string) (*Policy, error) {
	var policy Policy
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/policies/%s", id), nil, &policy)
	return &policy, err
}

// Validate checks Cedar policy syntax without saving.
func (s *PolicyService) Validate(ctx context.Context, req *ValidatePolicyRequest) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/policies/validate", req, &result)
	return result, err
}

// Duplicate duplicates an existing policy.
func (s *PolicyService) Duplicate(ctx context.Context, policyID string, req *DuplicatePolicyRequest) (*Policy, error) {
	var policy Policy
	err := s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/policies/%s/duplicate", policyID), req, &policy)
	return &policy, err
}

// GetEvaluations returns recent policy evaluation results.
func (s *PolicyService) GetEvaluations(ctx context.Context, opts *ListOptions) ([]PolicyEvaluation, error) {
	var result []PolicyEvaluation
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/policies/evaluations", params, nil, &result)
	return result, err
}
