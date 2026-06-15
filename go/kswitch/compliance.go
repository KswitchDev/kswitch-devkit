package kswitch

import (
	"context"
	"fmt"
)

// ComplianceService handles toxic combo evaluation, boundary analysis, and risk assessment.
type ComplianceService struct {
	client *Client
}

// EvaluateToxicCombos evaluates a specific agent for toxic skill/permission combinations.
func (s *ComplianceService) EvaluateToxicCombos(ctx context.Context, agentID string) ([]ToxicComboViolation, error) {
	var result []ToxicComboViolation
	err := s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/evaluate-toxic-combos", agentID), nil, &result)
	return result, err
}

// EvaluateAllToxicCombos runs toxic combo evaluation across all agents.
func (s *ComplianceService) EvaluateAllToxicCombos(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/toxic-combos/evaluate-all", nil, &result)
	return result, err
}

// GetToxicComboDashboard returns the toxic combo dashboard summary.
func (s *ComplianceService) GetToxicComboDashboard(ctx context.Context) (*ToxicComboDashboard, error) {
	var d ToxicComboDashboard
	err := s.client.do(ctx, "GET", "/api/v1/toxic-combos/dashboard", nil, &d)
	return &d, err
}

// ListToxicRules returns all defined toxic combo rules.
func (s *ComplianceService) ListToxicRules(ctx context.Context) ([]ToxicComboRule, error) {
	var rules []ToxicComboRule
	err := s.client.do(ctx, "GET", "/api/v1/toxic-combos/rules", nil, &rules)
	return rules, err
}

// GetBoundaryAnalysis returns boundary crossing analysis for an agent.
func (s *ComplianceService) GetBoundaryAnalysis(ctx context.Context, agentID string) (*BoundaryAnalysis, error) {
	var ba BoundaryAnalysis
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/boundary-analysis/%s", agentID), nil, &ba)
	return &ba, err
}

// GetFleetRiskSummary generates a risk summary across the entire fleet.
func (s *ComplianceService) GetFleetRiskSummary(ctx context.Context) (*FleetRiskSummary, error) {
	var summary FleetRiskSummary
	err := s.client.do(ctx, "GET", "/api/v1/compliance/fleet-risk", nil, &summary)
	return &summary, err
}

// AssessAgentRisk performs a comprehensive risk assessment for a single agent.
func (s *ComplianceService) AssessAgentRisk(ctx context.Context, agentID string) (*AgentRisk, error) {
	var risk AgentRisk
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/compliance/agent-risk/%s", agentID), nil, &risk)
	return &risk, err
}
