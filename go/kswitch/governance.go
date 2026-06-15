package kswitch

import (
	"context"
	"fmt"
)

// GovernanceService handles agent registration, lifecycle, and audit operations.
type GovernanceService struct {
	client *Client
}

// RegisterAgent registers a new agent in the governance system.
func (s *GovernanceService) RegisterAgent(ctx context.Context, req *RegisterAgentRequest) (*Agent, error) {
	var agent Agent
	err := s.client.do(ctx, "POST", "/api/v1/agents", req, &agent)
	return &agent, err
}

// ListAgents returns a paginated list of registered agents.
func (s *GovernanceService) ListAgents(ctx context.Context, opts *ListOptions) (*PaginatedResponse[Agent], error) {
	var resp PaginatedResponse[Agent]
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/agents", params, nil, &resp)
	return &resp, err
}

// GetAgent retrieves a single agent by ID.
func (s *GovernanceService) GetAgent(ctx context.Context, id string) (*Agent, error) {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return nil, err
	}
	var agent Agent
	err = s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/agents/%s", safeID), nil, &agent)
	return &agent, err
}

// Approve approves a pending agent.
func (s *GovernanceService) Approve(ctx context.Context, id string, req *ApproveRequest) error {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/approve", safeID), req, nil)
}

// Suspend suspends an active agent.
func (s *GovernanceService) Suspend(ctx context.Context, id string, reason string) error {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return err
	}
	body := &SuspendRequest{Reason: reason}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/suspend", safeID), body, nil)
}

// Reactivate reactivates a suspended agent.
func (s *GovernanceService) Reactivate(ctx context.Context, id string) error {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/reactivate", safeID), nil, nil)
}

// Decommission permanently decommissions an agent.
func (s *GovernanceService) Decommission(ctx context.Context, id string) error {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/decommission", safeID), nil, nil)
}

// GetApprovalCriteria returns the approval criteria for an agent.
func (s *GovernanceService) GetApprovalCriteria(ctx context.Context, id string) (map[string]any, error) {
	safeID, err := sanitizePathParam(id)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/agents/%s/approval-criteria", safeID), nil, &result)
	return result, err
}

// LinkTicket links a Jira ticket to an agent record.
func (s *GovernanceService) LinkTicket(ctx context.Context, agentID string, req *LinkTicketRequest) error {
	safeID, err := sanitizePathParam(agentID)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/tickets", safeID), req, nil)
}

// AssignSkills assigns skills to an agent.
func (s *GovernanceService) AssignSkills(ctx context.Context, agentID string, req *AssignSkillsRequest) error {
	safeID, err := sanitizePathParam(agentID)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/skills", safeID), req, nil)
}

// ConnectMCPs connects an agent to MCP servers.
func (s *GovernanceService) ConnectMCPs(ctx context.Context, agentID string, req *ConnectMCPsRequest) error {
	safeID, err := sanitizePathParam(agentID)
	if err != nil {
		return err
	}
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/connected-mcps", safeID), req, nil)
}

// GetAudit returns the full audit trail for an agent.
func (s *GovernanceService) GetAudit(ctx context.Context, agentID string) ([]AuditEntry, error) {
	safeID, err := sanitizePathParam(agentID)
	if err != nil {
		return nil, err
	}
	var result []AuditEntry
	err = s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/agents/%s/audit", safeID), nil, &result)
	return result, err
}

// RegisterMCP registers a new MCP server with its tool declaration.
func (s *GovernanceService) RegisterMCP(ctx context.Context, req *RegisterMCPRequest) (*MCPServer, error) {
	var mcp MCPServer
	err := s.client.do(ctx, "POST", "/api/v1/mcp/register", req, &mcp)
	return &mcp, err
}

// RefreshConsumerCounts refreshes MCP consumer counts across all servers.
func (s *GovernanceService) RefreshConsumerCounts(ctx context.Context) error {
	return s.client.do(ctx, "POST", "/api/v1/mcp/refresh-consumer-counts", nil, nil)
}

// GetDashboard returns the main governance dashboard.
func (s *GovernanceService) GetDashboard(ctx context.Context) (*Dashboard, error) {
	var d Dashboard
	err := s.client.do(ctx, "GET", "/api/v1/dashboard", nil, &d)
	return &d, err
}

// HealthCheck checks the API health status.
func (s *GovernanceService) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	var h HealthStatus
	err := s.client.do(ctx, "GET", "/api/v1/health", nil, &h)
	return &h, err
}

// TriggerGateEval runs auto-gate evaluation for an MCP server.
func (s *GovernanceService) TriggerGateEval(ctx context.Context, mcpID string) (map[string]any, error) {
	safeID, err := sanitizePathParam(mcpID)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/mcp/%s/gates/evaluate", safeID), nil, &result)
	return result, err
}

// AutoApplyGates auto-applies passing gates for an MCP server.
func (s *GovernanceService) AutoApplyGates(ctx context.Context, mcpID string) (map[string]any, error) {
	safeID, err := sanitizePathParam(mcpID)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/mcp/%s/gates/auto-apply", safeID), nil, &result)
	return result, err
}

// GetGateStatus returns gate evaluation status for an MCP.
func (s *GovernanceService) GetGateStatus(ctx context.Context, mcpID string) (*GateStatus, error) {
	safeID, err := sanitizePathParam(mcpID)
	if err != nil {
		return nil, err
	}
	var gs GateStatus
	err = s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/mcp/%s/gates/status", safeID), nil, &gs)
	return &gs, err
}

// RunCleanup runs maintenance cleanup of old policy evaluations and events.
func (s *GovernanceService) RunCleanup(ctx context.Context, req *CleanupRequest) (map[string]any, error) {
	var result map[string]any
	if req == nil {
		req = &CleanupRequest{}
	}
	err := s.client.do(ctx, "POST", "/api/v1/maintenance/cleanup", req, &result)
	return result, err
}
