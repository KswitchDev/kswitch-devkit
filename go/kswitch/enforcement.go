package kswitch

import (
	"context"
	"fmt"
)

// EnforcementService handles scanner, graph analysis, and enforcement operations.
type EnforcementService struct {
	client *Client
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

// TriggerScan triggers a repository scan for agent/MCP discovery.
func (s *EnforcementService) TriggerScan(ctx context.Context, req *TriggerScanRequest) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/scanner/scan", req, &result)
	return result, err
}

// GetScannerStats returns scanner statistics.
func (s *EnforcementService) GetScannerStats(ctx context.Context) (*ScannerStats, error) {
	var stats ScannerStats
	err := s.client.do(ctx, "GET", "/api/v1/scanner/stats", nil, &stats)
	return &stats, err
}

// ListScanRuns returns scan run history.
func (s *EnforcementService) ListScanRuns(ctx context.Context, opts *ListOptions) ([]ScanRun, error) {
	var runs []ScanRun
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/scanner/runs", params, nil, &runs)
	return runs, err
}

// GetScanRun returns a specific scan run.
func (s *EnforcementService) GetScanRun(ctx context.Context, scanID string) (*ScanRun, error) {
	var run ScanRun
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/scanner/runs/%s", scanID), nil, &run)
	return &run, err
}

// GetScanFindings returns findings for a specific scan run.
func (s *EnforcementService) GetScanFindings(ctx context.Context, scanID string) ([]ScanFinding, error) {
	var findings []ScanFinding
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/scanner/runs/%s/findings", scanID), nil, &findings)
	return findings, err
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

// GetGraphStats returns governance graph statistics.
func (s *EnforcementService) GetGraphStats(ctx context.Context) (*GraphStats, error) {
	var stats GraphStats
	err := s.client.do(ctx, "GET", "/api/v1/graph/stats", nil, &stats)
	return &stats, err
}

// GetBlastRadius returns blast radius analysis for a set of agents.
func (s *EnforcementService) GetBlastRadius(ctx context.Context, req *BlastRadiusRequest) (*BlastRadius, error) {
	var result BlastRadius
	err := s.client.do(ctx, "POST", "/api/v1/graph/blast-radius", req, &result)
	return &result, err
}

// ---------------------------------------------------------------------------
// MCP call enforcement (PR-05)
// ---------------------------------------------------------------------------

// EnforceMCPCall calls the enforcement endpoint before a tool invocation.
//
// This is the primary gate: call EnforceMCPCall, inspect the decision, then
// use [Interceptor.CheckAndInvoke] for the full safe execution path.
func (s *EnforcementService) EnforceMCPCall(ctx context.Context, req *EnforcementRequest) (*EnforcementDecision, error) {
	var decision EnforcementDecision
	err := s.client.do(ctx, "POST", "/api/v1/enforce/mcp-call", req, &decision)
	return &decision, err
}

// ObligationReportRequest is the payload for reporting fulfilled obligations.
type ObligationReportRequest struct {
	EnforcementID   string   `json:"enforcement_id"`
	ObligationsMet  []string `json:"obligations_met"`
}

// ObligationReportResult is the server validation response.
type ObligationReportResult struct {
	EnforcementID        string   `json:"enforcement_id"`
	ObligationsMet       []string `json:"obligations_met"`
	ObligationsTracked   bool     `json:"obligations_tracked"`
	Valid                bool     `json:"valid"`
	UnknownObligations   []string `json:"unknown_obligations"`
	MissingObligations   []string `json:"missing_obligations"`
	Message              string   `json:"message"`
	TrackedAt            string   `json:"tracked_at"`
}

// ReportObligations reports fulfilled obligations for a prior ALLOW decision (PR-05).
//
// Best-effort: callers should not fail tool execution on a reporting error.
func (s *EnforcementService) ReportObligations(ctx context.Context, req *ObligationReportRequest) (*ObligationReportResult, error) {
	var result ObligationReportResult
	err := s.client.do(ctx, "POST", "/api/v1/enforce/obligation-report", req, &result)
	return &result, err
}
