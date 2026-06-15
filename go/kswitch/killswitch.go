package kswitch

import (
	"context"
	"fmt"
)

// KillSwitchService handles targeted and blanket kill switch operations.
type KillSwitchService struct {
	client *Client
}

// TargetedKill activates a targeted kill switch on specific agents.
func (s *KillSwitchService) TargetedKill(ctx context.Context, req *TargetedKillRequest) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/kill-switch", req, &result)
	return result, err
}

// GetHistory returns the kill switch activation history.
func (s *KillSwitchService) GetHistory(ctx context.Context) ([]KillSwitchRecord, error) {
	var records []KillSwitchRecord
	err := s.client.do(ctx, "GET", "/api/v1/kill-switch/history", nil, &records)
	return records, err
}

// GetViolations returns kill switch violation records.
func (s *KillSwitchService) GetViolations(ctx context.Context) ([]KillSwitchViolation, error) {
	var violations []KillSwitchViolation
	err := s.client.do(ctx, "GET", "/api/v1/kill-switch/violations", nil, &violations)
	return violations, err
}

// InitiateBlanketKill initiates a blanket kill switch (requires 2 approvals).
func (s *KillSwitchService) InitiateBlanketKill(ctx context.Context, req *BlanketKillInitiateRequest) (*BlanketKillRequest, error) {
	var result BlanketKillRequest
	err := s.client.do(ctx, "POST", "/api/v1/kill-switch/blanket/initiate", req, &result)
	return &result, err
}

// ApproveBlanketKill approves a pending blanket kill switch request.
func (s *KillSwitchService) ApproveBlanketKill(ctx context.Context, blanketID string) error {
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/kill-switch/blanket/%s/approve", blanketID), nil, nil)
}

// CancelBlanketKill cancels a pending blanket kill switch request.
func (s *KillSwitchService) CancelBlanketKill(ctx context.Context, blanketID string) error {
	return s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/kill-switch/blanket/%s/cancel", blanketID), nil, nil)
}

// ListPendingBlanketKills returns pending blanket kill switch requests.
func (s *KillSwitchService) ListPendingBlanketKills(ctx context.Context) ([]BlanketKillRequest, error) {
	var result []BlanketKillRequest
	err := s.client.do(ctx, "GET", "/api/v1/kill-switch/blanket", nil, &result)
	return result, err
}
