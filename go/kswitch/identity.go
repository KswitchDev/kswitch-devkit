package kswitch

import (
	"context"
	"fmt"
)

// IdentityService handles SPIFFE identities, trust domains, and rotation.
type IdentityService struct {
	client *Client
}

// CreateSPIFFE creates a SPIFFE identity for an agent.
func (s *IdentityService) CreateSPIFFE(ctx context.Context, agentID string, req *CreateSPIFFERequest) (*SPIFFEIdentity, error) {
	var id SPIFFEIdentity
	if req == nil {
		req = &CreateSPIFFERequest{}
	}
	err := s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/spiffe", agentID), req, &id)
	return &id, err
}

// GetSPIFFE returns the SPIFFE identity for an agent.
func (s *IdentityService) GetSPIFFE(ctx context.Context, agentID string) (*SPIFFEIdentity, error) {
	var id SPIFFEIdentity
	err := s.client.do(ctx, "GET", fmt.Sprintf("/api/v1/agents/%s/spiffe", agentID), nil, &id)
	return &id, err
}

// RotateSPIFFE rotates an agent's SPIFFE SVID.
func (s *IdentityService) RotateSPIFFE(ctx context.Context, agentID string) (*SPIFFEIdentity, error) {
	var id SPIFFEIdentity
	err := s.client.do(ctx, "PATCH", fmt.Sprintf("/api/v1/agents/%s/spiffe", agentID), nil, &id)
	return &id, err
}

// RevokeSPIFFE revokes an agent's SPIFFE identity.
func (s *IdentityService) RevokeSPIFFE(ctx context.Context, agentID string) error {
	return s.client.do(ctx, "DELETE", fmt.Sprintf("/api/v1/agents/%s/spiffe", agentID), nil, nil)
}

// CreateServiceIdentity creates a service identity for an agent.
func (s *IdentityService) CreateServiceIdentity(ctx context.Context, agentID string, req *CreateServiceIdentityRequest) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", fmt.Sprintf("/api/v1/agents/%s/identities", agentID), req, &result)
	return result, err
}

// ListTrustDomains returns all configured trust domains.
func (s *IdentityService) ListTrustDomains(ctx context.Context) ([]TrustDomain, error) {
	var domains []TrustDomain
	err := s.client.do(ctx, "GET", "/api/v1/trust-domains", nil, &domains)
	return domains, err
}

// GetStats returns identity statistics (total, active, expiring, revoked).
func (s *IdentityService) GetStats(ctx context.Context) (*IdentityStats, error) {
	var stats IdentityStats
	err := s.client.do(ctx, "GET", "/api/v1/identities/stats", nil, &stats)
	return &stats, err
}

// GetExpiring returns identities expiring within the given number of days.
func (s *IdentityService) GetExpiring(ctx context.Context, days int) ([]SPIFFEIdentity, error) {
	if days <= 0 {
		days = 30
	}
	var result []SPIFFEIdentity
	params := map[string]string{"days": itoa(days)}
	err := s.client.doWithParams(ctx, "GET", "/api/v1/identities/expiring", params, nil, &result)
	return result, err
}

// GetRotationStatus returns the identity rotation scheduler status.
func (s *IdentityService) GetRotationStatus(ctx context.Context) (*RotationStatus, error) {
	var status RotationStatus
	err := s.client.do(ctx, "GET", "/api/v1/identities/rotation-status", nil, &status)
	return &status, err
}
