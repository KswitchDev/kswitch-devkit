package kswitch

import "context"

// AuthZenService provides access to the OpenID AuthZen PDP evaluation endpoint.
type AuthZenService struct {
	client *Client
}

// Evaluate sends an authorization evaluation request to the AuthZen PDP.
// This uses the standard AuthZen evaluation path (/access/v1/evaluation).
func (s *AuthZenService) Evaluate(ctx context.Context, req *AuthZenRequest) (*AuthZenResponse, error) {
	var resp AuthZenResponse
	err := s.client.do(ctx, "POST", "/access/v1/evaluation", req, &resp)
	return &resp, err
}

// EvaluationRequest is a convenience alias for AuthZenRequest.
type EvaluationRequest = AuthZenRequest

// EvaluationResponse is a convenience alias for AuthZenResponse.
type EvaluationResponse = AuthZenResponse
