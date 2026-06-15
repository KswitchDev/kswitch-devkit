package kswitch

import "fmt"

// APIError is returned when the KSwitch API responds with a non-2xx status.
type APIError struct {
	StatusCode int            `json:"status_code"`
	Message    string         `json:"message,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("kswitch: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("kswitch: HTTP %d", e.StatusCode)
}

// IsNotFound returns true if the error is a 404 response.
func IsNotFound(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 404
	}
	return false
}

// IsUnauthorized returns true if the error is a 401 response.
func IsUnauthorized(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 401
	}
	return false
}

// IsForbidden returns true if the error is a 403 response.
func IsForbidden(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 403
	}
	return false
}

// IsConflict returns true if the error is a 409 response.
func IsConflict(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 409
	}
	return false
}

// IsRetryable returns true if the error represents a retryable server error.
func IsRetryable(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 503 || ae.StatusCode == 429 || ae.StatusCode >= 500
	}
	return false
}

// AuthError is returned when M2M token acquisition fails.
type AuthError struct {
	Cause error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("kswitch: auth failed: %v", e.Cause)
}

func (e *AuthError) Unwrap() error {
	return e.Cause
}
