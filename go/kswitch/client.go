// Package kswitch provides a Go SDK for the KSwitch.ai governance platform.
//
// Create a client with NewClient and configure it with functional options:
//
//	client := kswitch.NewClient(
//	    kswitch.WithBaseURL("https://kswitch.example.com"),
//	    kswitch.WithToken("my-bearer-token"),
//	)
//
//	agent, err := client.Governance.RegisterAgent(ctx, &kswitch.RegisterAgentRequest{
//	    DisplayName: "my-agent",
//	    RiskTier:    "tier_2",
//	})
package kswitch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL   = "https://localhost:5001"
	defaultTimeout   = 30 * time.Second
	defaultRetries   = 3
	defaultBackoff   = 1 * time.Second
	defaultUserAgent = "kswitch-go/1.0"
)

// Client is the top-level KSwitch API client. Use NewClient to create one.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	userAgent  string

	// Keycloak M2M credentials
	clientID     string
	clientSecret string
	keycloakURL  string
	realm        string
	resource     string
	tokenCache   *tokenCache

	// HTTP behaviour
	timeout    time.Duration
	maxRetries int
	backoff    time.Duration
	tlsConfig  *tls.Config
	logger     *slog.Logger

	// Services
	Governance  *GovernanceService
	Policy      *PolicyService
	Identity    *IdentityService
	Compliance  *ComplianceService
	KillSwitch  *KillSwitchService
	Events      *EventsService
	Catalog     *CatalogService
	Enforcement *EnforcementService
	AuthZen     *AuthZenService
	Service     *ServiceService
}

// NewClient creates a configured KSwitch client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
		maxRetries: defaultRetries,
		backoff:    defaultBackoff,
		userAgent:  defaultUserAgent,
		tokenCache: &tokenCache{},
	}

	for _, opt := range opts {
		opt(c)
	}

	// Build HTTP client if not provided.
	if c.httpClient == nil {
		transport := &http.Transport{}
		if c.tlsConfig != nil {
			transport.TLSClientConfig = c.tlsConfig
		}
		c.httpClient = &http.Client{
			Timeout:   c.timeout,
			Transport: transport,
		}
	}

	// Initialise services.
	c.Governance = &GovernanceService{client: c}
	c.Policy = &PolicyService{client: c}
	c.Identity = &IdentityService{client: c}
	c.Compliance = &ComplianceService{client: c}
	c.KillSwitch = &KillSwitchService{client: c}
	c.Events = &EventsService{client: c}
	c.Catalog = &CatalogService{client: c}
	c.Enforcement = &EnforcementService{client: c}
	c.AuthZen = &AuthZenService{client: c}
	c.Service = &ServiceService{client: c}

	return c
}

// ---------------------------------------------------------------------------
// Internal HTTP helpers
// ---------------------------------------------------------------------------

// do executes an HTTP request with JSON encoding, retry, and auth.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	return c.doWithParams(ctx, method, path, nil, body, out)
}

// doWithParams executes an HTTP request with query parameters.
func (c *Client) doWithParams(ctx context.Context, method, path string, params map[string]string, body any, out any) error {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoff * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		err := c.doOnce(ctx, method, path, params, body, out)
		if err == nil {
			return nil
		}

		// On 401, try refreshing the token once.
		if ae, ok := err.(*APIError); ok && ae.StatusCode == 401 && attempt == 0 {
			if c.clientID != "" {
				if _, refreshErr := c.refreshToken(); refreshErr == nil {
					attempt = 0 // retry immediately with new token
					lastErr = err
					continue
				}
			}
		}

		// Retry only on retryable errors.
		if !isRetryableErr(err) {
			return err
		}
		lastErr = err
	}

	return lastErr
}

// doOnce performs a single HTTP request.
func (c *Client) doOnce(ctx context.Context, method, path string, params map[string]string, body any, out any) error {
	// Build URL
	u, err := url.Parse(strings.TrimRight(c.baseURL, "/") + path)
	if err != nil {
		return err
	}
	if len(params) > 0 {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	// Encode body
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("kswitch: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return err
	}

	// Headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	// Auth
	token, err := c.resolveToken()
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Execute
	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		c.log(ctx, slog.LevelWarn, "request failed",
			"method", method, "path", path, "duration_ms", duration.Milliseconds(), "error", err)
		return err
	}
	defer resp.Body.Close()

	c.log(ctx, slog.LevelDebug, "request completed",
		"method", method, "path", path, "status", resp.StatusCode, "duration_ms", duration.Milliseconds())

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("kswitch: read response: %w", err)
	}

	// Non-2xx → APIError
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		// Try to parse error message from body.
		var errBody struct {
			Message string         `json:"message"`
			Error   string         `json:"error"`
			Details map[string]any `json:"details"`
		}
		if json.Unmarshal(respBody, &errBody) == nil {
			apiErr.Message = errBody.Message
			if apiErr.Message == "" {
				apiErr.Message = errBody.Error
			}
			apiErr.Details = errBody.Details
		}
		return apiErr
	}

	// Decode into output if requested.
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("kswitch: decode response: %w", err)
		}
	}

	return nil
}

// log emits a structured log message if a logger is configured.
func (c *Client) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if c.logger != nil {
		c.logger.Log(ctx, level, msg, args...)
	}
}

// sanitizePathParam validates and encodes a user-provided ID for safe use in URL paths.
// It rejects values containing path traversal sequences or query string injections.
func sanitizePathParam(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("kswitch: path parameter must not be empty")
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") ||
		strings.Contains(id, "..") || strings.Contains(id, "?") ||
		strings.Contains(id, "#") || strings.Contains(id, "%2e") ||
		strings.Contains(id, "%2f") || strings.Contains(id, "%5c") {
		return "", fmt.Errorf("kswitch: invalid characters in path parameter")
	}
	return url.PathEscape(id), nil
}

// isRetryableErr checks if an error should be retried.
func isRetryableErr(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.StatusCode == 503 || ae.StatusCode == 429 || ae.StatusCode == 502
	}
	// Retry on network-level errors.
	return false
}
