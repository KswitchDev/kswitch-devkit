package kswitch

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"
)

// Option configures a Client.
type Option func(*Client)

// WithBaseURL sets the KSwitch API base URL (e.g. "https://kswitch.example.com").
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithToken sets a static Bearer token for authentication.
func WithToken(token string) Option {
	return func(c *Client) {
		c.token = token
	}
}

// WithKeycloak configures M2M token acquisition from Keycloak.
func WithKeycloak(url, realm, clientID, clientSecret string) Option {
	return func(c *Client) {
		c.keycloakURL = url
		c.realm = realm
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// WithHTTPClient sets a custom *http.Client (overrides TLS/timeout options).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithTLSConfig sets a custom TLS configuration for mTLS or CA pinning.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) {
		c.tlsConfig = cfg
	}
}

// WithTimeout sets the HTTP request timeout. Default is 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithRetries sets the maximum number of retry attempts. Default is 3.
func WithRetries(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxRetries = n
		}
	}
}

// WithBackoff sets the base backoff duration between retries. Default is 1s.
func WithBackoff(d time.Duration) Option {
	return func(c *Client) {
		c.backoff = d
	}
}

// WithLogger sets a structured logger for the client.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		c.logger = l
	}
}

// WithUserAgent sets the User-Agent header sent with every request.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.userAgent = ua
	}
}

// WithResource sets the OAuth2 resource parameter for token requests.
func WithResource(resource string) Option {
	return func(c *Client) {
		c.resource = resource
	}
}
