package kswitch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tokenCache stores a cached M2M access token with thread-safe access.
type tokenCache struct {
	mu        sync.RWMutex
	token     string
	expiresAt time.Time
}

// get returns the cached token if it is still valid (with a 60s buffer).
func (tc *tokenCache) get() string {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	if tc.token != "" && time.Now().Add(60*time.Second).Before(tc.expiresAt) {
		return tc.token
	}
	return ""
}

// set stores a token with its expiry.
func (tc *tokenCache) set(token string, expiresIn time.Duration) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.token = token
	tc.expiresAt = time.Now().Add(expiresIn)
}

// clear invalidates the cached token.
func (tc *tokenCache) clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.token = ""
	tc.expiresAt = time.Time{}
}

// tokenResponse is the JSON body returned by the OIDC token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// fetchM2MToken obtains an access token from the Keycloak (or compatible OIDC)
// token endpoint using the client_credentials grant. It caches the result.
func (c *Client) fetchM2MToken() (string, error) {
	// Return cached token if still valid.
	if tok := c.tokenCache.get(); tok != "" {
		return tok, nil
	}

	if c.clientID == "" || c.clientSecret == "" {
		return "", &AuthError{Cause: fmt.Errorf("client_id and client_secret are required for M2M auth")}
	}

	tokenURL := c.tokenEndpoint()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	if c.resource != "" {
		form.Set("resource", c.resource)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &AuthError{Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", &AuthError{Cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", &AuthError{Cause: err}
	}

	if resp.StatusCode != http.StatusOK {
		// Do not include response body in error — it may contain sensitive IdP details
		return "", &AuthError{
			Cause: fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode),
		}
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", &AuthError{Cause: err}
	}

	if tok.AccessToken == "" {
		return "", &AuthError{Cause: fmt.Errorf("empty access_token in response")}
	}

	expiresIn := time.Duration(tok.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 3600 * time.Second
	}
	c.tokenCache.set(tok.AccessToken, expiresIn)
	return tok.AccessToken, nil
}

// tokenEndpoint builds the OIDC token URL from Keycloak config.
func (c *Client) tokenEndpoint() string {
	base := strings.TrimRight(c.keycloakURL, "/")
	realm := c.realm
	if realm == "" {
		realm = "kswitch"
	}
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", base, realm)
}

// resolveToken returns the bearer token to use for a request.
// If a static token is set, it is returned directly. Otherwise M2M auth is used.
func (c *Client) resolveToken() (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	if c.clientID != "" && c.clientSecret != "" {
		return c.fetchM2MToken()
	}
	return "", nil // unauthenticated
}

// refreshToken clears the cached token and fetches a new one.
func (c *Client) refreshToken() (string, error) {
	c.tokenCache.clear()
	c.token = ""
	return c.fetchM2MToken()
}
