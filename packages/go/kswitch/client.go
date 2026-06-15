package kswitch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.kswitch.io"

type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client

	Governance *GovernanceClient
	Policy     *PolicyClient
	Audit      *AuditClient
	Tools      *ToolsClient
	KillSwitch *KillSwitchClient
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) {
		client.HTTPClient = httpClient
	}
}

func NewClient(baseURL string, apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("baseURL is required")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("apiKey is required")
	}

	client := &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(client)
	}

	client.Governance = &GovernanceClient{client: client}
	client.Policy = &PolicyClient{client: client}
	client.Audit = &AuditClient{client: client}
	client.Tools = &ToolsClient{client: client}
	client.KillSwitch = &KillSwitchClient{client: client}
	return client, nil
}

func NewClientFromEnv(opts ...Option) (*Client, error) {
	apiKey := os.Getenv("KSWITCH_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("KSWITCH_TOKEN")
	}
	if apiKey == "" {
		return nil, errors.New("KSWITCH_API_KEY or KSWITCH_TOKEN is required")
	}

	baseURL := os.Getenv("KSWITCH_BASE_URL")
	if baseURL == "" {
		baseURL = os.Getenv("KSWITCH_URL")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return NewClient(baseURL, apiKey, opts...)
}

func (c *Client) Request(ctx context.Context, method string, path string, body any, query url.Values, out any) error {
	requestURL, err := c.buildURL(path, query)
	if err != nil {
		return err
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kswitch-go/0.1.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: data}
	}
	if out == nil || len(data) == 0 {
		return nil
	}

	return json.Unmarshal(data, out)
}

func (c *Client) buildURL(path string, query url.Values) (string, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	base.RawQuery = query.Encode()
	return base.String(), nil
}

type APIError struct {
	StatusCode int
	Body       []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("KSwitch API request failed with status %d", e.StatusCode)
}

type GovernanceClient struct {
	client *Client
}

func (g *GovernanceClient) RegisterAgent(ctx context.Context, request *RegisterAgentRequest) (Agent, error) {
	var out Agent
	err := g.client.Request(ctx, http.MethodPost, "/api/v1/agents/register", request, nil, &out)
	return out, err
}

func (g *GovernanceClient) ConnectMCPs(ctx context.Context, agentID string, request *ConnectMCPsRequest) (APIObject, error) {
	var out APIObject
	err := g.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/mcps", request, nil, &out)
	return out, err
}

func (g *GovernanceClient) EvaluateToxicCombos(ctx context.Context, agentID string) (APIObject, error) {
	var out APIObject
	err := g.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/evaluate-toxic-combos", nil, nil, &out)
	return out, err
}

func (g *GovernanceClient) ApproveAgent(ctx context.Context, agentID string, secondLineRef string) (APIObject, error) {
	body := map[string]string{}
	if secondLineRef != "" {
		body["second_line_ref"] = secondLineRef
	}
	var out APIObject
	err := g.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/approve", body, nil, &out)
	return out, err
}

type PolicyClient struct {
	client *Client
}

func (p *PolicyClient) Update(ctx context.Context, policyID string, fields map[string]any) (APIObject, error) {
	var out APIObject
	err := p.client.Request(ctx, http.MethodPatch, "/api/v1/policies/"+url.PathEscape(policyID), fields, nil, &out)
	return out, err
}

type AuditClient struct {
	client *Client
}

func (a *AuditClient) Events(ctx context.Context, agentID string, eventType string, limit int) (APIObject, error) {
	query := url.Values{}
	if agentID != "" {
		query.Set("agent_id", agentID)
	}
	if eventType != "" {
		query.Set("event_type", eventType)
	}
	if limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", limit))
	}

	var out APIObject
	err := a.client.Request(ctx, http.MethodGet, "/api/v1/audit/events", nil, query, &out)
	return out, err
}

type ToolsClient struct {
	client *Client
}

func (t *ToolsClient) List(ctx context.Context) (APIObject, error) {
	var out APIObject
	err := t.client.Request(ctx, http.MethodGet, "/api/v1/tools-catalog", nil, nil, &out)
	return out, err
}

type KillSwitchClient struct {
	client *Client
}

func (k *KillSwitchClient) TargetedKillSwitch(ctx context.Context, agentID string, reason string) (APIObject, error) {
	var out APIObject
	err := k.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/kill-switch", map[string]string{"reason": reason}, nil, &out)
	return out, err
}

func (k *KillSwitchClient) SuspendAgent(ctx context.Context, agentID string, reason string) (APIObject, error) {
	var out APIObject
	err := k.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/suspend", map[string]string{"reason": reason}, nil, &out)
	return out, err
}

func (k *KillSwitchClient) ReactivateAgent(ctx context.Context, agentID string) (APIObject, error) {
	var out APIObject
	err := k.client.Request(ctx, http.MethodPost, "/api/v1/agents/"+url.PathEscape(agentID)+"/reactivate", nil, nil, &out)
	return out, err
}
