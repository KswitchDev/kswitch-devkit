package kswitch

import "context"

// CatalogService handles skills catalog, tools catalog, and sync source operations.
type CatalogService struct {
	client *Client
}

// ListSkills returns skills catalog entries.
func (s *CatalogService) ListSkills(ctx context.Context, opts *ListOptions) ([]Skill, error) {
	var skills []Skill
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/skills-catalog", params, nil, &skills)
	return skills, err
}

// ListTools returns tools catalog entries.
func (s *CatalogService) ListTools(ctx context.Context, opts *ListOptions) ([]ToolCatalogEntry, error) {
	var tools []ToolCatalogEntry
	params := opts.ToParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/tools-catalog", params, nil, &tools)
	return tools, err
}

// SyncTools syncs the tools catalog from connected MCP servers.
func (s *CatalogService) SyncTools(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/tools-catalog/sync", nil, &result)
	return result, err
}

// ListSyncSources returns all configured sync sources.
func (s *CatalogService) ListSyncSources(ctx context.Context) ([]SyncSource, error) {
	var sources []SyncSource
	err := s.client.do(ctx, "GET", "/api/v1/sync-sources", nil, &sources)
	return sources, err
}

// AddSyncSource adds a new sync source for skills or tools.
func (s *CatalogService) AddSyncSource(ctx context.Context, req *AddSyncSourceRequest) (*SyncSource, error) {
	var source SyncSource
	err := s.client.do(ctx, "POST", "/api/v1/sync-sources", req, &source)
	return &source, err
}

// TriggerSync triggers sync of all registry sources.
func (s *CatalogService) TriggerSync(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := s.client.do(ctx, "POST", "/api/v1/registry-sync/trigger", nil, &result)
	return result, err
}

// GetSyncStatus returns the current registry sync status.
func (s *CatalogService) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var status SyncStatus
	err := s.client.do(ctx, "GET", "/api/v1/registry-sync/status", nil, &status)
	return &status, err
}
