package kswitch

type RegisterAgentRequest struct {
	DisplayName    string            `json:"display_name"`
	RecordType     string            `json:"record_type"`
	RiskTier       string            `json:"risk_tier"`
	OwningDivision string            `json:"owning_division"`
	OwningTeam     string            `json:"owning_team"`
	Skills         []string          `json:"skills,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type ConnectMCPsRequest struct {
	MCPIDs []string `json:"mcp_ids"`
}

type Agent map[string]any
type APIObject map[string]any
