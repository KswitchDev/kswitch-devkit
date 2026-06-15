import { type KSwitchClient, sanitizePathParam } from "./client.js";
import type {
  Agent,
  AuditEntry,
  DelegationChain,
  DelegationRequest,
  PaginatedResponse,
  TicketLink,
} from "./types.js";

/**
 * Agent lifecycle and governance operations.
 *
 * Covers registration, approval workflow, suspension, decommissioning,
 * skill assignment, MCP connections, delegation, and audit trails.
 */
export class GovernanceAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── Dashboard ────────────────────────────────────────────────────────────

  /** Get the governance dashboard with record counts and status breakdown. */
  async getDashboard(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/dashboard");
  }

  // ── Agents CRUD ──────────────────────────────────────────────────────────

  /** List registered agents with optional pagination. */
  async listAgents(params?: {
    page?: number;
    page_size?: number;
    status?: string;
    record_type?: string;
    risk_tier?: string;
    search?: string;
    limit?: number;
  }): Promise<PaginatedResponse<Agent>> {
    return this.client.request("GET", "/api/v1/agents", { params });
  }

  /** Get a single agent by ID. */
  async getAgent(agentId: string): Promise<Agent> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}`);
  }

  /** Register a new agent. */
  async registerAgent(data: Partial<Agent>): Promise<Agent> {
    return this.client.request("POST", "/api/v1/agents", { json: data });
  }

  /** Update an existing agent record. */
  async updateAgent(agentId: string, data: Partial<Agent>): Promise<Agent> {
    return this.client.request("PATCH", `/api/v1/agents/${sanitizePathParam(agentId)}`, { json: data });
  }

  // ── Approval Workflow ────────────────────────────────────────────────────

  /** Get approval criteria for an agent. */
  async getApprovalCriteria(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/approval-criteria`);
  }

  /** Approve a pending agent. */
  async approveAgent(agentId: string, data?: Record<string, unknown>): Promise<Agent> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/approve`, { json: data ?? {} });
  }

  /** Suspend an active agent. */
  async suspendAgent(agentId: string, data?: { reason?: string }): Promise<Agent> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/suspend`, { json: data ?? {} });
  }

  /** Reactivate a suspended agent. */
  async reactivateAgent(agentId: string): Promise<Agent> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/reactivate`);
  }

  /** Permanently decommission an agent. */
  async decommissionAgent(agentId: string): Promise<Agent> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/decommission`);
  }

  // ── Tickets ──────────────────────────────────────────────────────────────

  /** Link a Jira / ServiceNow ticket to an agent record. */
  async linkTicket(agentId: string, data: TicketLink): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/tickets`, { json: data });
  }

  /** Validate a ticket exists in the external system. */
  async validateTicket(data: { system: string; ticket_id: string }): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/tickets/validate", { json: data });
  }

  /** Check a specific ticket by system and ID. */
  async checkTicket(system: string, ticketId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/tickets/validate/${sanitizePathParam(system)}/${sanitizePathParam(ticketId)}`);
  }

  /** Get ticket audit log. */
  async getTicketAudit(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/tickets/audit");
  }

  /** Clear ticket validation cache. */
  async clearTicketCache(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/tickets/cache/clear");
  }

  // ── Skills ───────────────────────────────────────────────────────────────

  /** List skills assigned to an agent. */
  async getAgentSkills(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/skills`);
  }

  /** Assign skills to an agent. */
  async assignSkills(agentId: string, data: { skills: string[] }): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/skills`, { json: data });
  }

  /** Remove a skill from an agent. */
  async removeSkill(agentId: string, skillId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/agents/${sanitizePathParam(agentId)}/skills/${sanitizePathParam(skillId)}`);
  }

  // ── Connected MCPs ───────────────────────────────────────────────────────

  /** List MCP servers connected to an agent. */
  async getConnectedMCPs(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/connected-mcps`);
  }

  /** Connect an agent to MCP servers. */
  async connectMCPs(agentId: string, data: { mcp_ids: string[] }): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/connected-mcps`, { json: data });
  }

  // ── Delegation ───────────────────────────────────────────────────────────

  /** Delegate permissions from one agent to another. */
  async delegate(agentId: string, data: DelegationRequest): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/delegate`, { json: data });
  }

  /** Get delegation chain for an agent. */
  async getDelegationChain(agentId: string): Promise<DelegationChain> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/delegation-chain`);
  }

  /** List delegates of an agent. */
  async getDelegates(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/delegates`);
  }

  /** Revoke delegation for an agent. */
  async revokeDelegation(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/agents/${sanitizePathParam(agentId)}/delegation`);
  }

  /** Validate a delegation request. */
  async validateDelegation(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/delegation/validate", { json: data });
  }

  // ── Audit ────────────────────────────────────────────────────────────────

  /** Get full audit trail for a specific agent. */
  async getAuditTrail(agentId: string): Promise<{ events: AuditEntry[] }> {
    return this.client.request("GET", `/api/v1/agents/${sanitizePathParam(agentId)}/audit`);
  }

  // ── Last Active ──────────────────────────────────────────────────────────

  /** Update last-active timestamp for an agent. */
  async updateLastActive(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/agents/${sanitizePathParam(agentId)}/last-active`);
  }

  // ── MCP Registration ─────────────────────────────────────────────────────

  /** Submit an MCP server declaration. */
  async declareMCP(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/mcp/declare", { json: data });
  }

  /** Register a new MCP server with declaration. */
  async registerMCP(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/mcp/register", { json: data });
  }

  /** Submit sandbox attestation for an MCP server. */
  async attestSandbox(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/mcp/sandbox/attest", { json: data });
  }

  /** Submit gate results for an MCP server. */
  async submitGates(mcpId: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/mcp/${sanitizePathParam(mcpId)}/gates`, { json: data });
  }

  /** Trigger auto-gate evaluation for an MCP server. */
  async evaluateGates(mcpId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/mcp/${sanitizePathParam(mcpId)}/gates/evaluate`);
  }

  /** Auto-apply passing gates for an MCP server. */
  async autoApplyGates(mcpId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/mcp/${sanitizePathParam(mcpId)}/gates/auto-apply`);
  }

  /** Get current gate evaluation status for an MCP server. */
  async getGateStatus(mcpId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/mcp/${sanitizePathParam(mcpId)}/gates/status`);
  }

  /** Get consumers of an MCP server. */
  async getMCPConsumers(mcpId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/mcp/${sanitizePathParam(mcpId)}/consumers`);
  }

  /** Get MCP registration tracks. */
  async getRegistrationTracks(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/mcp/registration-tracks");
  }

  /** Refresh consumer counts across all MCP servers. */
  async refreshConsumerCounts(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/mcp/refresh-consumer-counts");
  }

  /** Get tools registered for an MCP server. */
  async getMCPTools(mcpId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/api/v1/mcp/${sanitizePathParam(mcpId)}/tools`);
  }
}
