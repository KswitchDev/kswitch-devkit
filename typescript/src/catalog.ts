import type { KSwitchClient } from "./client.js";
import type { Skill, SyncSource, Tool } from "./types.js";

/**
 * Skills catalog, tools catalog, sync sources, and registry sync.
 */
export class CatalogAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── Skills Catalog ───────────────────────────────────────────────────────

  /** List skills catalog entries. */
  async listSkills(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    category?: string;
  }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/skills-catalog", { params });
  }

  /** Get a specific skill by ID. */
  async getSkill(skillId: string): Promise<Skill> {
    return this.client.request("GET", `/api/v1/skills-catalog/${skillId}`);
  }

  /** Create a new skill catalog entry. */
  async createSkill(data: Partial<Skill>): Promise<Skill> {
    return this.client.request("POST", "/api/v1/skills-catalog", { json: data });
  }

  /** Delete a skill catalog entry. */
  async deleteSkill(skillId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/skills-catalog/${skillId}`);
  }

  /** Approve a pending skill. */
  async approveSkill(skillId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/skills-catalog/${skillId}/approve`);
  }

  /** Reject a pending skill. */
  async rejectSkill(skillId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/skills-catalog/${skillId}/reject`);
  }

  /** Autocomplete skills by name prefix. */
  async autocompleteSkills(params: { q: string }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/skills-catalog/autocomplete", { params });
  }

  // ── Tools Catalog ────────────────────────────────────────────────────────

  /** List tools catalog entries. */
  async listTools(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    mcp_server_id?: string;
  }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/tools-catalog", { params });
  }

  /** Get a specific tool by ID. */
  async getTool(toolId: string): Promise<Tool> {
    return this.client.request("GET", `/api/v1/tools-catalog/${toolId}`);
  }

  /** Create a new tool catalog entry. */
  async createTool(data: Partial<Tool>): Promise<Tool> {
    return this.client.request("POST", "/api/v1/tools-catalog", { json: data });
  }

  /** Delete a tool catalog entry. */
  async deleteTool(toolId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/tools-catalog/${toolId}`);
  }

  /** Approve a pending tool. */
  async approveTool(toolId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/tools-catalog/${toolId}/approve`);
  }

  /** Reject a pending tool. */
  async rejectTool(toolId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/tools-catalog/${toolId}/reject`);
  }

  /** Autocomplete tools by name prefix. */
  async autocompleteTools(params: { q: string }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/tools-catalog/autocomplete", { params });
  }

  /** Backfill tool metadata from connected MCP servers. */
  async backfillTools(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/tools-catalog/backfill");
  }

  /** Sync tools catalog from connected MCP servers. */
  async syncTools(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/tools-catalog/sync");
  }

  // ── Skills Inference ─────────────────────────────────────────────────────

  /** Analyse and infer skills for an agent or MCP. */
  async analyseSkills(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/skills-inference/analyse", { json: data });
  }

  // ── Sync Sources ─────────────────────────────────────────────────────────

  /** List all sync sources. */
  async listSyncSources(): Promise<{ sources: SyncSource[] }> {
    return this.client.request("GET", "/api/v1/sync-sources");
  }

  /** Add a new sync source. */
  async addSyncSource(data: Partial<SyncSource>): Promise<SyncSource> {
    return this.client.request("POST", "/api/v1/sync-sources", { json: data });
  }

  /** Delete a sync source. */
  async deleteSyncSource(sourceId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/sync-sources/${sourceId}`);
  }

  /** Trigger sync for a specific source. */
  async syncSource(sourceId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/sync-sources/${sourceId}/sync`);
  }

  /** Approve a pending sync source. */
  async approveSyncSource(sourceId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/sync-sources/${sourceId}/approve`);
  }

  /** Reject a pending sync source. */
  async rejectSyncSource(sourceId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/sync-sources/${sourceId}/reject`);
  }

  // ── Registry Sync ────────────────────────────────────────────────────────

  /** Trigger sync of all registry sources. */
  async triggerSync(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/registry-sync/trigger");
  }

  /** Sync skills from registry. */
  async syncSkills(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/registry-sync/skills");
  }

  /** Get registry sync status. */
  async getSyncStatus(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/registry-sync/status");
  }

  // ── Pending & Audit ──────────────────────────────────────────────────────

  /** Get all pending catalog items (skills, tools, sources). */
  async getPendingItems(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/pending-catalog");
  }

  /** Get catalog audit log. */
  async getAuditLog(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/catalog-audit");
  }
}
