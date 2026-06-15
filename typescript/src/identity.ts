import type { KSwitchClient } from "./client.js";
import type {
  IdentityStats,
  ServiceIdentity,
  SpiffeIdentity,
  TrustDomain,
} from "./types.js";

/**
 * Identity management: SPIFFE/SVID, service identities, trust domains, rotation.
 */
export class IdentityAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── SPIFFE ───────────────────────────────────────────────────────────────

  /** Get SPIFFE identity details for an agent. */
  async getSpiffe(agentId: string): Promise<SpiffeIdentity> {
    return this.client.request("GET", `/api/v1/agents/${agentId}/spiffe`);
  }

  /** Create a SPIFFE identity for an agent. */
  async createSpiffe(agentId: string, data?: Record<string, unknown>): Promise<SpiffeIdentity> {
    return this.client.request("POST", `/api/v1/agents/${agentId}/spiffe`, { json: data ?? {} });
  }

  /** Rotate an agent's SPIFFE SVID. */
  async rotateSpiffe(agentId: string): Promise<SpiffeIdentity> {
    return this.client.request("PATCH", `/api/v1/agents/${agentId}/spiffe`);
  }

  /** Revoke an agent's SPIFFE identity. */
  async revokeSpiffe(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/agents/${agentId}/spiffe`);
  }

  // ── Service Identities ───────────────────────────────────────────────────

  /** List service identities for an agent. */
  async listIdentities(agentId: string): Promise<{ identities: ServiceIdentity[] }> {
    return this.client.request("GET", `/api/v1/agents/${agentId}/identities`);
  }

  /** Create a service identity for an agent. */
  async createIdentity(agentId: string, data: Partial<ServiceIdentity>): Promise<ServiceIdentity> {
    return this.client.request("POST", `/api/v1/agents/${agentId}/identities`, { json: data });
  }

  /** Update a service identity. */
  async updateIdentity(
    agentId: string,
    identityId: string,
    data: Partial<ServiceIdentity>,
  ): Promise<ServiceIdentity> {
    return this.client.request("PATCH", `/api/v1/agents/${agentId}/identities/${identityId}`, {
      json: data,
    });
  }

  /** Delete a service identity. */
  async deleteIdentity(agentId: string, identityId: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/agents/${agentId}/identities/${identityId}`);
  }

  // ── Identity Stats ───────────────────────────────────────────────────────

  /** Get identity statistics (total, active, expiring, revoked). */
  async getStats(): Promise<IdentityStats> {
    return this.client.request("GET", "/api/v1/identities/stats");
  }

  /** Get identities expiring within N days. */
  async getExpiring(days: number = 30): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/identities/expiring", { params: { days } });
  }

  /** List all SPIFFE identities. */
  async listAllSpiffe(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/identities/spiffe");
  }

  // ── Rotation ─────────────────────────────────────────────────────────────

  /** Get identity rotation scheduler status. */
  async getRotationStatus(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/identities/rotation-status");
  }

  /** Trigger rotation for all eligible identities. */
  async rotateAll(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/identities/rotate-all");
  }

  // ── Trust Domains ────────────────────────────────────────────────────────

  /** List all configured trust domains. */
  async listTrustDomains(): Promise<{ trust_domains: TrustDomain[] }> {
    return this.client.request("GET", "/api/v1/trust-domains");
  }

  /** Create a new trust domain. */
  async createTrustDomain(data: Partial<TrustDomain>): Promise<TrustDomain> {
    return this.client.request("POST", "/api/v1/trust-domains", { json: data });
  }

  /** Get a specific trust domain. */
  async getTrustDomain(domainName: string): Promise<TrustDomain> {
    return this.client.request("GET", `/api/v1/trust-domains/${domainName}`);
  }

  /** Update a trust domain. */
  async updateTrustDomain(domainName: string, data: Partial<TrustDomain>): Promise<TrustDomain> {
    return this.client.request("PATCH", `/api/v1/trust-domains/${domainName}`, { json: data });
  }

  /** Delete a trust domain. */
  async deleteTrustDomain(domainName: string): Promise<Record<string, unknown>> {
    return this.client.request("DELETE", `/api/v1/trust-domains/${domainName}`);
  }

  // ── WIMSE ────────────────────────────────────────────────────────────────

  /** Get WIMSE threat model. */
  async getWIMSEThreatModel(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/wimse/threat-model");
  }
}
