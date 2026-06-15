import type { KSwitchClient } from "./client.js";
import type { EventStats, GovernanceEvent } from "./types.js";

/**
 * Governance event outbox: event listing, stats, replay, and fleet events.
 */
export class EventsAPI {
  constructor(private readonly client: KSwitchClient) {}

  // ── Events ───────────────────────────────────────────────────────────────

  /** Get governance events with optional filtering. */
  async list(params?: {
    status?: string;
    event_type?: string;
    limit?: number;
    page?: number;
    page_size?: number;
  }): Promise<{ events: GovernanceEvent[] }> {
    return this.client.request("GET", "/api/v1/events", { params });
  }

  /** Get a specific event by ID. */
  async get(eventId: string): Promise<GovernanceEvent> {
    return this.client.request("GET", `/api/v1/events/${eventId}`);
  }

  /** Get event outbox delivery statistics. */
  async getStats(): Promise<EventStats> {
    return this.client.request("GET", "/api/v1/events/stats");
  }

  /** Replay dead letter events. */
  async replayDeadLetters(): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/events/replay-dead-letters");
  }

  /** Replay a specific event. */
  async replay(eventId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/api/v1/events/${eventId}/replay`);
  }

  // ── Fleet Events ─────────────────────────────────────────────────────────

  /** Publish a fleet event. */
  async publishFleetEvent(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/fleet/events", { json: data });
  }

  /** List fleet events. */
  async listFleetEvents(params?: {
    limit?: number;
    event_type?: string;
  }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/fleet/events", { params });
  }

  /** Get fleet event statistics. */
  async getFleetStats(): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/fleet/events/stats");
  }

  /** Export fleet events. */
  async exportFleetEvents(params?: {
    format?: string;
  }): Promise<Record<string, unknown>> {
    return this.client.request("GET", "/api/v1/fleet/events/export", { params });
  }

  // ── Maintenance ──────────────────────────────────────────────────────────

  /** Run maintenance cleanup of old policy evaluations and events. */
  async runCleanup(data?: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/api/v1/maintenance/cleanup", { json: data ?? {} });
  }
}
