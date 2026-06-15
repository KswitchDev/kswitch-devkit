import type { KSwitchClient } from "./client.js";
import type { MCPCallEnforcementRequest, MCPCallEnforcementResponse } from "./types.js";

/** Result from the obligation-report endpoint. */
export interface ObligationReportResult {
  enforcement_id: string;
  obligations_met: string[];
  obligations_tracked: boolean;
  valid: boolean;
  unknown_obligations: string[];
  missing_obligations: string[];
  message: string;
  tracked_at: string;
}

/**
 * Runtime enforcement: MCP call gating and inline policy checks.
 */
export class EnforcementAPI {
  constructor(private readonly client: KSwitchClient) {}

  /**
   * Enforce an MCP tool call.
   *
   * Call this before allowing an agent to invoke an MCP tool.
   * Returns whether the call is allowed based on governance policies,
   * kill switch state, and toxic combo rules.
   */
  async enforceMCPCall(data: MCPCallEnforcementRequest): Promise<MCPCallEnforcementResponse> {
    return this.client.request("POST", "/api/v1/enforce/mcp-call", { json: data });
  }

  /**
   * Report fulfilled obligations for a prior ALLOW decision (PR-05).
   *
   * @param enforcementId - The ID returned in the enforcement decision.
   * @param obligationsMet - Obligation type strings fulfilled by the caller.
   */
  async reportObligations(
    enforcementId: string,
    obligationsMet: string[],
  ): Promise<ObligationReportResult> {
    return this.client.request("POST", "/api/v1/enforce/obligation-report", {
      json: { enforcement_id: enforcementId, obligations_met: obligationsMet },
    });
  }
}
