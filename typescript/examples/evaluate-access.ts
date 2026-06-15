/**
 * Example: Evaluate access decisions using AuthZen and Cedar policies.
 *
 * Usage:
 *   npx tsx examples/evaluate-access.ts
 */

import { KSwitchClient, type AuthZenEvaluationRequest } from "../src/index.js";

async function main() {
  const client = new KSwitchClient({
    baseUrl: process.env.KSWITCH_BASE_URL ?? "http://localhost:5001",
    token: process.env.KSWITCH_AUTH_TOKEN,
  });

  // 1. Single AuthZen evaluation
  const request: AuthZenEvaluationRequest = {
    subject: {
      type: "agent",
      id: "agent-analytics-001",
      properties: { risk_tier: "tier_2", division: "engineering" },
    },
    resource: {
      type: "mcp_tool",
      id: "postgres-query",
      properties: { mcp_server: "mcp-postgres-readonly" },
    },
    action: {
      name: "invoke",
    },
  };

  const result = await client.authzen.evaluate(request);
  console.log("AuthZen decision:", result.decision);
  console.log("Context:", result.context);

  // 2. Batch evaluation
  const batchResult = await client.authzen.evaluateBatch({
    evaluations: [
      request,
      {
        subject: { type: "agent", id: "agent-analytics-001" },
        resource: { type: "mcp_tool", id: "s3-write" },
        action: { name: "invoke" },
      },
    ],
  });
  console.log("Batch results:", batchResult.evaluations);

  // 3. Cedar policy evaluation
  const policyDecision = await client.policy.evaluate({
    principal: "Agent::\"agent-analytics-001\"",
    action: "Action::\"invoke_tool\"",
    resource: "MCPTool::\"postgres-query\"",
    context: { environment: "production" },
  });
  console.log("Policy decision:", policyDecision.decision);

  // 4. Search for accessible resources
  const resources = await client.authzen.searchResources({
    subject: { type: "agent", id: "agent-analytics-001" },
    action: { name: "invoke" },
  });
  console.log("Accessible resources:", resources);
}

main().catch(console.error);
