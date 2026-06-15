/**
 * Example: Register a new AI agent with KSwitch governance.
 *
 * Usage:
 *   npx tsx examples/register-agent.ts
 */

import { KSwitchClient } from "../src/index.js";

async function main() {
  const client = new KSwitchClient({
    baseUrl: process.env.KSWITCH_BASE_URL ?? "http://localhost:5001",
    clientId: process.env.KSWITCH_CLIENT_ID,
    clientSecret: process.env.KSWITCH_CLIENT_SECRET,
    keycloakUrl: process.env.KEYCLOAK_ENDPOINT,
    keycloakRealm: process.env.KEYCLOAK_REALM ?? "kswitch",
  });

  // 1. Check health
  const health = await client.healthCheck();
  console.log("KSwitch health:", health.status);

  // 2. Register a new agent
  const agent = await client.governance.registerAgent({
    display_name: "My Analytics Agent",
    record_type: "AGENT",
    risk_tier: "tier_2",
    owning_division: "Engineering",
    owning_team: "Data Platform",
    description: "Analyses customer data and generates reports",
    environment: "production",
    framework: "langchain",
  });
  console.log("Registered agent:", agent.id, agent.display_name);

  // 3. Assign skills
  await client.governance.assignSkills(agent.id, {
    skills: ["data-analysis", "report-generation", "sql-query"],
  });
  console.log("Skills assigned");

  // 4. Connect to MCP servers
  await client.governance.connectMCPs(agent.id, {
    mcp_ids: ["mcp-postgres-readonly", "mcp-s3-reports"],
  });
  console.log("MCP servers connected");

  // 5. Evaluate toxic combos
  const toxicResult = await client.compliance.evaluateAgent(agent.id);
  if (toxicResult.violations.length > 0) {
    console.warn("Toxic combo violations found:", toxicResult.violations);
  } else {
    console.log("No toxic combo violations");
  }

  // 6. Get approval criteria
  const criteria = await client.governance.getApprovalCriteria(agent.id);
  console.log("Approval criteria:", criteria);
}

main().catch(console.error);
