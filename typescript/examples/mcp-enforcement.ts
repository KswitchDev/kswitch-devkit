/**
 * Example: Governed MCP tool invocation via KSwitchInterceptor.
 *
 * This is the SUPPORTED production pattern for gating MCP tool calls through
 * KSwitch governance policies. It uses the governed invocation path:
 *
 *   KSwitchInterceptor.checkAndInvoke() → local PDP → enforce → tool → output filter → audit
 *
 * The old pattern (client.enforcement.enforceMCPCall()) is deprecated and does
 * NOT provide local-PDP evaluation, bypass prevention, output filtering, or
 * obligation blocking. Use KSwitchInterceptor.checkAndInvoke() instead.
 *
 * Usage:
 *   npx tsx examples/mcp-enforcement.ts
 */

import {
  KSwitchClient,
  KSwitchInterceptor,
  KSwitchEnforcementError,
  KSwitchObligationError,
  OutputDeniedError,
  LocalPDPEvaluator,
} from "../src/index.js";

// ── Simulated MCP tool implementations ────────────────────────────────────────

async function readRecords(table: string, limit = 10): Promise<object> {
  return { records: Array.from({ length: limit }, (_, i) => ({ id: i, table })) };
}

async function deleteRecords(table: string, ids: number[]): Promise<object> {
  return { deleted: ids.length, table };
}

// ── Governed invocation (supported path) ──────────────────────────────────────

async function main() {
  const client = new KSwitchClient({
    baseUrl: process.env.KSWITCH_BASE_URL ?? "http://localhost:5001",
    clientId: process.env.KSWITCH_CLIENT_ID,
    clientSecret: process.env.KSWITCH_CLIENT_SECRET,
    keycloakUrl: process.env.KEYCLOAK_ENDPOINT,
  });

  // Create the interceptor with optional local PDP for in-process enforcement.
  // The interceptor is the primary governed invocation surface for TypeScript.
  const evaluator = new LocalPDPEvaluator();
  const interceptor = new KSwitchInterceptor(client, {
    localPDP: evaluator,
  });

  const agentId = "agent:fraud-detector@bank.internal";
  const mcpServerId = "mcp:database@bank.internal";

  console.log("Checking tool call authorizations via governed interceptor\n");

  // ── Governed invocations ───────────────────────────────────────────────────
  // checkAndInvoke() is the ONLY supported production path.
  // Local PDP evaluate → enforce → output filter → audit is automatic.

  const calls: Array<{ toolName: string; toolFn: (...args: any[]) => Promise<any>; args: object }> = [
    { toolName: "read_records", toolFn: readRecords, args: { table: "customers", limit: 10 } },
    { toolName: "delete_records", toolFn: deleteRecords, args: { table: "customers", ids: [1, 2, 3] } },
  ];

  for (const { toolName, toolFn, args } of calls) {
    console.log(`Invoking ${toolName}...`);
    try {
      const result = await interceptor.checkAndInvoke({
        agentId,
        mcpServerId,
        toolName,
        toolFn: () => (toolFn as any)(...Object.values(args)),
      });
      console.log(`  ALLOWED — result:`, result);
    } catch (err) {
      if (err instanceof KSwitchEnforcementError) {
        console.warn(`  DENIED — reason: ${err.reason}`);
      } else if (err instanceof KSwitchObligationError) {
        console.warn(`  BLOCKED (obligation) — reason: ${err.reason}`);
      } else if (err instanceof OutputDeniedError) {
        console.warn(`  OUTPUT DENIED — policy prevents export of this result`);
      } else {
        throw err;
      }
    }
    console.log();
  }
}

main().catch(console.error);
