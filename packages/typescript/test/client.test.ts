import assert from "node:assert/strict";
import { test } from "node:test";
import { KSwitchClient } from "../src/index.js";

test("registerAgent sends the expected request", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ id: "agent-123" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const client = new KSwitchClient({
    baseUrl: "https://api.example.test",
    apiKey: "test-token",
    fetchImpl,
  });

  const result = await client.governance.registerAgent({
    display_name: "customer-onboarding-v1",
    record_type: "AGENT",
    risk_tier: "tier_2",
    owning_division: "Retail Banking",
    owning_team: "onboarding-platform",
  });

  assert.deepEqual(result, { id: "agent-123" });
  assert.equal(calls[0].url, "https://api.example.test/api/v1/agents/register");
  assert.equal(calls[0].init?.method, "POST");
  assert.equal((calls[0].init?.headers as Record<string, string>).authorization, "Bearer test-token");
  assert.equal(JSON.parse(String(calls[0].init?.body)).display_name, "customer-onboarding-v1");
});

test("audit events adds filters as query parameters", async () => {
  let requestedUrl = "";
  const fetchImpl: typeof fetch = async (input) => {
    requestedUrl = String(input);
    return new Response(JSON.stringify({ events: [] }), { status: 200 });
  };

  const client = new KSwitchClient({
    baseUrl: "https://api.example.test",
    apiKey: "test-token",
    fetchImpl,
  });

  await client.audit.events({ agent_id: "agent-123", event_type: "shadow_denied", limit: 25 });

  assert.equal(
    requestedUrl,
    "https://api.example.test/api/v1/audit/events?agent_id=agent-123&event_type=shadow_denied&limit=25",
  );
});

