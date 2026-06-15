import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sdkRoot = join(here, "..");

function readSource(path: string): string {
  return readFileSync(join(sdkRoot, path), "utf8");
}

describe("B005 service SDK contract", () => {
  it("defines the same governed service paths as kswitch_service MCP", () => {
    const service = readSource("src/service.ts");

    assert.match(service, /SERVICE_BASE = "\/api\/v1\/b005\/service"/);
    for (const suffix of ["/fetch", "/search", "/policy_check", "/policy", "/health"]) {
      assert.ok(service.includes("`${SERVICE_BASE}" + suffix + "`"), `missing ${suffix}`);
    }
    for (const method of ["fetch(", "search(", "policyCheck(", "getPolicy(", "health("]) {
      assert.ok(service.includes(method), `missing method ${method}`);
    }
  });

  it("wires the service namespace into the TypeScript client and public exports", () => {
    const client = readSource("src/client.ts");
    const index = readSource("src/index.ts");

    assert.match(client, /readonly service: ServiceAPI;/);
    assert.match(client, /this\.service = new ServiceAPI\(this\);/);
    assert.match(index, /export \{ ServiceAPI, SERVICE_BASE \} from "\.\/service\.js";/);
    assert.match(index, /export type \{ FetchRequest, PolicyCheckRequest, SearchRequest \} from "\.\/service\.js";/);
  });
});
