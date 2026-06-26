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

describe("KSwitchClient base URL handling", () => {
  it("trims repeated trailing slashes without a regular expression", () => {
    const client = readSource("src/client.ts");

    assert.ok(
      client.includes("function trimTrailingSlashes(value: string): string"),
      "expected deterministic base URL trimming helper",
    );
    assert.ok(
      client.includes("this.baseUrl = trimTrailingSlashes(config.baseUrl);"),
      "expected constructor to normalize baseUrl with helper",
    );
    assert.ok(
      !client.includes('config.baseUrl.replace(/\\/+$/, "")'),
      "baseUrl normalization must not use the CodeQL-flagged regex",
    );
  });
});
