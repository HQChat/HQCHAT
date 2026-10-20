// Production settings the server refuses to start without. Each case boots
// `assertConfig` in a process of its own, because a refusal is an exit.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { test } from "node:test";

const BOOT = path.join(__dirname, "..", "helpers", "assert-config-boot.ts");

function boot(env: Record<string, string>, needs: string[]): { code: number; out: string } {
  const r = spawnSync(process.execPath, ["--import", "tsx", BOOT], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      DATABASE_URL: "postgres://x@localhost/x",
      ENV_FILE: "/nonexistent/.env",
      __NEEDS__: JSON.stringify(needs),
      ...env,
    },
  });
  return { code: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
}

// Behind nginx every request comes from 127.0.0.1; with no header trusted,
// every per-address limit would be one limit shared by everybody.
test("production needs TRUSTED_PROXY", () => {
  const missing = boot({ NODE_ENV: "production" }, ["proxy"]);
  assert.notEqual(missing.code, 0, missing.out);
  assert.match(missing.out, /TRUSTED_PROXY is required/);

  const set = boot({ NODE_ENV: "production", TRUSTED_PROXY: "x-real-ip" }, ["proxy"]);
  assert.equal(set.code, 0, set.out);
});

test("outside production TRUSTED_PROXY may be unset, but never misspelt", () => {
  assert.equal(boot({}, ["proxy"]).code, 0);
  const typo = boot({ TRUSTED_PROXY: "x-realip" }, ["proxy"]);
  assert.notEqual(typo.code, 0, typo.out);
  assert.match(typo.out, /not one of/);
});
