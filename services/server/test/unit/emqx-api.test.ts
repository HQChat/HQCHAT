import assert from "node:assert/strict";
import { test } from "node:test";
import { emqxApi, emqxApiConfigured } from "../../src/server/emqx";

const savedFetch = globalThis.fetch;
test.after(() => {
  globalThis.fetch = savedFetch;
});

function withEnv(env: Record<string, string | undefined>) {
  for (const k of ["EMQX_API_KEY", "EMQX_API_SECRET", "EMQX_API_URL"]) delete process.env[k];
  Object.assign(process.env, env);
}

test("without a key and secret the client is not configured and refuses to call", async () => {
  withEnv({ EMQX_API_KEY: "hqcat-svc" });
  assert.equal(emqxApiConfigured(), false);
  await assert.rejects(() => emqxApi("GET", "nodes"), /no EMQX API key/);
});

test("a call carries Basic auth, a JSON body and a timeout", async () => {
  withEnv({ EMQX_API_KEY: "hqcat-svc", EMQX_API_SECRET: "s3cret", EMQX_API_URL: "http://emqx.test:18083" });
  assert.equal(emqxApiConfigured(), true);
  let seen: { url: string; init: RequestInit } | null = null;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    seen = { url, init };
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  await emqxApi("POST", "publish", { topic: "u/x/graph" });
  const call = seen as unknown as { url: string; init: RequestInit };
  assert.equal(call.url, "http://emqx.test:18083/api/v5/publish");
  const headers = call.init.headers as Record<string, string>;
  assert.equal(headers.authorization, `Basic ${Buffer.from("hqcat-svc:s3cret").toString("base64")}`);
  assert.equal(headers["content-type"], "application/json");
  assert.equal(call.init.body, JSON.stringify({ topic: "u/x/graph" }));
  assert.ok(call.init.signal);
});
