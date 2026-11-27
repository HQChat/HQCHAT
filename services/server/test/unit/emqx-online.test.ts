import assert from "node:assert/strict";
import { test } from "node:test";
import { setLogLevel } from "../../src/common/logger";
import { EMQX } from "../../src/server/emqx";

setLogLevel("silent");

const savedFetch = globalThis.fetch;
test.after(() => {
  globalThis.fetch = savedFetch;
});

function configure(on: boolean) {
  for (const k of ["EMQX_API_KEY", "EMQX_API_SECRET", "EMQX_API_URL"]) delete process.env[k];
  if (on)
    Object.assign(process.env, { EMQX_API_KEY: "hqcat-svc", EMQX_API_SECRET: "s", EMQX_API_URL: "http://emqx.test" });
}

const id = (c: string) => c.repeat(64);

/** Serves `pages` in order; a number is a status for that page. */
function broker(pages: Array<string[] | number>) {
  const asked: string[] = [];
  globalThis.fetch = (async (url: string) => {
    asked.push(url);
    const page = Number(new URL(url).searchParams.get("page"));
    const p = pages[page - 1];
    if (typeof p === "number") return new Response("{}", { status: p });
    return new Response(
      JSON.stringify({
        data: (p ?? []).map((clientid) => ({ clientid })),
        meta: { page, hasnext: page < pages.length },
      }),
      { status: 200 },
    );
  }) as typeof fetch;
  return asked;
}

test("counts accounts across pages, leaving out services, the bot and the sims", async () => {
  configure(true);
  const asked = broker([
    [id("a"), id("b"), "svc-internal", id("f")],
    [id("c"), id("a")],
  ]);
  const n = await EMQX.onlineCount(new Set([id("f"), id("c")]));
  assert.equal(n, 2); // a and b; a counted once
  assert.equal(asked.length, 2);
  assert.match(asked[0]!, /\/api\/v5\/clients\?page=1&limit=1000&fields=clientid$/);
});

test("no number rather than a wrong one when a page fails", async () => {
  configure(true);
  broker([[id("a")], 500]);
  assert.equal(await EMQX.onlineCount(new Set()), null);
});

test("no number without an API key, and no call", async () => {
  configure(false);
  const asked = broker([[id("a")]]);
  assert.equal(await EMQX.onlineCount(new Set()), null);
  assert.equal(asked.length, 0);
});

test("a body without a data array is refused", async () => {
  configure(true);
  globalThis.fetch = (async () => new Response(JSON.stringify({ meta: {} }), { status: 200 })) as typeof fetch;
  assert.equal(await EMQX.onlineCount(new Set()), null);
});
