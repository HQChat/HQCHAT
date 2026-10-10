import assert from "node:assert/strict";
import * as http from "node:http";
import { test } from "node:test";
import { createServerHandler } from "../../src/server/main";

function tagged(name: string): http.RequestListener {
  return (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ handledBy: name }));
  };
}

async function get(handler: http.RequestListener, method: string, path: string, headers: Record<string, string> = {}) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers });
    return { status: res.status, body: await res.json(), requestId: res.headers.get("x-request-id") };
  } finally {
    server.close();
  }
}

const handler = createServerHandler({
  auth: tagged("auth"),
  api: tagged("api"),
  brokerProblems: () => ["emqx.x: down"],
});

test("/health reports the version and the broker's problems", async () => {
  const r = await get(handler, "GET", "/health");
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
  assert.equal(typeof r.body.version, "string");
  assert.deepEqual(r.body.broker, ["emqx.x: down"]);
});

test("auth paths and the broker hooks go to the auth service", async () => {
  for (const path of ["/auth/init", "/auth/transport", "/mqtt/authn", "/mqtt/authn/internal"]) {
    assert.equal((await get(handler, "POST", path)).body.handledBy, "auth", path);
  }
});

test("everything else goes to the REST API", async () => {
  for (const path of ["/friends", "/info", "/peer/x/key", "/authx"]) {
    assert.equal((await get(handler, "GET", path)).body.handledBy, "api", path);
  }
});

test("every response carries a request id, the caller's when well-formed", async () => {
  for (const path of ["/health", "/auth/init", "/friends"]) {
    assert.match(String((await get(handler, "GET", path)).requestId), /^[0-9a-f-]{36}$/, path);
  }
  assert.equal((await get(handler, "GET", "/friends", { "x-request-id": "abc-123" })).requestId, "abc-123");
  assert.match(
    String((await get(handler, "GET", "/friends", { "x-request-id": "not a valid id" })).requestId),
    /^[0-9a-f-]{36}$/,
  );
});
