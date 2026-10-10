// What the watchdog actually asks EMQX and Postgres, and how it reads the answer.
//
// The alert state machine is covered in broker-watch.test.ts. This is the other
// half — the half that produces the `Check`s it escalates — and it was entirely
// untested, which is how the bug recorded in the source got in:
//
//   `GET /authorization/sources` wraps its array in `{sources: [...]}`, unlike
//   `/authentication` which really does answer with a bare array. Reading it as
//   an array threw "authz is not iterable" on EVERY poll, so the one check that
//   exists to notice a broken topic ACL had never once reported on it — it
//   failed before it could look.
//
// That is a SHAPE CONTRACT with a piece of software this repo does not build,
// and the only thing that can hold it is a test that encodes both shapes. The
// consequence of it breaking is not a quiet gap: the watchdog that exists to
// say the ACL is wrong is the thing that crashed.
//
// `fetch` is stubbed, so nothing reaches a broker. `services/db/pg` is stubbed,
// so nothing reaches a database.

import assert from "node:assert/strict";
import Module from "node:module";
import { test } from "node:test";
import { setLogLevel } from "../../src/common/logger";

setLogLevel("debug");

// Read at import by ops/broker-watch, so they are set before the require below.
process.env.EMQX_API_URL = "http://emqx.test:18083";
process.env.EMQX_API_KEY = "hqcat-svc";
process.env.EMQX_API_SECRET = "test-secret";

// --- the database double ---------------------------------------------------------

const pgPath = require.resolve("../../src/server/db/pg");
const REAL_PG = require(pgPath); // captured before the stub displaces it

let pingResult: boolean | Error = true;
let sweepResult: Record<string, number> | Error = {};

const pgStub = {
  ...REAL_PG,
  async ping() {
    if (pingResult instanceof Error) throw pingResult;
    return pingResult;
  },
  async sweepExpired() {
    if (sweepResult instanceof Error) throw sweepResult;
    return sweepResult;
  },
};
{
  const m = new Module(pgPath, module);
  m.filename = pgPath;
  m.loaded = true;
  m.exports = pgStub;
  require.cache[pgPath] = m;
}

// --- the broker double ------------------------------------------------------------

interface Call {
  url: string;
  init: any;
}

let calls: Call[] = [];
/** path (after /api/v5/) -> the response to give. A function may vary by call. */
let routes: Record<string, any> = {};

const savedFetch = globalThis.fetch;

function reply(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

(globalThis as any).fetch = async (url: any, init: any) => {
  const u = String(url);
  calls.push({ url: u, init });
  const path = u.replace("http://emqx.test:18083/api/v5/", "");
  const route = routes[path];
  if (route === undefined) return reply(404, { error: `no route for ${path}` });
  return typeof route === "function" ? route(calls.length) : route;
};

test.after(() => {
  (globalThis as any).fetch = savedFetch;
});

const bw = require("../../src/server/watch") as typeof import("../../src/server/watch");

/** Healthy defaults; individual tests override one route at a time. */
function healthy() {
  calls = [];
  pingResult = true;
  sweepResult = {};
  routes = {
    nodes: reply(200, [{ node: "emqx@node1", node_status: "running", connections: 42 }]),
    authentication: reply(200, [{ mechanism: "password_based", backend: "http", enable: true, status: "connected" }]),
    "authorization/sources": reply(200, {
      sources: [{ type: "file", enable: true, status: "connected" }],
    }),
    "authorization/settings": reply(200, { no_match: "deny", deny_action: "ignore", cache: { enable: false } }),
    "configs/global_zone": reply(200, { mqtt: { wildcard_subscription: false } }),
  };
}

test.beforeEach(() => healthy());

const byName = (checks: bw_Check[], name: string) => checks.find((c) => c.name === name);
type bw_Check = import("../../src/server/watch").Check;

// --- the shape contract that broke ------------------------------------------------

test("the authorization sources are read out of their wrapper", async () => {
  // The bug, pinned. `/authorization/sources` answers `{sources: [...]}` and
  // `/authentication` answers a bare array — two endpoints on the same API with
  // two shapes.
  const checks = await bw.checkEmqx();
  const authz = byName(checks, "emqx.authz.file");
  assert.ok(authz, `no authz check produced; got ${checks.map((c) => c.name).join(", ")}`);
  assert.equal(authz!.ok, true);
});

test("a bare array from that endpoint is not silently accepted", async () => {
  // If EMQX ever unwraps it, the destructure yields undefined and defaults to
  // `[]` — which must read as "no authorization source configured", the loudest
  // check in the file, rather than as nothing at all.
  routes["authorization/sources"] = reply(200, [{ type: "file", enable: true, status: "connected" }]);
  const checks = await bw.checkEmqx();
  const authz = byName(checks, "emqx.authz");
  assert.ok(authz, "an unexpected shape must produce a check, not vanish");
  assert.equal(authz!.ok, false);
  assert.match(authz!.detail, /topic ACL is not enforced/);
});

test("no authorization source at all is the loudest thing this can say", async () => {
  // `no_match = deny` + `deny_action = disconnect`: with no source the ACL never
  // matches and every client that touches a topic is dropped.
  routes["authorization/sources"] = reply(200, { sources: [] });
  const authz = byName(await bw.checkEmqx(), "emqx.authz")!;
  assert.equal(authz.ok, false);
  assert.match(authz.detail, /no authorization source configured/);
});

test("no authenticator means the broker is admitting everyone", async () => {
  // The opposite failure and the more dangerous one: EMQX with an empty authn
  // chain accepts every CONNECT.
  routes.authentication = reply(200, []);
  const authn = byName(await bw.checkEmqx(), "emqx.authn")!;
  assert.equal(authn.ok, false);
  assert.match(authn.detail, /admitting everyone/);
});

// --- reading a link's health --------------------------------------------------------

test("a source with no status is healthy, and a disconnected one is not", async () => {
  // The built-in file authorizer and the built-in authn mechanisms hold no
  // connection and report no status. Treating a missing status as an outage
  // would alert permanently on a correctly configured broker.
  assert.equal(bw.linkOk({ enable: true }), true, "no status is not an outage");
  assert.equal(bw.linkOk({ enable: true, status: "connected" }), true);
  assert.equal(bw.linkOk({ enable: true, status: "disconnected" }), false);
  assert.equal(bw.linkOk({ enable: false }), false, "a disabled source is not healthy");
  assert.equal(
    bw.linkOk({ enable: false, status: "connected" }),
    false,
    "disabled wins over connected — it is not doing its job either way",
  );
  assert.equal(bw.linkOk({}), true, "neither field set is the built-in case");
});

test("per-node errors are flattened into the detail line", async () => {
  assert.equal(bw.nodeErrors({}), "");
  assert.equal(bw.nodeErrors({ node_error: [] }), "");
  assert.match(bw.nodeErrors({ node_error: ["connect timeout"] }), /connect timeout/);
  // Objects too — EMQX reports either, depending on the source.
  assert.match(bw.nodeErrors({ node_error: [{ node: "n1", error: "econnrefused" }] }), /econnrefused/);
  // Bounded: this ends up in a Sentry event title, and a node error can be a
  // whole Erlang term.
  const huge = bw.nodeErrors({ node_error: ["x".repeat(5000)] });
  assert.ok(huge.length < 320, `detail was ${huge.length} characters`);
});

test("a disconnected authorizer is reported unhealthy with its reason", async () => {
  routes["authorization/sources"] = reply(200, {
    sources: [{ type: "postgresql", enable: true, status: "disconnected", node_error: ["econnrefused"] }],
  });
  const authz = byName(await bw.checkEmqx(), "emqx.authz.postgresql")!;
  assert.equal(authz.ok, false);
  assert.match(authz.detail, /econnrefused/, "the reason is the whole diagnosis");
});

// --- the settings the static ACL rests on ---------------------------------------------

test("a healthy broker reports wildcards off and no_match = deny", async () => {
  const checks = await bw.checkEmqx();
  assert.equal(byName(checks, "emqx.wildcard_subscription")!.ok, true);
  assert.equal(byName(checks, "emqx.authz.no_match")!.ok, true);
  assert.equal(byName(checks, "emqx.authz"), undefined, "a loaded file source raises no source alarm");
  assert.ok(
    checks.every((c) => c.ok),
    JSON.stringify(checks.filter((c) => !c.ok)),
  );
});

test("wildcards ON is an alarm — it is the whole of the conversation ACL", async () => {
  // acl.conf allows `cv/+` to everyone. With wildcards on, a client filter
  // `cv/#` matches that rule and receives every conversation on the broker.
  routes["configs/global_zone"] = reply(200, { mqtt: { wildcard_subscription: true } });
  const c = byName(await bw.checkEmqx(), "emqx.wildcard_subscription")!;
  assert.equal(c.ok, false);
  assert.match(c.detail, /read every conversation/);
});

test("an unreadable wildcard setting is an alarm, not a pass", async () => {
  // Missing is not false. A broker whose API stopped answering this path has
  // stopped proving the one thing that matters.
  routes["configs/global_zone"] = reply(200, { mqtt: {} });
  assert.equal(byName(await bw.checkEmqx(), "emqx.wildcard_subscription")!.ok, false);
  delete routes["configs/global_zone"];
  const checks = await bw.checkEmqx();
  assert.equal(byName(checks, "emqx.wildcard_subscription")!.ok, false);
  assert.ok(byName(checks, "emqx.node.emqx@node1"), "one unanswered path must not sink the other checks");
});

test("no_match = allow is an alarm — it makes every rule moot", async () => {
  routes["authorization/settings"] = reply(200, { no_match: "allow" });
  assert.equal(byName(await bw.checkEmqx(), "emqx.authz.no_match")!.ok, false);
});

test("a broker enforcing something other than the file ACL is an alarm", async () => {
  // e.g. an old config that still names the Postgres source, and no file one.
  routes["authorization/sources"] = reply(200, {
    sources: [{ type: "postgresql", enable: true, status: "connected" }],
  });
  const c = byName(await bw.checkEmqx(), "emqx.authz")!;
  assert.equal(c.ok, false);
  assert.match(c.detail, /static file ACL is not loaded/);
});

// --- the nodes ------------------------------------------------------------------------

test("a node that is not running is unhealthy, and the count is reported", async () => {
  routes.nodes = reply(200, [
    { node: "emqx@node1", node_status: "running", connections: 7 },
    { node: "emqx@node2", node_status: "stopped", connections: 0 },
  ]);
  const checks = await bw.checkEmqx();
  assert.equal(byName(checks, "emqx.node.emqx@node1")!.ok, true);
  assert.match(byName(checks, "emqx.node.emqx@node1")!.detail, /7 connections/);
  assert.equal(byName(checks, "emqx.node.emqx@node2")!.ok, false);
});

// --- the dashboard token --------------------------------------------------------------

test("every call authenticates with the API key", async () => {
  await bw.checkEmqx();
  const expected = `Basic ${Buffer.from("hqcat-svc:test-secret").toString("base64")}`;
  assert.ok(calls.length > 0);
  for (const c of calls) assert.equal(c.init.headers.authorization, expected, c.url);
});

test("every call to the broker is bounded by a timeout", async () => {
  // The watchdog polls on an interval. A request with no deadline against a
  // hung broker stacks up one pending fetch per tick, forever.
  await bw.checkEmqx();
  for (const c of calls) {
    assert.ok(c.init.signal, `no AbortSignal on ${c.url}`);
  }
});

test("the API secret is never put in a URL", async () => {
  await bw.checkEmqx();
  for (const c of calls) assert.ok(!c.url.includes("test-secret"), c.url);
});

// --- Postgres --------------------------------------------------------------------------

test("a database that answers is healthy, and the latency is reported", async () => {
  pingResult = true;
  const c = await bw.checkPostgres();
  assert.equal(c.name, "postgres.ping");
  assert.equal(c.ok, true);
  assert.match(c.detail, /SELECT 1 in \d+ms/, "the latency is why this beats a boolean");
});

test("a database that is up but not answering is unhealthy", async () => {
  // `ping` resolving false rather than throwing: a pool that connects and
  // returns the wrong thing. This is the "up yet not answering" case the file's
  // header names, and it is the one a connection check misses.
  pingResult = false;
  assert.equal((await bw.checkPostgres()).ok, false);
});

test("a database error becomes a check, never a throw", async () => {
  // `tick` calls this FIRST and outside its own try. A throw here would skip
  // every EMQX check and the escalation for all of them.
  pingResult = new Error("connection terminated unexpectedly");
  const c = await bw.checkPostgres();
  assert.equal(c.ok, false);
  assert.match(c.detail, /connection terminated/);
});

// --- the sweep --------------------------------------------------------------------------

test("the sweeper never throws, whatever the database does", async () => {
  // It runs on its own interval with `void sweep()`. An unhandled rejection
  // there reaches the process handler and, on the crash path, would take the
  // watchdog down — the one process whose job is to still be alive.
  sweepResult = new Error("deadlock detected");
  await bw.sweep(); // must not reject
  sweepResult = { sessions: 3, nonces: 11 };
  await bw.sweep();
  sweepResult = {};
  await bw.sweep();
});

// --- one poll, end to end ------------------------------------------------------------------

test("a poll escalates what it found and the status reports it", async () => {
  routes["authorization/sources"] = reply(200, {
    sources: [{ type: "postgresql", enable: true, status: "disconnected" }],
  });
  await bw.tick();

  const found = bw.lastChecks();
  assert.ok(found.length >= 4, `expected a check per subsystem, got ${found.length}`);
  assert.equal(byName(found, "emqx.authz.postgresql")!.ok, false);

  const status = bw.watchStatus();
  assert.ok(
    status.unhealthy.some((u) => /emqx\.authz\.postgresql/.test(u)),
    JSON.stringify(status),
  );
  assert.ok(status.lastRunAgoMs !== null && status.lastRunAgoMs < 60_000);
});

test("an unreachable broker is itself the alert", async () => {
  // Not a silent gap: if the API cannot be reached the watchdog has no idea
  // whether the broker is healthy, and that is exactly what it must say.
  routes.nodes = reply(500, { error: "internal" });
  await bw.tick();
  const api = bw.lastChecks().find((c) => c.name === "emqx.api");
  assert.ok(
    api,
    `expected an emqx.api check; got ${bw
      .lastChecks()
      .map((c) => c.name)
      .join(", ")}`,
  );
  assert.equal(api!.ok, false);
  // Postgres is still checked — one dependency being down must not hide another.
  assert.ok(bw.lastChecks().some((c) => c.name === "postgres.ping"));
});

// --- helpers ---------------------------------------------------------------------------------
