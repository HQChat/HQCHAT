// The app-API's routes, driven through the real handler.
//
// Twenty routes, none of which had a test — `api/main.ts` built its server and
// called `listen()` at import time, so loading the module opened a socket and no
// test could hold it. What went untested includes the friend-graph mutations
// that maintain the MQTT topic ACL, the prekey claim, and account deletion.
//
// The emphasis here is on the REFUSALS. A route that returns the right thing to
// the right caller is the easy half; the half that matters is what it does for a
// caller who should not be there, and that is what nothing was checking.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { createApiHandler } from "../../src/server/api";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { call as request } from "../helpers/http";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

// --- harness ---------------------------------------------------------------

const call = (method: string, path: string, opts: { body?: unknown; token?: string } = {}) =>
  request(createApiHandler(), method, path, opts);

const someId = () => crypto.randomBytes(32).toString("hex");

/** A caller with a live session. */
async function user() {
  const id = someId();
  const token = await DB.mintSessionToken(id);
  return { id, token };
}

// --- unauthenticated ---------------------------------------------------------

// The one route that is deliberately open. Its safety is not access control but
// the commitment: the caller checks sha256(hex(key)) == id before pinning, so
// this server cannot substitute a key even for itself.
test("GET /peer/:id/key shape-checks the id before touching the database", async () => {
  for (const bad of ["nothex", "ab", `${"AB".repeat(32)}zz`, "%20"]) {
    const r = await call("GET", `/peer/${bad}/key`);
    assert.equal(r.status, 400, bad);
    assert.equal(r.body.error, "INVALID_FIELD");
  }
});

test("GET /peer/:id/key answers a malformed %-escape with a 400, not a 500", async () => {
  for (const bad of ["%E0%A4%A", "%", "%zz"]) {
    const r = await call("GET", `/peer/${bad}/key`);
    assert.equal(r.status, 400, `${bad}: ${r.text}`);
    assert.equal(r.body.error, "INVALID_FIELD");
  }
});

test("GET /peer/:id/key is a 404 for a malformed path", async () => {
  assert.equal((await call("GET", "/peer//key")).status, 404);
  assert.equal((await call("GET", `/peer/${someId()}`)).status, 404);
});

// --- EVERY mutating route requires a session ---------------------------------
//
// The table is the test. Adding a route without an auth check should be visible
// as a missing row, not discovered later.

const AUTHENTICATED: Array<[string, string, unknown?]> = [
  ["GET", "/friends"],
  ["GET", "/friends/invites"],
  // The field names are the route's OWN — `to` for an invite, `from` for an
  // accept, `peer` for the rest. A 401 lands before the body is read, so a wrong
  // name here still passes the auth test while quietly making every other test
  // that copies this row vacuous. It did: see the two below.
  ["POST", "/friends/invite", { to: "someone" }],
  ["POST", "/friends/accept", { from: "someone" }],
  ["POST", "/friends/cancel", { peer: "someone" }],
  ["POST", "/friends/remove", { peer: "someone" }],
  ["POST", "/friends/block", { peer: "someone" }],
  ["POST", "/friends/unblock", { peer: "someone" }],
  ["GET", "/friends/blocked"],
  ["POST", "/report", { conversation: "ab".repeat(32), peer: "someone", category: "spam" }],
  ["POST", "/username", { username: "someone" }],
  ["POST", "/prekeys/claim", { peer: "someone" }],
  ["GET", "/prekeys/count"],
  ["POST", "/push/token", { token: "abc", platform: "ios" }],
  ["POST", "/account/delete", {}],
];

test("every mutating route refuses a caller with no session", async () => {
  for (const [method, path, body] of AUTHENTICATED) {
    const r = await call(method, path, { body });
    assert.equal(r.status, 401, `${method} ${path} without a bearer`);
    assert.equal(r.body.error, "unauthenticated", `${method} ${path}`);
  }
});

test("…and a caller holding a token that resolves to nothing", async () => {
  const bogus = crypto.randomBytes(32).toString("hex");
  for (const [method, path, body] of AUTHENTICATED) {
    const r = await call(method, path, { body, token: bogus });
    assert.equal(r.status, 401, `${method} ${path} with an unknown bearer`);
  }
});

// --- the friend graph, which is also the topic ACL ---------------------------

// ⚠️ These three sent `peer`, and the invite/accept routes read `to` and `from`.
// So all three were refused at field validation with a 400 and NEVER REACHED the
// logic they are named after — three green tests asserting "not 200" about a
// route that had not run. Corrected here; the invite route's own error mapping
// was wrong underneath them, which is what a real call finally showed.
test("an invite to somebody who does not exist is refused, not silently accepted", async () => {
  const me = await user();
  const r = await call("POST", "/friends/invite", { body: { to: someId() }, token: me.token });
  // 404, specifically. It was a 500 — a plain Error out of DB.invite, caught by
  // the route's catch-all — so an ordinary typo produced a Sentry event and an
  // "internal error" in the app. It also has to be the SAME refusal a blocked
  // invite gets, or the status tells the blocked party they were blocked.
  assert.equal(r.status, 404, `got ${r.status} ${r.text}`);
  assert.equal(r.body.error, "NOT_FOUND");
});

test("you cannot invite yourself", async () => {
  const me = await user();
  const r = await call("POST", "/friends/invite", { body: { to: me.id }, token: me.token });
  assert.equal(r.status, 400, "a self-invite would grant a conversation topic with nobody on it");
  assert.equal(r.body.error, "SELF_INVITE");
});

test("accepting an invite that was never sent does not create a friendship", async () => {
  const me = await user();
  const stranger = await user();
  const r = await call("POST", "/friends/accept", { body: { from: stranger.id }, token: me.token });
  assert.notEqual(r.status, 200, "an unsolicited accept must not grant the topic ACL");
  assert.equal(await DB.areFriends(me.id, stranger.id), false, "…and no friendship exists afterwards");
});

test("a malformed peer field is a 400, not a 500", async () => {
  const me = await user();
  for (const body of [{}, { peer: 1 }, { peer: null }, { peer: "" }, { peer: {} }, { peer: "x".repeat(200) }]) {
    const r = await call("POST", "/friends/invite", { body, token: me.token });
    assert.equal(r.status, 400, JSON.stringify(body));
  }
});

// --- prekeys -----------------------------------------------------------------

test("claiming a prekey from someone you are not friends with is refused", async () => {
  const me = await user();
  const victim = await user();
  // Friendship is the authorization here: without it anyone with a session could
  // drain a stranger's one-time pool, forcing every future conversation of
  // theirs onto the reusable medium-term key.
  const r = await call("POST", "/prekeys/claim", { body: { peer: victim.id }, token: me.token });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "NOT_FRIENDS");
});

test("/prekeys/count only ever reports the caller's own pool", async () => {
  const me = await user();
  const r = await call("GET", "/prekeys/count", { token: me.token });
  assert.equal(r.status, 200);
  assert.equal(typeof r.body.remaining, "number");
  // There is no parameter to point it at anyone else, and the route is matched
  // EXACTLY (`url === "/prekeys/count"`), so a query string does not reach it at
  // all — it 404s rather than being parsed and ignored. Stricter than necessary
  // and worth pinning: adding a `?id=` convenience here would leak how deep a
  // peer's one-time pool is, which is how an attacker would know when draining
  // it had worked.
  const other = await user();
  const probe = await call("GET", `/prekeys/count?id=${other.id}`, { token: me.token });
  assert.equal(probe.status, 404, "a query string does not reach this route");
});

// --- directory ---------------------------------------------------------------

test("GET /users answers only exact usernames, and never enumerates", async () => {
  const r = await call("GET", "/users?username=");
  assert.equal(r.status, 200);
  assert.equal(r.body.id, null, "an empty query resolves to nobody");

  const missing = await call("GET", `/users?username=definitely-not-taken-${crypto.randomBytes(4).toString("hex")}`);
  assert.equal(missing.body.id, null);
  // The response shape is {username, id} — no list, no count, nothing that grows
  // with the size of the directory.
  assert.deepEqual(Object.keys(missing.body).sort(), ["id", "username"]);
});

test.after(async () => {
  await closePg();
});

test("a push token must be an APNs device token", async () => {
  // It is interpolated into the :path of the request sent to Apple.
  const me = await user();
  for (const token of [
    `abc/../../x?y#z${"a".repeat(60)}`,
    "g".repeat(64),
    "a".repeat(63),
    "a".repeat(201),
    "a b".repeat(30),
  ]) {
    const r = await call("POST", "/push/token", {
      body: { platform: "ios", environment: "production", token },
      token: me.token,
    });
    assert.equal(r.status, 400, `${token.slice(0, 20)}: ${r.text}`);
  }
  for (const [platform, environment] of [
    ["android", "production"],
    ["ios", "development"],
  ]) {
    const r = await call("POST", "/push/token", {
      body: { platform, environment, token: "ab".repeat(32) },
      token: me.token,
    });
    assert.equal(r.status, 400, `${platform}/${environment}`);
  }
  const ok = await call("POST", "/push/token", {
    body: { platform: "ios", environment: "sandbox", token: "AB".repeat(32) },
    token: me.token,
  });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await DB.getPushToken(me.id))?.token, "ab".repeat(32), "stored lowercase");
  await q(`DELETE FROM push_tokens WHERE id = $1`, [me.id]);
});
