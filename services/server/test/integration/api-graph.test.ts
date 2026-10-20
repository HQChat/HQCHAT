// The friend graph, the prekey pool and account deletion: the routes that
// decide who may read what.
//
// EMQX is stubbed and its calls recorded, because on these routes the broker
// call is the behaviour: `/friends/remove` that updates the database but fails
// to revoke the topic leaves the removed peer's subscription delivering. The
// database is real.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import Module from "node:module";
import { test } from "node:test";
import { setLogLevel } from "../../src/common/logger";
import { q } from "../../src/server/db/pg";
import { call as request } from "../helpers/http";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

setLogLevel("silent");

// --- the broker double ------------------------------------------------------------

interface EmqxCall {
  fn: string;
  args: unknown[];
}

const emqxCalls: EmqxCall[] = [];
let emqxThrows: Error | null = null;

const emqxPath = require.resolve("../../src/server/emqx");
const REAL_EMQX = require(emqxPath); // captured before the stub displaces it

const record =
  (fn: string) =>
  async (...args: unknown[]) => {
    emqxCalls.push({ fn, args });
    if (emqxThrows) throw emqxThrows;
    return undefined as any;
  };

const emqxStub = {
  EMQX: {
    get enabled() {
      return true;
    },
    kick: record("kick"),
    unsubscribe: record("unsubscribe"),
    revokeTopic: record("revokeTopic"),
    revokeFriendshipTopics: record("revokeFriendshipTopics"),
    notifyGraphChanged: record("notifyGraphChanged"),
  },
};
{
  const m = new Module(emqxPath, module);
  m.filename = emqxPath;
  m.loaded = true;
  m.exports = emqxStub;
  require.cache[emqxPath] = m;
}

// Required AFTER the stub, so the handler closes over it.
const { createApiHandler } = require("../../src/server/api") as typeof import("../../src/server/api");
const { DB } = require("../../src/server/db/api") as typeof import("../../src/server/db/api");
const { peerId } = require("../reference/protocol/identity") as typeof import("../reference/protocol/identity");

const { REPORT_CATEGORIES } = require("../../src/server/db/api") as typeof import("../../src/server/db/api");

/** The conversation topic id of an existing friendship. */
async function convoId(a: string, b: string): Promise<string> {
  const topics = await DB.getFriendshipTopics(a, b);
  if (!topics) throw new Error("not friends");
  return topics.convoId;
}

// --- harness -----------------------------------------------------------------------

const handler = createApiHandler();

const call = (method: string, path: string, body?: unknown, token?: string) =>
  request(handler, method, path, { body, ...(token ? { token } : {}) });

const created: string[] = [];

interface Account {
  id: string;
  pkHex: string;
  token: string;
  username: string;
}

/** A registered account with a session, made directly rather than through the
 *  handshake — this file is about what happens after login, and the handshake
 *  has its own file. */
async function account(): Promise<Account> {
  // The id is DERIVED, not chosen: `users` carries
  // CHECK (encode(pk_digest(identity_pk), 'hex') = id), so the database itself
  // refuses a row whose id does not name its key. Inventing the two
  // independently — which is what I tried first — fails at the constraint.
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  const username = `t${crypto.randomBytes(6).toString("hex")}`;
  await DB.ensureUser(id, pkHex);
  await DB.setUsername(id, username);
  created.push(id);
  return { id, pkHex, token: await DB.mintSessionToken(id), username };
}

/** Two accounts that are already friends. */
async function friends(): Promise<[Account, Account]> {
  const a = await account();
  const b = await account();
  await DB.createFriendship(a.id, b.id);
  return [a, b];
}

async function cleanup(): Promise<void> {
  emqxCalls.length = 0;
  emqxThrows = null;
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM sessions WHERE id = ANY($1::text[])`,
    `DELETE FROM invites WHERE from_id = ANY($1::text[]) OR to_id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM ended_friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM prekeys_onetime WHERE id = ANY($1::text[])`,
    `DELETE FROM prekeys_medium WHERE id = ANY($1::text[])`,
    `DELETE FROM push_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM blocks WHERE blocker_id = ANY($1::text[]) OR blocked_id = ANY($1::text[])`,
    `DELETE FROM reports WHERE reporter_id = ANY($1::text[]) OR reported_id = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try {
      await q(sql, [ids]);
    } catch {
      /* a column this schema does not have */
    }
  }
  await q(`DELETE FROM rate_counters WHERE key LIKE 'invite:day:%' OR key LIKE 'report:day:%' OR key LIKE 'prekeys:%'`);
  created.length = 0;
}

test.afterEach(async () => {
  await cleanup();
});
test.after(async () => {
  await cleanup();
  await closePg();
});

const called = (fn: string) => emqxCalls.filter((c) => c.fn === fn);

// --- the stub is not a fiction -----------------------------------------------------------

test("the stubbed broker client still matches the real one", () => {
  for (const fn of ["kick", "unsubscribe", "revokeTopic", "notifyGraphChanged"] as const) {
    assert.equal(typeof REAL_EMQX.EMQX[fn], "function", `EMQX.${fn} is gone`);
    assert.equal(
      REAL_EMQX.EMQX[fn].length,
      (emqxStub.EMQX as any)[fn].length === 0 ? REAL_EMQX.EMQX[fn].length : 0,
      "arity is not comparable through a rest-args stub; presence is what is checked",
    );
  }
  assert.equal(typeof REAL_EMQX.EMQX.enabled, "boolean");
});

// --- inviting -----------------------------------------------------------------------------

test("an invite reaches the recipient, and they are told it happened", async () => {
  const a = await account();
  const b = await account();

  const res = await call("POST", "/friends/invite", { to: b.username }, a.token);
  assert.equal(res.status, 200, res.text);

  const invites = await call("GET", "/friends/invites", undefined, b.token);
  assert.equal(invites.status, 200, invites.text);
  assert.equal(invites.body.invites.length, 1, JSON.stringify(invites.body));

  // The recipient has no other way to learn an invite exists — nothing pushed
  // graph changes, so one sat unseen until their next poll. This nudge is what
  // makes it appear without a manual refresh.
  const nudges = called("notifyGraphChanged");
  assert.equal(nudges.length, 1, "the recipient was not notified");
  assert.deepEqual(nudges[0]!.args[0], [b.id]);
});

test("an invite to a handle nobody holds notifies nobody", async () => {
  const a = await account();
  await call("POST", "/friends/invite", { to: "nobody-holds-this-handle" }, a.token);
  assert.deepEqual(
    called("notifyGraphChanged"),
    [],
    "a nudge for an unresolvable handle would be a request per junk invite",
  );
});

test("the daily invite ceiling refuses with 429, not 402", async () => {
  // Deliberately not 402: the app reads 402 as "fall back to the free door" and
  // re-authenticates, so a user who hit a daily limit would silently lose their
  // friend topics for the trouble.
  const a = await account();
  const statuses: number[] = [];
  for (let i = 0; i < 22; i++) {
    const b = await account();
    statuses.push((await call("POST", "/friends/invite", { to: b.username }, a.token)).status);
  }
  assert.equal(statuses.filter((s) => s === 200).length, 20, statuses.join(","));
  const refused = statuses.slice(20);
  assert.deepEqual(refused, [429, 429], statuses.join(","));
});

test("the ceiling is counted before the body is read", async () => {
  // `bumpCounter` runs before `readJson`, so a rate-limited caller is refused
  // without the server parsing anything it sent. A limiter behind the body
  // parser still pays for every request it refuses.
  const a = await account();
  for (let i = 0; i < 20; i++) {
    const b = await account();
    await call("POST", "/friends/invite", { to: b.username }, a.token);
  }
  const res = await call("POST", "/friends/invite", { nonsense: true }, a.token);
  assert.equal(res.status, 429, `a missing "to" would be 400 if the body were read first: ${res.text}`);
});

// --- accepting, which is where the topic ids are handed out ------------------------------

test("accepting an invite hands the accepter the new friendship's topic ids", async () => {
  // The accepter greets immediately, so it needs the ids in THIS response rather
  // than after a /friends round trip. And both members must get the same ids,
  // or the two ends of one conversation sit on different topics.
  const a = await account();
  const b = await account();
  await call("POST", "/friends/invite", { to: b.username }, a.token);
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/accept", { from: a.username }, b.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.friend.id, a.id);
  assert.match(res.body.friend.convo_id, /^[0-9a-f]{64}$/);
  assert.match(res.body.friend.handshake_id, /^[0-9a-f]{64}$/);

  const listA = (await call("GET", "/friends", undefined, a.token)).body.friends;
  const bAsSeenByA = listA.find((f: { id: string }) => f.id === b.id);
  assert.equal(bAsSeenByA.convo_id, res.body.friend.convo_id, "the inviter is handed the same conversation");
  assert.equal(bAsSeenByA.handshake_id, res.body.friend.handshake_id);

  // Both sides are nudged. The inviter is the one that matters: they invited a
  // HANDLE, so their contact row holds no client id (or topic ids) until a
  // directory sync fills it in — and the accepter greets immediately.
  const nudged = called("notifyGraphChanged");
  assert.equal(nudged.length, 1);
  assert.deepEqual([...(nudged[0]!.args[0] as string[])].sort(), [a.id, b.id].sort());
});

test("accepting an invite that was never sent creates nothing", async () => {
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/accept", { from: a.username }, b.token);
  assert.equal(res.status, 400);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.friend, undefined, "no topic ids for a friendship that does not exist");
  assert.equal(await DB.areFriends(a.id, b.id), false);
  assert.deepEqual(called("notifyGraphChanged"), [], "nothing happened, so nobody is told");
});

// --- removing, which is where the topic ids are retired -------------------------------------------

test("removing a friend retires the topic ids AND drops both live subscriptions", async () => {
  // Deleting the row retires the ids — nobody is handed them again. But the
  // ex-friend already HOLDS them, and a subscription that is already open keeps
  // delivering; the broker call is what ends it now.
  const [a, b] = await friends();
  const topics = await DB.getFriendshipTopics(a.id, b.id);
  assert.ok(topics, "setup");
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(await DB.getFriendshipTopics(a.id, b.id), null, "the friendship survived the unfriend");

  const revokes = called("revokeFriendshipTopics");
  assert.equal(revokes.length, 1, "the open subscriptions were never dropped");
  assert.deepEqual(revokes[0]!.args, [a.id, b.id, topics]);
  // Ids are 64 characters, which keeps the admin URL short.
  for (const arg of revokes[0]!.args.slice(0, 2) as string[]) {
    assert.equal(arg.length, 64, `a ${arg.length}-character argument would rebuild the 414`);
  }
  assert.deepEqual([...(called("notifyGraphChanged")[0]!.args[0] as string[])].sort(), [a.id, b.id].sort());
});

test("removing someone you are not friends with revokes nothing", async () => {
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 400);
  assert.deepEqual(called("revokeFriendshipTopics"), [], "a non-friendship must not touch the broker");
});

test("a broker that refuses does not undo the unfriend", async () => {
  // Best effort by design: the unfriend has already succeeded in the database
  // and must not be rolled back because the broker is unwell. Today that surfaces
  // as a 500 to the caller — the database change stands, so a retry is safe, and
  // pinning it means a future change to swallow the error is deliberate.
  const [a, b] = await friends();
  emqxThrows = new Error("emqx unreachable");
  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 500, res.text);
  assert.equal(res.body.error, "INTERNAL", "the broker's message must not reach the caller");
  assert.equal(await DB.areFriends(a.id, b.id), false, "the unfriend must stand even when the broker call fails");
});

// --- cancelling ----------------------------------------------------------------------------------

test("an invite can be withdrawn by the sender and declined by the recipient", async () => {
  // One route serves both, and only one of the two can match a real pending
  // invite — so the same call means "withdraw" to a sender and "decline" to a
  // recipient without either being able to act on the other's behalf.
  const a = await account();
  const b = await account();

  await call("POST", "/friends/invite", { to: b.username }, a.token);
  const withdrawn = await call("POST", "/friends/cancel", { peer: b.username }, a.token);
  assert.equal(withdrawn.status, 200, withdrawn.text);
  assert.equal((await call("GET", "/friends/invites", undefined, b.token)).body.invites.length, 0);

  await call("POST", "/friends/invite", { to: b.username }, a.token);
  const declined = await call("POST", "/friends/cancel", { peer: a.username }, b.token);
  assert.equal(declined.status, 200, declined.text);
  assert.equal((await call("GET", "/friends/invites", undefined, b.token)).body.invites.length, 0);
});

test("cancelling nothing is a 400 and notifies nobody", async () => {
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/cancel", { peer: b.username }, a.token);
  assert.equal(res.status, 400);
  assert.deepEqual(called("notifyGraphChanged"), []);
});

// --- prekeys ---------------------------------------------------------------------------------------

const KEY = (seed: number) => seed.toString(16).padStart(2, "0").repeat(7237);

test("a one-time prekey is handed out once and never again", async () => {
  // The whole point of the one-time pool. A key served twice means two
  // conversations derive from the same ephemeral secret, which is the property
  // the pool exists to avoid.
  const [a, b] = await friends();
  const c = await account();
  await DB.createFriendship(c.id, b.id);
  const upload = await call(
    "POST",
    "/prekeys",
    {
      medium: KEY(0xaa),
      oneTime: [
        { id: 1, prekey: KEY(0xb1) },
        { id: 2, prekey: KEY(0xb2) },
      ],
    },
    b.token,
  );
  assert.equal(upload.status, 200, upload.text);
  assert.equal(upload.body.accepted, 2);

  const seen = new Set<number>();
  for (const claimer of [a, c]) {
    const res = await call("POST", "/prekeys/claim", { peer: b.username }, claimer.token);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.body.medium, KEY(0xaa), "the medium-term key comes with every claim");
    assert.ok(res.body.oneTime, `a claim by ${claimer.username} returned no one-time key`);
    assert.ok(!seen.has(res.body.oneTime.id), `one-time key ${res.body.oneTime.id} was served twice`);
    seen.add(res.body.oneTime.id);
  }
  assert.equal(seen.size, 2);
});

test("an exhausted pool falls back to the medium-term key rather than failing", async () => {
  // The server is untrusted here by design: it can withhold one-time keys to
  // force the weaker fallback, but it cannot read anything, because the
  // initiator also encapsulates to the peer's PINNED identity key. So an empty
  // pool is a degraded handshake, not a refused one.
  const [a, b] = await friends();
  await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [] }, b.token);

  const res = await call("POST", "/prekeys/claim", { peer: b.username }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.medium, KEY(0xaa));
  assert.equal(res.body.oneTime, null, "an empty pool must not invent a key");
});

test("a peer with no bundle at all is a 404", async () => {
  // No medium-term key means no bundle. A one-time key is an addition to it,
  // never a substitute — an initiator with only a one-time key could not derive
  // the same root as the responder.
  const [a, b] = await friends();
  const res = await call("POST", "/prekeys/claim", { peer: b.username }, a.token);
  assert.equal(res.status, 404);
  assert.equal(res.body.error, "NO_PREKEYS");
});

test("a stranger cannot drain a pool, however many sessions they hold", async () => {
  // Friendship is the authorization. Without it anyone with a session could
  // empty a stranger's one-time pool — a cheap way to force every one of their
  // future conversations onto the reusable medium-term key.
  const victim = await account();
  const stranger = await account();
  await call(
    "POST",
    "/prekeys",
    {
      medium: KEY(0xaa),
      oneTime: [{ id: 1, prekey: KEY(0xb1) }],
    },
    victim.token,
  );

  const res = await call("POST", "/prekeys/claim", { peer: victim.username }, stranger.token);
  assert.equal(res.status, 403);
  assert.equal(res.body.error, "NOT_FRIENDS");
  assert.equal(
    (await call("GET", "/prekeys/count", undefined, victim.token)).body.remaining,
    1,
    "the refused claim consumed a key anyway",
  );
});

test("one friend cannot drain another's one-time pool", async () => {
  // Every account is the bot's friend, so without a per-pair allowance anyone
  // could empty the bot's pool and leave every later initiator with the
  // medium-term key alone.
  const owner = await account();
  const [greedy, honest] = [await account(), await account()];
  await DB.createFriendship(owner.id, greedy.id);
  await DB.createFriendship(owner.id, honest.id);
  const oneTime = Array.from({ length: 8 }, (_, i) => ({ id: i, prekey: KEY(0xb0 + i) }));
  assert.equal((await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime }, owner.token)).status, 200);

  const greedyClaims = [];
  for (let i = 0; i < 8; i++) greedyClaims.push(await call("POST", "/prekeys/claim", { peer: owner.id }, greedy.token));
  assert.ok(
    greedyClaims.every((r) => r.status === 200 && r.body.medium === KEY(0xaa)),
    "every claim still gets the bundle",
  );
  assert.equal(greedyClaims.filter((r) => r.body.oneTime).length, 1, "one friend took more than one one-time key");

  const later = await call("POST", "/prekeys/claim", { peer: owner.id }, honest.token);
  assert.ok(later.body.oneTime, "the honest initiator was left with the medium-term key only");
  assert.equal((await call("GET", "/prekeys/count", undefined, owner.token)).body.remaining, 6);
});

test("the one-time pool is capped, keeping the newest", async () => {
  const owner = await account();
  for (let batch = 0; batch < 6; batch++) {
    const oneTime = Array.from({ length: 8 }, (_, i) => ({ id: batch * 8 + i, prekey: KEY(0xb0 + i) }));
    assert.equal((await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime }, owner.token)).status, 200);
  }
  const count = (await call("GET", "/prekeys/count", undefined, owner.token)).body;
  assert.equal(count.remaining, 32, "six uploads of eight were all kept");
  assert.equal(count.maxId, 47, "the newest keys were the ones dropped");
  const ids = await q<{ key_id: number }>(`SELECT min(key_id) AS key_id FROM prekeys_onetime WHERE id = $1`, [
    owner.id,
  ]);
  assert.equal(ids.rows[0]!.key_id, 16, "the oldest sixteen go");
});

test("prekey uploads are limited per day", async () => {
  const owner = await account();
  await q(`INSERT INTO rate_counters (key, n, window_ends_at) VALUES ($1, 30, now() + interval '1 day')`, [
    `prekeys:day:${owner.id}`,
  ]);
  const res = await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [] }, owner.token);
  assert.equal(res.status, 429, res.text);
});

test("a one-time prekey id past the column's range is a 400, not a 500", async () => {
  const owner = await account();
  for (const id of [2 ** 31, 2 ** 32, Number.MAX_SAFE_INTEGER]) {
    const res = await call(
      "POST",
      "/prekeys",
      { medium: KEY(0xaa), oneTime: [{ id, prekey: KEY(0xb1) }] },
      owner.token,
    );
    assert.equal(res.status, 400, `${id}: ${res.text}`);
    assert.equal(res.body.error, "INVALID_FIELD");
  }
  const top = await call(
    "POST",
    "/prekeys",
    { medium: KEY(0xaa), oneTime: [{ id: 2 ** 31 - 1, prekey: KEY(0xb1) }] },
    owner.token,
  );
  assert.equal(top.status, 200, top.text);
});

test("an upload larger than the cap is refused whole", async () => {
  // Eight keeps the body near 130 kB, half of MAX_BODY_BYTES. A key travels as
  // hex, so it costs 2 x 7237 characters on the wire — the byte count is not the
  // wire cost, which is the easy way to size this wrong.
  const a = await account();
  const nine = Array.from({ length: 9 }, (_, i) => ({ id: i, prekey: KEY(0xb0 + i) }));
  const res = await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: nine }, a.token);
  assert.equal(res.status, 400, res.text);
  assert.equal(res.body.error, "TOO_MANY_PREKEYS");
  assert.equal(
    (await call("GET", "/prekeys/count", undefined, a.token)).body.remaining,
    0,
    "a refused upload must not store the first eight",
  );
});

test("a malformed prekey entry names the index that is wrong", async () => {
  const a = await account();
  for (const bad of [
    { id: -1, prekey: KEY(0xb1) },
    { id: 1.5, prekey: KEY(0xb1) },
    { id: "1", prekey: KEY(0xb1) },
    { id: 1, prekey: "not hex" },
    { id: 1 },
  ]) {
    const res = await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [bad] }, a.token);
    assert.equal(res.status, 400, `${JSON.stringify(bad).slice(0, 40)} -> ${res.status}`);
    assert.ok(/oneTime\[0\]|prekey/.test(res.body.message ?? res.body.error), res.text);
  }
});

test("/prekeys/count reports the caller's own pool and the target", async () => {
  const a = await account();
  await call(
    "POST",
    "/prekeys",
    {
      medium: KEY(0xaa),
      oneTime: [
        { id: 5, prekey: KEY(0xb1) },
        { id: 9, prekey: KEY(0xb2) },
      ],
    },
    a.token,
  );
  const res = await call("GET", "/prekeys/count", undefined, a.token);
  assert.equal(res.body.remaining, 2);
  assert.equal(res.body.maxId, 9, "so a client knows where to continue numbering");
  assert.equal(res.body.target, 8);
});

// --- account deletion ---------------------------------------------------------------------------------

test("deleting an account leaves no row anywhere, and ends the live connection", async () => {
  // Everything in the database stops the NEXT connect. The kick is what ends the
  // current one — otherwise a deleted account keeps a live session, and its
  // queued backlog, for as long as the connection happens to last.
  //
  // TWO sessions on purpose. The route also calls `revokeSessionToken(bearer)`,
  // which would kill only the one that made the request; `deleteUser` deletes
  // every table by hand in a transaction — there are no FK cascades in this
  // schema — so the second session must die too. That is the property worth
  // asserting, and it is also what makes the route's explicit
  // `revokeSessionToken`/`revokeMqttAuth` calls redundant: verified by removing
  // each, which changes nothing observable. They are cheap belt-and-braces, not
  // load-bearing, and this test says so rather than appearing to cover them.
  const [a, b] = await friends();
  await DB.setPushToken(a.id, "ios", "production", "a".repeat(64));
  await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [{ id: 1, prekey: KEY(0xb1) }] }, a.token);
  const otherSession = await DB.mintSessionToken(a.id);

  // Moderation state on both sides, so the exception below is asserted against
  // rows that actually exist rather than against an empty table.
  await DB.block(a.id, b.id);
  await DB.block(b.id, a.id);
  const hash = await convoId(a.id, b.id);
  const filedByA = await DB.createReport({
    reporterId: a.id,
    reportedId: b.id,
    conversationId: hash,
    category: "spam",
    excerpt: "a message a reported",
  });
  const filedAboutA = await DB.createReport({
    reporterId: b.id,
    reportedId: a.id,
    conversationId: hash,
    category: "harassment",
    excerpt: "a message b reported",
  });
  emqxCalls.length = 0;

  const res = await call("POST", "/account/delete", {}, a.token);
  assert.equal(res.status, 200, res.text);

  // A new table that forgets to appear in `deleteUser` is the silent regression
  // this guards — and the App Store evidence for account deletion rests on it.
  //
  // `reports` is NOT in this list, and that is the one deliberate hole in "no
  // row anywhere". It is spelled out rather than omitted, because a reader who
  // finds a table missing from this loop should be able to tell a decision from
  // an oversight — an oversight here is exactly the regression the loop exists
  // to catch. The two assertions under it pin both halves of the rule.
  for (const [table, col] of [
    ["users", "id"],
    ["sessions", "id"],
    ["push_tokens", "id"],
    ["prekeys_medium", "id"],
    ["prekeys_onetime", "id"],
    ["friendships", "id_lo"],
    ["ended_friendships", "id_lo"],
    ["ended_friendships", "id_hi"],
    // The blocks this user placed. A block placed ON them is the blocker's, below.
    ["blocks", "blocker_id"],
  ] as const) {
    const rows = await q(`SELECT 1 FROM ${table} WHERE ${col} = $1`, [a.id]);
    assert.equal(rows.rows.length, 0, `${table}.${col} still holds a row for the deleted account`);
  }

  // The second exception: b's block on a is b's data, and it outlives a. The
  // same key signs back in to the same id, so dropping it would let a blocked
  // account lift every block on it by deleting itself.
  assert.deepEqual(await DB.blockedIds(b.id), [a.id], "deleting the blocked account lifted the block on it");

  // The exception, and its limit. A report ABOUT the deleted user survives —
  // otherwise deleting an account erases the complaints against it, which makes
  // deletion the abuse-evasion button. A report BY them keeps its content and
  // loses its filer, because who complained is this user's own footprint and the
  // message they handed in is not. Neither row's clock moves: both still expire
  // 90 days after they were filed. See migrations/006_reports.sql §1.
  const about = await q<{ reporter_id: string | null; message_excerpt: string | null }>(
    `SELECT reporter_id, message_excerpt FROM reports WHERE id = $1::uuid`,
    [filedAboutA],
  );
  assert.equal(
    about.rows.length,
    1,
    "a report ABOUT the deleted account vanished with it — deletion is now an abuse-evasion tool",
  );
  assert.equal(about.rows[0]!.reporter_id, b.id, "…and it still names who filed it");

  const by = await q<{ reporter_id: string | null; message_excerpt: string | null }>(
    `SELECT reporter_id, message_excerpt FROM reports WHERE id = $1::uuid`,
    [filedByA],
  );
  assert.equal(by.rows.length, 1, "a report FILED by the deleted account was purged with it");
  assert.equal(by.rows[0]!.reporter_id, null, "…but it must no longer say who filed it: that half IS their footprint");
  assert.equal(
    by.rows[0]!.message_excerpt,
    "a message a reported",
    "…and its content stands, because it is about somebody else",
  );

  const kicks = called("kick");
  assert.equal(kicks.length, 1, "the live connection was left open");
  assert.deepEqual(kicks[0]!.args, [a.id]);

  // BOTH sessions, not just the one that asked.
  assert.equal((await call("GET", "/friends", undefined, a.token)).status, 401, "the deleting session");
  assert.equal(
    (await call("GET", "/friends", undefined, otherSession)).status,
    401,
    "a second device's session outlived the account",
  );

  // The friend is untouched — their account is not ours to delete — and the
  // friendship, with its topic ids, is gone from their list.
  assert.equal((await q(`SELECT 1 FROM users WHERE id = $1`, [b.id])).rows.length, 1);
  const left = (await call("GET", "/friends", undefined, b.token)).body.friends as Array<{ id: string }>;
  assert.ok(!left.some((f) => f.id === a.id), "the remaining friend is still handed the deleted account's topics");
});

test("a blocked account that deletes itself and signs back in is still blocked", async () => {
  const [victim, abuser] = await friends();
  assert.equal((await call("POST", "/friends/block", { peer: abuser.id }, victim.token)).status, 200);
  assert.equal((await call("POST", "/account/delete", {}, abuser.token)).status, 200);

  // What /auth/verify does for a returning key: the same id, a new session.
  assert.equal(await DB.identityKey(abuser.id), null, "the account is gone");
  await DB.ensureUser(abuser.id, abuser.pkHex);
  const token = await DB.mintSessionToken(abuser.id);

  assert.deepEqual(
    (await call("GET", "/friends/blocked", undefined, victim.token)).body.blocked,
    [abuser.id],
    "the victim's block list was emptied by the abuser's delete",
  );
  const again = await call("POST", "/friends/invite", { to: victim.id }, token);
  assert.equal(again.status, 404, "the same id invites its blocker again");
  assert.deepEqual((await call("GET", "/friends/invites", undefined, victim.token)).body.invites, []);
});

test("deletion needs a session, like everything else", async () => {
  const res = await call("POST", "/account/delete", {});
  assert.equal(res.status, 401);
  assert.deepEqual(called("kick"), [], "an unauthenticated call must not reach the broker");
});

// --- the friend ceiling ---------------------------------------------------------------------------------

test("the friend ceiling is checked on both sides of an accept", async () => {
  const [inviter, invitee] = [await account(), await account()];
  const sent = await call("POST", "/friends/invite", { to: invitee.id }, inviter.token);
  assert.equal(sent.status, 200, sent.text);
  const cap = Number(process.env.FRIEND_CAP || 150);
  await q(
    `INSERT INTO friendships (id_lo, id_hi)
     SELECT least($1, f), greatest($1, f)
       FROM (SELECT md5(i::text || $1) || md5($1 || i::text) AS f FROM generate_series(1, $2) i) fake`,
    [inviter.id, cap],
  );
  const res = await call("POST", "/friends/accept", { from: inviter.id }, invitee.token);
  assert.equal(res.status, 409, res.text);
  assert.equal(res.body.error, "FRIEND_LIMIT");
  assert.equal(res.body.peer, true, "the client is told it is the other side that is full");
});

test("concurrent accepts cannot overshoot the friend ceiling", async () => {
  // The cap is checked inside the accept's transaction with both accounts
  // locked; checked before it, ten simultaneous accepts all saw room.
  const me = await account();
  const cap = Number(process.env.FRIEND_CAP || 150);
  await q(
    `INSERT INTO friendships (id_lo, id_hi)
     SELECT least($1, f), greatest($1, f)
       FROM (SELECT md5(i::text || $1) || md5($1 || i::text) AS f FROM generate_series(1, $2) i) fake`,
    [me.id, cap - 2],
  );
  const inviters = await Promise.all(Array.from({ length: 10 }, account));
  for (const f of inviters) assert.equal((await call("POST", "/friends/invite", { to: me.id }, f.token)).status, 200);
  const replies = await Promise.all(inviters.map((f) => call("POST", "/friends/accept", { from: f.id }, me.token)));
  assert.equal(replies.filter((r) => r.status === 200).length, 2, replies.map((r) => r.status).join(", "));
  assert.ok(replies.every((r) => r.status === 200 || (r.status === 409 && r.body.error === "FRIEND_LIMIT")));
  assert.equal(await DB.countFriends(me.id), cap);
  assert.equal((await DB.getMyInvites(me.id)).length, 8, "a refused accept keeps its invite");
});

test("a username race answers USERNAME_TAKEN, never the database's own words", async () => {
  const name = `race_${crypto.randomBytes(4).toString("hex")}`;
  const users = await Promise.all(Array.from({ length: 12 }, account));
  const replies = await Promise.all(users.map((u) => call("POST", "/username", { username: name }, u.token)));
  assert.equal(replies.filter((r) => r.status === 200).length, 1, replies.map((r) => r.status).join(", "));
  for (const r of replies.filter((x) => x.status !== 200)) {
    assert.equal(r.status, 409, r.text);
    assert.equal(r.body.error, "USERNAME_TAKEN");
    assert.ok(!/duplicate|constraint|users_/i.test(r.text), r.text);
  }
});

// --- moderation: report + block -------------------------------------------------------------------------
//
// Guideline 1.2. The refusals are the emphasis here for the same reason they are
// everywhere else in this file — a report route that files whatever it is sent
// is a way to write message content into someone else's moderation record, and
// a block that a re-invite walks through is not a block.

/** A filed report, straight from the table. */
async function reportRow(id: string) {
  const r = await q<{
    reporter_id: string | null;
    reported_id: string;
    conversation_id: string;
    category: string;
    reporter_note: string | null;
    message_excerpt: string | null;
    message_id: string | null;
    message_frame: Buffer | null;
    expires_at: string;
    handled_at: string | null;
  }>(`SELECT * FROM reports WHERE id = $1::uuid`, [id]);
  return r.rows[0] ?? null;
}

test("a report names a conversation the reporter is in, and the server derives the subject", async () => {
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);

  const res = await call(
    "POST",
    "/report",
    {
      conversation: hash,
      peer: b.id,
      category: "harassment",
      note: "kept messaging after I asked them to stop",
      excerpt: "the message text",
      // The shape the iOS client actually mints: `UUID().uuidString`, uppercase
      // and hyphenated. 006 constrained this column to lowercase hex, so every
      // report carrying a real message id failed the CHECK and came back 500 —
      // and the test that should have caught it passed "deadbeef", the one shape
      // no client sends. 007 widens the column to the envelope's own contract.
      messageId: "9F3A1C2E-4B6D-4E8A-9C1F-2D7B5A0E3C84",
    },
    a.token,
  );
  assert.equal(res.status, 200, res.text);
  assert.ok(res.body.id, "the response must carry the id an operator quotes");

  const row = await reportRow(res.body.id);
  assert.ok(row, "nothing was written");
  assert.equal(row!.reporter_id, a.id);
  assert.equal(row!.reported_id, b.id, "the subject is derived from the conversation, not from `peer`");
  assert.equal(row!.category, "harassment");
  assert.equal(row!.message_excerpt, "the message text");
  assert.equal(
    row!.message_id,
    "9F3A1C2E-4B6D-4E8A-9C1F-2D7B5A0E3C84",
    "stored verbatim: this value is compared against what the broker delivered, " +
      "so a normalized copy matches nothing",
  );
  assert.equal(row!.message_frame, null, "no frame was sent, and none was invented");
  assert.equal(row!.handled_at, null, "a fresh report is unhandled, which is what puts it in the queue");
});

test("a report takes any message id the wire format allows, and refuses what it does not", async () => {
  // `message_id` is a copy of the envelope's `msgId`: 1..128 bytes of UTF-8,
  // opaque, chosen by the sending client. The column must not have opinions the
  // wire format does not — 006 did, and refused every real report.
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);

  for (const messageId of [
    "01JBQ7X4M9K2ZC8V5N3T6PW0RY", // a ULID: uppercase Crockford
    "aGVsbG8td29ybGQtbWVzc2FnZS1pZA", // base64url, mixed case
    "m".repeat(128), // exactly the envelope's ceiling
  ]) {
    const res = await call(
      "POST",
      "/report",
      {
        conversation: hash,
        peer: b.id,
        category: "spam",
        messageId,
      },
      a.token,
    );
    assert.equal(res.status, 200, `${messageId.slice(0, 16)}…: ${res.text}`);
    assert.equal((await reportRow(res.body.id))!.message_id, messageId);
  }

  // Over the ceiling in BYTES, which is the only unit the envelope counts: 40 of
  // these are 80 UTF-16 units and 160 bytes, so a `.length` bound of 128 waves
  // them through and the column then refuses them.
  const tooLong = await call(
    "POST",
    "/report",
    {
      conversation: hash,
      peer: b.id,
      category: "spam",
      messageId: "🙂".repeat(40),
    },
    a.token,
  );
  assert.equal(tooLong.status, 400, tooLong.text);
  assert.equal(tooLong.body.error, "INVALID_FIELD");

  // Control characters are refused at the route, because `npm run reports`
  // prints this value into an operator's terminal.
  const controlChars = await call(
    "POST",
    "/report",
    {
      conversation: hash,
      peer: b.id,
      category: "spam",
      messageId: "abc\u001b[2Jdef",
    },
    a.token,
  );
  assert.equal(controlChars.status, 400, controlChars.text);
  assert.equal(controlChars.body.error, "INVALID_FIELD");

  // C1 as well: U+009B is CSI on terminals that honour 8-bit controls.
  const c1 = await call(
    "POST",
    "/report",
    { conversation: hash, peer: b.id, category: "spam", messageId: "abc\u009b2Jdef" },
    a.token,
  );
  assert.equal(c1.status, 400, c1.text);
  assert.equal(c1.body.error, "INVALID_FIELD");

  assert.equal(
    (await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [a.id])).rows.length,
    3,
    "the refusals must not have written rows",
  );
});

test("a report is refused for a conversation the caller is not in", async () => {
  // The whole point of deriving the subject from the friendship: an outsider
  // holding the hash — which is derivable by anyone who knows both ids — must
  // not be able to file against a pair they are not part of.
  const [a, b] = await friends();
  const outsider = await account();
  const res = await call(
    "POST",
    "/report",
    {
      conversation: await convoId(a.id, b.id),
      peer: b.id,
      category: "spam",
    },
    outsider.token,
  );
  assert.equal(res.status, 403, res.text);
  assert.equal(res.body.error, "NOT_A_MEMBER");
});

test("a report for a conversation that does not exist is a 404, not a row", async () => {
  const me = await account();
  const res = await call(
    "POST",
    "/report",
    {
      conversation: crypto.randomBytes(32).toString("hex"),
      peer: me.id,
      category: "spam",
    },
    me.token,
  );
  assert.equal(res.status, 404, res.text);
  assert.equal((await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [me.id])).rows.length, 0);
});

test("a conversation stays reportable after the friendship ends, by either side", async () => {
  // The abuser must not be able to make a conversation unreportable by
  // unfriending first.
  const [victim, abuser] = await friends();
  const hash = await convoId(victim.id, abuser.id);
  assert.equal((await call("POST", "/friends/remove", { peer: victim.id }, abuser.token)).status, 200);
  assert.equal(await DB.getTopicMembers(hash).then((m) => m.length), 0, "the push bridge still sees members");

  const res = await call(
    "POST",
    "/report",
    { conversation: hash, peer: abuser.id, category: "harassment" },
    victim.token,
  );
  assert.equal(res.status, 200, res.text);
  assert.equal((await reportRow(res.body.id))!.reported_id, abuser.id);

  // Ended by a block, the same.
  const [other, blocked] = await friends();
  const blockedHash = await convoId(other.id, blocked.id);
  assert.equal((await call("POST", "/friends/block", { peer: blocked.id }, other.token)).status, 200);
  const after = await call(
    "POST",
    "/report",
    { conversation: blockedHash, peer: blocked.id, category: "spam" },
    other.token,
  );
  assert.equal(after.status, 200, after.text);

  // Still only the two members.
  const outsider = await account();
  const stranger = await call(
    "POST",
    "/report",
    { conversation: hash, peer: victim.id, category: "spam" },
    outsider.token,
  );
  assert.equal(stranger.status, 403, stranger.text);
});

test("an ended friendship stops being reportable when its window lapses, and goes with an account", async () => {
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);
  await call("POST", "/friends/remove", { peer: b.id }, a.token);
  await q(`UPDATE ended_friendships SET expires_at = now() - interval '1 second' WHERE convo_id = $1`, [hash]);
  const lapsed = await call("POST", "/report", { conversation: hash, peer: b.id, category: "spam" }, a.token);
  assert.equal(lapsed.status, 404, lapsed.text);

  const [c, d] = await friends();
  const other = await convoId(c.id, d.id);
  await call("POST", "/friends/remove", { peer: d.id }, c.token);
  assert.equal((await call("POST", "/account/delete", {}, d.token)).status, 200);
  assert.equal((await q(`SELECT 1 FROM ended_friendships WHERE convo_id = $1`, [other])).rows.length, 0);
});

test("a report note with control characters is refused, and an excerpt's are neutralised", async () => {
  // Both are printed on the operator's terminal. The note is the reporter's own
  // text, so it is refused; the excerpt quotes the reported person, whose
  // control characters must not make the report fail.
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);
  for (const note of ["\x1b[2Jcleared", "bell\x07", "c1\u009b31m", "cr\rover"]) {
    const res = await call("POST", "/report", { conversation: hash, peer: b.id, category: "spam", note }, a.token);
    assert.equal(res.status, 400, `${JSON.stringify(note)}: ${res.text}`);
  }
  const fine = await call(
    "POST",
    "/report",
    {
      conversation: hash,
      peer: b.id,
      category: "spam",
      note: "line one\n\tline two",
      excerpt: "hi\x1b]52;c;x\x07 there",
    },
    a.token,
  );
  assert.equal(fine.status, 200, fine.text);
  const row = await reportRow(fine.body.id);
  assert.equal(row!.reporter_note, "line one\n\tline two");
  assert.equal(row!.message_excerpt, "hi\ufffd]52;c;x\ufffd there");
});

test("a `peer` that is not the other member is refused rather than ignored", async () => {
  // `peer` is redundant — the subject is already derived — and that is why it is
  // required. A client that disagrees with the server about whose conversation
  // this is has a bug, and filing against the wrong person is the worst possible
  // moment to find out.
  const [a, b] = await friends();
  const someoneElse = await account();
  const res = await call(
    "POST",
    "/report",
    {
      conversation: await convoId(a.id, b.id),
      peer: someoneElse.id,
      category: "spam",
    },
    a.token,
  );
  assert.equal(res.status, 400, res.text);
  assert.equal(res.body.error, "PEER_MISMATCH");
  assert.equal(
    (await q(`SELECT 1 FROM reports WHERE reported_id = $1`, [someoneElse.id])).rows.length,
    0,
    "…and nothing was filed against the person the client named",
  );
});

test("a report refuses a category the runbook has no procedure for", async () => {
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);
  for (const category of ["", "abuse", "DROP TABLE", "spam!"]) {
    const res = await call("POST", "/report", { conversation: hash, peer: b.id, category }, a.token);
    assert.equal(res.status, 400, `category=${JSON.stringify(category)} -> ${res.status}`);
  }
  // …and the vocabulary the route accepts is the one the column accepts. Two
  // lists that can drift would fail at the constraint, as a 500, after the
  // client was told the field was fine.
  for (const category of REPORT_CATEGORIES) {
    const res = await call("POST", "/report", { conversation: hash, peer: b.id, category }, a.token);
    assert.equal(res.status, 200, `category=${category} -> ${res.text}`);
  }
});

test("a malformed conversation hash never reaches the database", async () => {
  const [a, b] = await friends();
  for (const conversation of ["nothex", "ab", "zz".repeat(32), `${await convoId(a.id, b.id)}00`]) {
    const res = await call("POST", "/report", { conversation, peer: b.id, category: "spam" }, a.token);
    assert.equal(res.status, 400, `${conversation.slice(0, 12)} -> ${res.status}`);
    assert.equal(res.body.error, "INVALID_FIELD");
  }
});

test("an attached frame must be base64 and must fit", async () => {
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);
  const base = { conversation: hash, peer: b.id, category: "spam" };

  const notB64 = await call("POST", "/report", { ...base, frame: "this is not base64!!" }, a.token);
  assert.equal(notB64.status, 400, notB64.text);

  // Bounded in BYTES after decoding, because base64 is 4/3 the size of what it
  // carries and a cap on the string is a cap on the wrong number.
  const tooBig = await call("POST", "/report", { ...base, frame: Buffer.alloc(97 * 1024).toString("base64") }, a.token);
  assert.equal(tooBig.status, 400, tooBig.text);
  assert.match(tooBig.body.message ?? "", /bytes/);

  const ok = await call(
    "POST",
    "/report",
    { ...base, frame: Buffer.from("a sealed frame would go here").toString("base64") },
    a.token,
  );
  assert.equal(ok.status, 200, ok.text);
  const row = await reportRow(ok.body.id);
  assert.equal(
    row!.message_frame?.toString("utf8"),
    "a sealed frame would go here",
    "the bytes stored must be the bytes sent, not their base64",
  );
});

test("the daily report cap bites, and it bites before the body is read", async () => {
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);
  // The limit comes from the environment, so this drives the counter directly
  // rather than sending twenty requests to discover a number a deployment can
  // change.
  const limit = Number(process.env.REPORTS_PER_DAY || 20);
  for (let i = 0; i < limit; i++) await DB.bumpCounter(`report:day:${a.id}`, 86400);

  const res = await call("POST", "/report", { conversation: hash, peer: b.id, category: "spam" }, a.token);
  assert.equal(res.status, 429, res.text);
  assert.equal(res.body.limit, limit);
  assert.equal(
    (await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [a.id])).rows.length,
    0,
    "a rate-limited report must not still write its row",
  );
});

test("blocking ends the friendship, revokes the topic, and survives a re-invite", async () => {
  const [a, b] = await friends();
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/block", { peer: b.id }, a.token);
  assert.equal(res.status, 200, res.text);

  assert.equal(await DB.areFriends(a.id, b.id), false, "the friendship survived the block");
  // The ids are retired with the row; the blocked peer still holds them, so the
  // subscriptions already open on them are dropped now.
  assert.equal(called("revokeFriendshipTopics").length, 1, "the live subscriptions were left in place");
  assert.equal(called("notifyGraphChanged").length, 1, "neither side was told the graph changed");

  // The durable half. Without it the blocked party re-invites and the block has
  // evaporated — which is the ordinary way this feature is got wrong.
  const reinvite = await call("POST", "/friends/invite", { to: a.id }, b.token);
  assert.equal(reinvite.status, 404, reinvite.text);
  assert.equal((await q(`SELECT 1 FROM invites WHERE to_id = $1 AND from_id = $2`, [a.id, b.id])).rows.length, 0);

  // …and the blocker cannot walk through it either, by accident or otherwise.
  assert.equal((await call("POST", "/friends/invite", { to: b.id }, a.token)).status, 404);
});

test("a block refuses the invite with the SAME 404 an unknown handle gets", async () => {
  // Telling a blocked invite apart from an invite to nobody tells the blocked
  // party they were blocked, which is the one thing a block should not announce.
  const [a, b] = await friends();
  await call("POST", "/friends/block", { peer: b.id }, a.token);

  const blocked = await call("POST", "/friends/invite", { to: a.id }, b.token);
  const stranger = await call("POST", "/friends/invite", { to: crypto.randomBytes(32).toString("hex") }, b.token);
  assert.equal(blocked.status, stranger.status, "the status distinguishes a block from a stranger");
  assert.deepEqual(blocked.body, stranger.body, "…and so does the body");
});

test("a pending invite does not survive a block, in either direction", async () => {
  const a = await account();
  const b = await account();
  await call("POST", "/friends/invite", { to: b.id }, a.token);
  assert.equal(
    (await q(`SELECT 1 FROM invites WHERE to_id = $1 AND from_id = $2`, [b.id, a.id])).rows.length,
    1,
    "the fixture did not create the invite it is about to test",
  );

  const res = await call("POST", "/friends/block", { peer: a.id }, b.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(
    (await q(`SELECT 1 FROM invites WHERE to_id = $1 OR from_id = $1`, [a.id])).rows.length,
    0,
    "a pending invite is a live route back in and must go with the friendship",
  );

  // And accepting it afterwards — from a device that was offline when the block
  // landed and still holds the invite in its UI — rebuilds nothing.
  const accept = await call("POST", "/friends/accept", { from: a.id }, b.token);
  assert.notEqual(accept.status, 200, accept.text);
  assert.equal(await DB.areFriends(a.id, b.id), false);
});

test("unblocking lifts the block without restoring the friendship", async () => {
  const [a, b] = await friends();
  await call("POST", "/friends/block", { peer: b.id }, a.token);

  const res = await call("POST", "/friends/unblock", { peer: b.id }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(
    await DB.areFriends(a.id, b.id),
    false,
    "unblocking handed back a conversation topic the user deliberately tore down",
  );

  // What it DOES restore is the ability to ask again.
  assert.equal((await call("POST", "/friends/invite", { to: a.id }, b.token)).status, 200);
});

test("GET /friends/blocked is what stops the client deleting a blocked contact", async () => {
  // DirectorySync treats absence from /friends as "delete this row and its
  // history". A blocked peer is absent from /friends by construction, so without
  // this list a block silently destroys the conversation it was placed over.
  const [a, b] = await friends();
  assert.deepEqual((await call("GET", "/friends/blocked", undefined, a.token)).body.blocked, []);

  await call("POST", "/friends/block", { peer: b.id }, a.token);
  const mine = await call("GET", "/friends/blocked", undefined, a.token);
  assert.deepEqual(mine.body.blocked, [b.id]);

  // One direction only. A blocked peer must not be handed a list that tells them
  // who blocked them.
  assert.deepEqual(
    (await call("GET", "/friends/blocked", undefined, b.token)).body.blocked,
    [],
    "the blocked party can read who blocked them",
  );
});

test("report, then block, or block, then report: both file", async () => {
  // /friends/block tears the conversation down, and an ended friendship stays
  // reportable for a while, so the order the client uses does not decide
  // whether the report is filed.
  const [a, b] = await friends();
  const hash = await convoId(a.id, b.id);

  const filed = await call(
    "POST",
    "/report",
    { conversation: hash, peer: b.id, category: "harassment", excerpt: "…" },
    a.token,
  );
  assert.equal(filed.status, 200, filed.text);
  assert.equal((await call("POST", "/friends/block", { peer: b.id }, a.token)).status, 200);

  const after = await call("POST", "/report", { conversation: hash, peer: b.id, category: "harassment" }, a.token);
  assert.equal(after.status, 200, after.text);
  assert.equal((await reportRow(after.body.id))!.reported_id, b.id);

  // The report filed BEFORE the block stands, with its content, which is the
  // property that makes the ordering workable at all.
  const row = await reportRow(filed.body.id);
  assert.equal(row!.reported_id, b.id);
  assert.equal(row!.message_excerpt, "…");
});
