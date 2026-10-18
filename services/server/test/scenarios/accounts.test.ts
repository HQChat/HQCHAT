import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../reference/client";
import { BASE_URL, BOT_USERNAME, friends, newClient, pause, signedUp, signIn, stackUp, tag } from "./stack";

const rejectsWith = (status: number, code?: string) => (e: unknown) =>
  e instanceof ApiError && e.status === status && (code === undefined || e.code === code);

test("the server reports its health and version", async (t) => {
  if (!(await stackUp(t))) return;
  const health = await newClient().api.health();
  assert.equal(health.ok, true);
  assert.equal(typeof health.version, "string");
  if (process.env.TEST_EXPECT_VERSION) assert.equal(health.version, process.env.TEST_EXPECT_VERSION);
});

test("signing up claims a username that resolves to the new id and cannot be taken twice", async (t) => {
  if (!(await stackUp(t))) return;
  const { client, username } = await signedUp("su");
  assert.equal(await client.api.lookup(username), client.id);
  const other = newClient();
  await signIn(other);
  await assert.rejects(other.api.setUsername(username), rejectsWith(409, "USERNAME_TAKEN"));
  await assert.rejects(other.api.setUsername("x"), rejectsWith(400));
});

test("an accepted invite creates a friendship with topic ids on both sides", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  const [fa, fb] = await Promise.all([a.api.friends(), b.api.friends()]);
  const ab = fa.find((f) => f.id === b.id);
  const ba = fb.find((f) => f.id === a.id);
  assert.ok(ab && ba);
  assert.equal(ab.convoId, ba.convoId);
  assert.equal(ab.handshakeId, ba.handshakeId);
  assert.notEqual(ab.convoId, ab.handshakeId);
});

test("an invite can be declined by the invitee or withdrawn by the inviter", async (t) => {
  if (!(await stackUp(t))) return;
  const [{ client: a }, { client: b, username: bName }] = await Promise.all([signedUp("ia"), signedUp("ib")]);
  await a.api.invite(bName);
  assert.deepEqual(
    (await b.api.invites()).map((i) => i.id),
    [a.id],
  );
  await b.api.cancel(a.id);
  assert.deepEqual(await b.api.invites(), []);
  await a.api.invite(bName);
  await a.api.cancel(b.id);
  assert.deepEqual(await b.api.invites(), []);
  await assert.rejects(b.api.accept(a.id), rejectsWith(400));
  await assert.rejects(a.api.invite(`nobody_${tag()}`), rejectsWith(404));
});

test("blocking ends the friendship and hides the blocker until unblocked", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.api.block(b.id);
  assert.deepEqual(await a.api.blocked(), [b.id]);
  assert.equal(
    (await b.api.friends()).some((f) => f.id === a.id),
    false,
  );
  await assert.rejects(b.api.invite(a.id), rejectsWith(404));
  await a.api.unblock(b.id);
  await b.api.invite(a.id);
  await a.api.accept(b.id);
  assert.ok((await a.api.friends()).some((f) => f.id === b.id));
});

test("a report names a conversation the reporter belongs to", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  const conversation = (await a.api.friends()).find((f) => f.id === b.id)!.convoId;
  const id = await a.api.report({ conversation, peer: b.id, category: "spam", note: "scenario" });
  assert.equal(typeof id, "string");
  const { client: stranger } = await signedUp("rx");
  await assert.rejects(
    stranger.api.report({ conversation, peer: b.id, category: "spam" }),
    rejectsWith(403, "NOT_A_MEMBER"),
  );
  await assert.rejects(a.api.report({ conversation, peer: a.id, category: "spam" }), rejectsWith(400));
});

test("deleting an account revokes its session and removes it from its friends", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await b.close();
  await b.api.deleteAccount();
  await assert.rejects(b.api.friends(), rejectsWith(401));
  assert.equal(
    (await a.api.friends()).some((f) => f.id === b.id),
    false,
  );
  await assert.rejects(a.api.peerKey(b.id), rejectsWith(404));
});

test("refreshing the MQTT key keeps the REST session", async (t) => {
  if (!(await stackUp(t))) return;
  const { client } = await signedUp("rf");
  assert.equal(await client.auth.refresh(), true);
  assert.ok(Array.isArray(await client.api.friends()));
});

test("a new account is befriended to the helper bot, which greets it and answers", async (t) => {
  if (!(await stackUp(t))) return;
  const { client } = await signedUp("hb");
  const botId = await client.api.lookup(BOT_USERNAME);
  if (!botId) {
    if (process.env.SCENARIOS_REQUIRED === "1") throw new Error(`no @${BOT_USERNAME} on ${BASE_URL}`);
    return t.skip(`no @${BOT_USERNAME} on this stack`);
  }
  await client.sync();
  assert.ok(client.conversations.peer(botId), "the bot is a friend from the start");
  await client.connect();
  const welcome = await client.next(botId, 30_000);
  assert.equal(welcome.from, botId);
  assert.match(welcome.text, /welcome to hqchat/);
  await client.send(botId, "hello");
  for (let i = 0; i < 3; i++) {
    const m = await client.next(botId, 15_000);
    if (/I'm a bot/.test(m.text)) return;
    await pause(10);
  }
  assert.fail("the bot did not answer hello");
});
