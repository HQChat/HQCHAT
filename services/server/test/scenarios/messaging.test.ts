import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, identityFromSeed, newSeed } from "../reference/client";
import { encodeFrame } from "../reference/protocol/envelope";
import { keyMatchesId, peerId } from "../reference/protocol/identity";
import { inboxTopic } from "../reference/protocol/topics";
import { friends, pause, signedUp, stackUp } from "./stack";

test("a first message opens the session through the handshake challenge, both ways", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  const sent = await a.send(b.id, "first contact");
  assert.equal(sent.t, "init");
  assert.deepEqual(await b.next(a.id), { from: a.id, text: "first contact", msgId: sent.msgId });
  await b.send(a.id, "received");
  assert.equal((await a.next(b.id)).text, "received");
});

test("a burst sent before the peer replies arrives in full and in order", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  for (const text of ["hi", "you there?", "it is about tomorrow"]) await a.send(b.id, text);
  const got = [];
  for (let i = 0; i < 3; i++) got.push((await b.next(a.id)).text);
  assert.deepEqual(got, ["hi", "you there?", "it is about tomorrow"]);
});

test("a message sent while the peer is offline is delivered when it reconnects", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await b.close();
  await a.send(b.id, "sent while you were away");
  await b.auth.renew();
  await b.connect();
  assert.equal((await b.next(a.id)).text, "sent while you were away");
});

test("a conversation ratchets and stays in sync across many turns", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.send(b.id, "turn 0");
  assert.equal((await b.next(a.id)).text, "turn 0");
  for (let i = 1; i <= 6; i++) {
    await b.send(a.id, `b${i}`);
    assert.equal((await a.next(b.id)).text, `b${i}`);
    await a.send(b.id, `a${i}`);
    assert.equal((await b.next(a.id)).text, `a${i}`);
  }
});

test("messages delivered out of order still decrypt", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.send(b.id, "opener");
  await b.next(a.id);
  await b.send(a.id, "ack");
  await a.next(b.id);
  const sealed = [];
  for (let i = 0; i < 3; i++) sealed.push(await a.conversations.seal(b.id, `ooo-${i}`));
  for (const s of sealed) assert.equal(s.frame.t, "msg");
  for (const s of sealed.reverse()) assert.ok(await a.publish(s.outbound.topic, s.outbound.payload));
  const seen = new Set<string>();
  for (let i = 0; i < 3; i++) seen.add((await b.next(a.id)).text);
  assert.deepEqual([...seen].sort(), ["ooo-0", "ooo-1", "ooo-2"]);
});

test("a rewritten header does not decrypt and leaves the session usable", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.send(b.id, "establish");
  await b.next(a.id);
  await b.send(a.id, "ack");
  await a.next(b.id);
  const { frame, outbound } = await a.conversations.seal(b.id, "tamper me");
  const tampered = encodeFrame({ ...frame, n: frame.n + 1 })!;
  const drops = b.drops.length;
  await a.publish(outbound.topic, tampered);
  await pause(1500);
  assert.match(b.drops.slice(drops).join("; "), /did not authenticate/);
  await a.publish(outbound.topic, outbound.payload);
  assert.equal((await b.next(a.id)).text, "tamper me");
});

test("an init whose sender key does not hash to its sender is refused, the genuine one opens", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  const { frame, outbound } = await a.conversations.seal(b.id, "first contact");
  const impostor = identityFromSeed(newSeed());
  assert.equal(encodeFrame({ ...frame, senderPk: impostor.pk }), null, "the encoder refuses the forgery");
  const forged = Buffer.from(outbound.payload);
  impostor.pk.copy(forged, outbound.payload.indexOf(frame.senderPk!));
  const drops = b.drops.length;
  await a.publish(inboxTopic(b.id), forged);
  await pause(1500);
  assert.match(b.drops.slice(drops).join("; "), /not a frame/);
  await a.publish(inboxTopic(b.id), outbound.payload);
  assert.equal((await b.next(a.id)).text, "first contact");
});

test("the broker refuses wildcards and other clients' private topics", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  const { client: stranger } = await signedUp("sx");
  await stranger.connect();
  for (const filter of ["#", "cv/+", "cv/#", "hs/+", "u/+/presence", "+/+", `u/${b.id}/inbox`, `u/${b.id}/graph`]) {
    assert.deepEqual(await stranger.subscribe([filter]), [filter], `${filter} was granted`);
  }
  await stranger.publish(inboxTopic(b.id), "not a frame");
  await a.send(b.id, "still working");
  assert.equal((await b.next(a.id)).text, "still working");
});

test("a peer's key is served under its id and verifies; an unknown id is a 404", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  for (const [me, peer] of [
    [a, b],
    [b, a],
  ] as const) {
    const key = await me.api.peerKey(peer.id);
    assert.ok(keyMatchesId(key.toString("hex"), peer.id));
  }
  await assert.rejects(a.api.peerKey(peerId("00")), (e: unknown) => e instanceof ApiError && e.status === 404);
});

test("unfriending drops the live subscription immediately", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.send(b.id, "before");
  await b.next(a.id);
  const [retired] = a.conversations.topicsOf(b.id);
  await a.api.remove(b.id);
  await pause(1000);
  const drops = b.drops.length;
  await a.publish(retired!, "not a frame");
  await pause(1500);
  assert.ok(!b.drops.slice(drops).some((d) => d.includes(retired!)), "the retired topic still delivered");
});

test("a client reconnects with fresh credentials and keeps its sessions", async (t) => {
  if (!(await stackUp(t))) return;
  const { a, b } = await friends();
  await a.send(b.id, "one");
  await b.next(a.id);
  await a.close();
  assert.equal(await a.auth.refresh(), true);
  await a.connect();
  await b.send(a.id, "two");
  assert.equal((await a.next(b.id)).text, "two");
  await a.send(b.id, "three");
  assert.equal((await b.next(a.id)).text, "three");
});

test("a client is told about a new friendship without polling", async (t) => {
  if (!(await stackUp(t))) return;
  const [{ client: a }, { client: b, username }] = await Promise.all([signedUp("ga"), signedUp("gb")]);
  await Promise.all([a.connect(), b.connect()]);
  await a.api.invite(username);
  await b.api.accept(a.id);
  for (let i = 0; i < 40 && !a.conversations.peer(b.id); i++) await pause(100);
  assert.ok(a.conversations.peer(b.id), "the graph nudge synced the new friend");
  await a.send(b.id, "hello new friend");
  assert.equal((await b.next(a.id)).text, "hello new friend");
});
