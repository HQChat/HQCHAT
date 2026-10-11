import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import type { Api, Friend, PrekeyClaim } from "../../src/client/api";
import { Conversations, initHeaderOf, messageHeaderOf, type Outbound } from "../../src/client/conversation";
import { ApiError } from "../../src/client/http";
import { type Identity, identityFromSeed, newSeed } from "../../src/client/identity";
import { decodeSession, encodeSession, FileStore, MemoryStore } from "../../src/client/store";
import { openPayload, sealPayload } from "../../src/protocol/aead";
import { decodeFrame, encodeFrame } from "../../src/protocol/envelope";
import { hqcKem } from "../../src/protocol/hqc";
import { startAsInitiator } from "../../src/protocol/ratchet";
import { conversationTopic, handshakeTopic, inboxTopic } from "../../src/protocol/topics";

const topicId = () => crypto.randomBytes(32).toString("hex");

/** The prekey and key directory both test clients share, standing in for the server. */
class Directory {
  readonly keys = new Map<string, Buffer>();
  readonly bundles = new Map<string, { medium: Buffer; oneTime: Array<{ id: number; pk: Buffer }> }>();

  apiFor(id: string): Api {
    return {
      peerKey: async (peer: string) => this.keys.get(peer)!,
      claimPrekeys: async (peer: string): Promise<PrekeyClaim> => {
        const b = this.bundles.get(peer);
        if (!b) throw new ApiError(404, "NO_PREKEYS", "no prekeys");
        const ot = b.oneTime.shift();
        return { medium: b.medium.toString("hex"), oneTime: ot ? { id: ot.id, prekey: ot.pk.toString("hex") } : null };
      },
      publishPrekeys: async (medium: Buffer, oneTime: Array<{ id: number; pk: Buffer }>) => {
        const b = this.bundles.get(id);
        this.bundles.set(id, { medium, oneTime: [...(b?.oneTime ?? []), ...oneTime] });
      },
      prekeyCount: async () => this.bundles.get(id)?.oneTime.length ?? 0,
    } as unknown as Api;
  }
}

function client(dir: Directory, identity = identityFromSeed(newSeed())) {
  dir.keys.set(identity.id, identity.pk);
  const c = new Conversations({ identity, kem: hqcKem, api: dir.apiFor(identity.id), store: new MemoryStore() });
  return { identity, c };
}

/** Two friends with prekeys published and topics assigned. */
async function friends() {
  const dir = new Directory();
  const a = client(dir);
  const b = client(dir);
  const convoId = topicId();
  const handshakeId = topicId();
  const row = (x: Identity, name: string): Friend => ({ id: x.id, username: name, convoId, handshakeId });
  a.c.applyFriends([row(b.identity, "bob")]);
  b.c.applyFriends([row(a.identity, "alice")]);
  await Promise.all([a.c.ensurePrekeys(), b.c.ensurePrekeys()]);
  return { a, b, convoId, handshakeId };
}

/** Delivers outbound frames until both sides are quiet; returns what each side received. */
function pump(
  sides: { a: Conversations; b: Conversations },
  queue: Array<{ to: "a" | "b"; out: Outbound }>,
): { a: string[]; b: string[]; drops: string[]; delivered: { a: string[]; b: string[] } } {
  const got = {
    a: [] as string[],
    b: [] as string[],
    drops: [] as string[],
    delivered: { a: [] as string[], b: [] as string[] },
  };
  while (queue.length) {
    const { to, out } = queue.shift()!;
    const r = sides[to].receive(out.topic, out.payload);
    got[to].push(...r.messages.map((m) => m.text));
    if (r.dropped) got.drops.push(r.dropped);
    got.delivered[to].push(...(r.delivered ?? []));
    for (const o of r.outbound) queue.push({ to: to === "a" ? "b" : "a", out: o });
  }
  return got;
}

test("a first message is held, challenged, proven and then opened", async () => {
  const { a, b, handshakeId } = await friends();
  const sent = await a.c.seal(b.identity.id, "hello bob");
  assert.equal(sent.frame.t, "init");
  assert.equal(sent.outbound.topic, inboxTopic(b.identity.id));

  const first = b.c.receive(sent.outbound.topic, sent.outbound.payload);
  assert.deepEqual(first.messages, []);
  assert.equal(first.outbound.length, 1);
  assert.equal(first.outbound[0]!.topic, handshakeTopic(handshakeId));

  const got = pump({ a: a.c, b: b.c }, [{ to: "a", out: first.outbound[0]! }]);
  assert.deepEqual(got.b, ["hello bob"]);
  assert.ok(b.c.peer(a.identity.id)?.session, "the responder now holds a session");
});

test("a burst of inits before the proof arrives is delivered in full and in order", async () => {
  const { a, b } = await friends();
  const burst = [];
  for (const text of ["one", "two", "three"]) burst.push((await a.c.seal(b.identity.id, text)).outbound);
  const got = pump(
    { a: a.c, b: b.c },
    burst.map((out) => ({ to: "b" as const, out })),
  );
  assert.deepEqual(got.b, ["one", "two", "three"]);
});

test("a conversation ratchets in both directions across many turns", async () => {
  const { a, b } = await friends();
  const send = async (from: typeof a, to: typeof b, text: string) =>
    pump({ a: a.c, b: b.c }, [{ to: from === a ? "b" : "a", out: (await from.c.seal(to.identity.id, text)).outbound }]);
  assert.deepEqual((await send(a, b, "hi")).b, ["hi"]);
  for (let i = 0; i < 40; i++) {
    const [from, to] = i % 3 === 0 ? [b, a] : [a, b];
    const got = await send(from, to, `turn ${i}`);
    assert.deepEqual(from === a ? got.b : got.a, [`turn ${i}`], `turn ${i}`);
  }
  assert.ok(a.c.peer(b.identity.id)?.session?.pendingInit === undefined, "the init header stops once answered");
});

test("every opened message is acknowledged with a sealed receipt, and receipts are not", async () => {
  const { a, b } = await friends();
  const first = await a.c.seal(b.identity.id, "first");
  const got = pump({ a: a.c, b: b.c }, [{ to: "b", out: first.outbound }]);
  assert.deepEqual(got.b, ["first"]);
  assert.deepEqual(got.delivered.a, [first.frame.msgId], "the init's message is acknowledged");

  const next = await a.c.seal(b.identity.id, "second");
  const receipt = b.c.receive(next.outbound.topic, next.outbound.payload).outbound;
  assert.equal(receipt.length, 1);
  const decoded = decodeFrame(receipt[0]!.payload);
  assert.equal(decoded?.frame.t, "receipt");
  assert.equal(decoded?.frame.msgId, next.frame.msgId);

  const back = a.c.receive(receipt[0]!.topic, receipt[0]!.payload);
  assert.deepEqual(back.delivered, [next.frame.msgId]);
  assert.deepEqual(back.messages, []);
  assert.deepEqual(back.outbound, [], "a receipt is never acknowledged");
  assert.match(
    a.c.receive(receipt[0]!.topic, receipt[0]!.payload).dropped ?? "",
    /did not authenticate/,
    "nor replayed",
  );
});

test("frames on the wrong topic or for another client are dropped", async () => {
  const { a, b, convoId } = await friends();
  pump({ a: a.c, b: b.c }, [{ to: "b", out: (await a.c.seal(b.identity.id, "open")).outbound }]);
  const reply = await b.c.seal(a.identity.id, "reply");
  pump({ a: a.c, b: b.c }, [{ to: "a", out: reply.outbound }]);
  const msg = await a.c.seal(b.identity.id, "misplaced");
  assert.equal(msg.outbound.topic, conversationTopic(convoId));
  assert.match(b.c.receive(inboxTopic(b.identity.id), msg.outbound.payload).dropped ?? "", /expected/);

  const stranger = client(new Directory());
  assert.match(stranger.c.receive(msg.outbound.topic, msg.outbound.payload).dropped ?? "", /not a friend/);
});

test("a proof that does not match discards the held init", async () => {
  const { a, b, handshakeId } = await friends();
  const sent = await a.c.seal(b.identity.id, "hello");
  const chal = b.c.receive(sent.outbound.topic, sent.outbound.payload).outbound[0]!;
  const proof = a.c.receive(chal.topic, chal.payload).outbound[0]!;
  const forged = Buffer.from(proof.payload);
  forged[forged.length - 1]! ^= 0xff;
  const r = b.c.receive(handshakeTopic(handshakeId), forged);
  assert.match(r.dropped ?? "", /did not match/);
  assert.deepEqual(r.messages, []);
  assert.equal(b.c.peer(a.identity.id)?.session, undefined);
});

test("a challenge is answered only while this client's own handshake is open", async () => {
  const { a, b } = await friends();
  const sent = await a.c.seal(b.identity.id, "hello");
  const chal = b.c.receive(sent.outbound.topic, sent.outbound.payload).outbound[0]!;
  pump({ a: a.c, b: b.c }, [{ to: "a", out: chal }]);
  pump({ a: a.c, b: b.c }, [{ to: "a", out: (await b.c.seal(a.identity.id, "reply")).outbound }]);
  const replayed = a.c.receive(chal.topic, chal.payload);
  assert.deepEqual(replayed.outbound, []);
  assert.match(replayed.dropped ?? "", /did not start/);
});

test("sealing for a friend with no prekeys throws NO_PREKEYS and opens nothing", async () => {
  const dir = new Directory();
  const a = client(dir);
  const b = client(dir);
  a.c.applyFriends([{ id: b.identity.id, username: "b", convoId: topicId(), handshakeId: topicId() }]);
  await assert.rejects(a.c.seal(b.identity.id, "hi"), (e: unknown) => e instanceof ApiError && e.code === "NO_PREKEYS");
});

test("applyFriends adds, renames, moves and forgets friends with their topics", () => {
  const dir = new Directory();
  const a = client(dir);
  const p = identityFromSeed(newSeed()).id;
  const q = identityFromSeed(newSeed()).id;
  const t1 = { convoId: topicId(), handshakeId: topicId() };
  const t2 = { convoId: topicId(), handshakeId: topicId() };

  const added = a.c.applyFriends([
    { id: p, username: "p", ...t1 },
    { id: q, username: "q", ...t1 },
  ]);
  assert.deepEqual(
    added.subscribe.sort(),
    [conversationTopic(t1.convoId), handshakeTopic(t1.handshakeId)]
      .concat([conversationTopic(t1.convoId), handshakeTopic(t1.handshakeId)])
      .sort(),
  );
  assert.deepEqual(a.c.subscriptions()[0], inboxTopic(a.identity.id));

  const moved = a.c.applyFriends([
    { id: p, username: "p2", ...t2 },
    { id: q, username: "q", ...t1 },
  ]);
  assert.deepEqual(moved.subscribe, [conversationTopic(t2.convoId), handshakeTopic(t2.handshakeId)]);
  assert.deepEqual(moved.unsubscribe, [conversationTopic(t1.convoId), handshakeTopic(t1.handshakeId)]);
  assert.equal(a.c.peer(p)?.username, "p2");

  const removed = a.c.applyFriends([{ id: p, username: "p2", ...t2 }]);
  assert.deepEqual(removed.unsubscribe, [conversationTopic(t1.convoId), handshakeTopic(t1.handshakeId)]);
  assert.equal(a.c.peer(q), undefined);
});

test("ensurePrekeys tops up only below the threshold", async () => {
  const dir = new Directory();
  const a = client(dir);
  assert.equal(await a.c.ensurePrekeys(), 8);
  assert.equal(await a.c.ensurePrekeys(), 0);
  dir.bundles.get(a.identity.id)!.oneTime.splice(0, 5);
  assert.equal(await a.c.ensurePrekeys(), 5);
});

test("a session survives the store codec byte for byte, and junk is refused", () => {
  const responder = identityFromSeed(newSeed());
  const medium = hqcKem.generateKeypair();
  const { state } = startAsInitiator(hqcKem, {
    identityPk: responder.pk,
    mediumPk: medium.pk,
    oneTimePk: null,
    oneTimeId: null,
  });
  const back = decodeSession(JSON.parse(JSON.stringify(encodeSession(state))));
  assert.deepEqual(back, state);
  for (const junk of [null, 1, "x", {}, { root: 1 }]) assert.equal(decodeSession(junk), null);
});

test("FileStore round-trips peers and prekeys", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-store-"));
  const store = new FileStore(path.join(dir, "state.json"));
  const { a, b } = await friends();
  pump({ a: a.c, b: b.c }, [{ to: "b", out: (await a.c.seal(b.identity.id, "hi")).outbound }]);
  store.save(b.c.state);
  const back = store.load();
  assert.deepEqual(back.peers, b.c.state.peers);
  assert.deepEqual([...back.prekeys!.oneTime], [...b.c.state.prekeys!.oneTime]);
  assert.equal(fs.statSync(path.join(dir, "state.json")).mode & 0o777, 0o600);
});

test("header adapters carry exactly the fields the ratchet needs", async () => {
  const { a, b } = await friends();
  const { frame } = await a.c.seal(b.identity.id, "x");
  const decoded = decodeFrame(encodeFrame(frame)!)!.frame;
  assert.deepEqual(Object.keys(messageHeaderOf(decoded)).sort(), ["cid", "n", "pn", "rk"]);
  const init = initHeaderOf(decoded)!;
  assert.equal(init.cid, decoded.cid);
  const { ctId: _ctId, ...withoutCtId } = decoded;
  assert.equal(initHeaderOf(withoutCtId), null);
});

test("payload sealing binds the AAD and refuses a short tag", () => {
  const key = crypto.randomBytes(32);
  const aad = Buffer.from("header");
  const sealed = sealPayload("attack at dawn", key, aad);
  assert.equal(openPayload(sealed, key, aad), "attack at dawn");
  assert.throws(() => openPayload(sealed, key, Buffer.from("other")));
  assert.throws(() => openPayload(sealed.subarray(0, 20), key, aad));
});

test("the client delivers a released burst before a later frame whose receipt is quicker", async () => {
  const { Client } = await import("../../src/client/client");
  const identity = identityFromSeed(newSeed());
  const c = new Client({ baseUrl: "https://hqchat.invalid", endpoint: { url: "wss://hqchat.invalid/mqtt" }, identity });
  const receipt = (topic: string) => ({ topic, payload: Buffer.alloc(0) });
  // The proof releases two held messages with a receipt each; the next init,
  // opened right after, carries one. Every publish takes a tick of the broker.
  const results = [
    {
      messages: [
        { from: "a", text: "hi", msgId: "1" },
        { from: "a", text: "you there?", msgId: "2" },
      ],
      outbound: [receipt("r1"), receipt("r2")],
    },
    { messages: [{ from: "a", text: "it is about tomorrow", msgId: "3" }], outbound: [receipt("r3")] },
  ];
  c.conversations.receive = () => results.shift()!;
  const fake = { publish: () => new Promise<boolean>((r) => setTimeout(() => r(true), 5)) };
  const internals = c as unknown as { transport: unknown; handle(topic: string, payload: Buffer): Promise<void> };
  internals.transport = fake;
  const got: string[] = [];
  c.onMessage((m) => got.push(m.text));
  await Promise.all([internals.handle("hs/x", Buffer.alloc(0)), internals.handle("u/x/inbox", Buffer.alloc(0))]);
  assert.deepEqual(got, ["hi", "you there?", "it is about tomorrow"]);
});
