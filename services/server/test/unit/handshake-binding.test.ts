// The handshake proof is bound to the init it releases (handshake v2).
//
// The attack this pins shut: Mallory, who can publish to Bob's inbox and claim
// Bob's prekeys (any friend of Bob, or the server), builds an init that names
// Alice — every value in it is public. Bob holds it and challenges "Alice".
// Alice, who has her own handshake with Bob pending, answers. Under v1 the
// proof covered only the nonce and the two ids, so Alice's answer released
// Mallory's init: Bob saw Mallory's text as Alice's, Alice's real messages
// stopped opening, and whoever read cv/ could decrypt Bob's replies.
//
// Under v2 the proof covers the init's transcript. Alice proves only the init
// she sent, so the forged one stays held and expires.
//
// The KEM is a toy X25519 KEM padded to HQC sizes: what is under test is the
// state machine, and it needs no native library.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import type { Friend } from "../../src/client/api";
import { Conversations, type Outbound } from "../../src/client/conversation";
import { MemoryStore } from "../../src/client/store";
import { HANDSHAKE_TRANSCRIPT_BYTES, initTranscript } from "../../src/protocol/handshake";
import { peerId } from "../../src/protocol/identity";
import type { InitHeader, Kem } from "../../src/protocol/ratchet";

const PK = 7237;
const SK = 7333;
const CT = 14421;
const PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI = Buffer.from("302a300506032b656e032100", "hex");
const priv = (k: Buffer) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8, k]), format: "der", type: "pkcs8" });
const pub = (k: Buffer) => crypto.createPublicKey({ key: Buffer.concat([SPKI, k]), format: "der", type: "spki" });
const pad = (b: Buffer, n: number) => Buffer.concat([b, Buffer.alloc(n - b.length)]);
const dh = (sk: Buffer, pk: Buffer) =>
  crypto
    .createHash("sha256")
    .update(crypto.diffieHellman({ privateKey: priv(sk.subarray(0, 32)), publicKey: pub(pk.subarray(0, 32)) }))
    .digest();

const toyKem: Kem = {
  generateKeypair() {
    const s = crypto.randomBytes(32);
    const p = (crypto.createPublicKey(priv(s)).export({ format: "der", type: "spki" }) as Buffer).subarray(12);
    return { pk: pad(p, PK), sk: pad(s, SK) };
  },
  encapsulate(pk) {
    const e = toyKem.generateKeypair();
    return { ct: pad(e.pk.subarray(0, 32), CT), ss: dh(e.sk, pk) };
  },
  decapsulate: (sk, ct) => dh(sk, ct),
};

function identity() {
  const { pk, sk } = toyKem.generateKeypair();
  const pkHex = pk.toString("hex");
  return { pk, sk, pkHex, id: peerId(pkHex) };
}

/** Stands in for the server's key directory and prekey store. */
class Directory {
  readonly keys = new Map<string, Buffer>();
  readonly bundles = new Map<string, { medium: Buffer; oneTime: Array<{ id: number; pk: Buffer }> }>();
  api(self: string) {
    return {
      peerKey: async (peer: string) => this.keys.get(peer)!,
      claimPrekeys: async (peer: string) => {
        const b = this.bundles.get(peer)!;
        const ot = b.oneTime.shift();
        return { medium: b.medium.toString("hex"), oneTime: ot ? { id: ot.id, prekey: ot.pk.toString("hex") } : null };
      },
      publishPrekeys: async (medium: Buffer, oneTime: Array<{ id: number; pk: Buffer }>) => {
        const b = this.bundles.get(self);
        this.bundles.set(self, { medium, oneTime: [...(b?.oneTime ?? []), ...oneTime] });
      },
      prekeyCount: async () => this.bundles.get(self)?.oneTime.length ?? 0,
    } as never;
  }
}

/** Alice and Bob, friends with prekeys, and Mallory holding Alice's PUBLIC key and her own secret. */
async function scene() {
  const dir = new Directory();
  const alice = identity();
  const bob = identity();
  for (const x of [alice, bob]) dir.keys.set(x.id, x.pk);
  const row = (x: { id: string }, username: string): Friend => ({
    id: x.id,
    username,
    convoId: "c".repeat(64),
    handshakeId: "d".repeat(64),
  });
  const make = (who: ReturnType<typeof identity>, api: string) =>
    new Conversations({ identity: who, kem: toyKem, api: dir.api(api), store: new MemoryStore() });

  const A = make(alice, alice.id);
  const B = make(bob, bob.id);
  A.applyFriends([row(bob, "bob")]);
  B.applyFriends([row(alice, "alice")]);
  await A.ensurePrekeys();
  await B.ensurePrekeys();

  const mallory = identity();
  const M = make({ ...alice, sk: mallory.sk }, mallory.id);
  M.applyFriends([row(bob, "bob")]); // the topic ids too: the strongest attacker, the server
  return { alice, bob, A, B, M };
}

/** Delivers frames to their recipient until quiet; returns what Bob displayed and why things were dropped. */
function pump(
  sides: { A: Conversations; B: Conversations },
  queue: Array<{ to: "A" | "B"; out: Outbound }>,
): { bobSaw: Array<{ from: string; text: string }>; drops: string[] } {
  const got = { bobSaw: [] as Array<{ from: string; text: string }>, drops: [] as string[] };
  while (queue.length) {
    const { to, out } = queue.shift()!;
    const r = sides[to].receive(out.topic, out.payload);
    if (to === "B") got.bobSaw.push(...r.messages.map((m) => ({ from: m.from, text: m.text })));
    if (r.dropped) got.drops.push(r.dropped);
    for (const o of r.outbound) queue.push({ to: to === "A" ? "B" : "A", out: o });
  }
  return got;
}

for (const order of ["forged first", "genuine first"] as const) {
  test(`a forged init naming Alice is not released by Alice's proof (${order})`, async () => {
    const { alice, bob, A, B, M } = await scene();
    const forged = (await M.seal(bob.id, "Hi Bob, it's Alice. New number, send the code here.")).outbound;
    const genuine = (await A.seal(bob.id, "hello bob (really Alice)")).outbound;
    const arrivals = order === "forged first" ? [forged, genuine] : [genuine, forged];

    const got = pump(
      { A, B },
      arrivals.map((out) => ({ to: "B" as const, out })),
    );

    assert.deepEqual(got.bobSaw, [{ from: alice.id, text: "hello bob (really Alice)" }], "only Alice's own init opens");
    // Alice answered the challenge about the forged init too; that answer opened nothing.
    assert.ok(
      got.drops.some((d) => d === "handshake proof did not match" || d === "proof for no open challenge"),
      `the challenge about the forged init released nothing: ${got.drops}`,
    );

    // Mallory has no session Bob accepts: another forged frame is dropped…
    const more = (await M.seal(bob.id, "Still me (Alice). Did you send it?")).outbound;
    assert.deepEqual(B.receive(more.topic, more.payload).messages, []);

    // …Alice's next message still opens…
    const real2 = (await A.seal(bob.id, "Bob? It's really me")).outbound;
    assert.deepEqual(
      B.receive(real2.topic, real2.payload).messages.map((m) => m.text),
      ["Bob? It's really me"],
    );

    // …and Bob's reply is unreadable with Mallory's state.
    const reply = (await B.seal(alice.id, "the code is 4817")).outbound;
    assert.deepEqual(M.receive(reply.topic, reply.payload).messages, [], "the attacker cannot read Bob's reply");
    assert.deepEqual(
      A.receive(reply.topic, reply.payload).messages.map((m) => m.text),
      ["the code is 4817"],
    );
  });
}

test("a burst of Alice's inits shares one challenge and opens in order", async () => {
  const { bob, A, B } = await scene();
  const burst: Outbound[] = [];
  for (const text of ["one", "two", "three"]) burst.push((await A.seal(bob.id, text)).outbound);
  const first = B.receive(burst[0]!.topic, burst[0]!.payload);
  assert.equal(first.outbound.length, 1, "one challenge for the burst");
  for (const out of burst.slice(1)) {
    assert.equal(
      B.receive(out.topic, out.payload).outbound.length,
      0,
      "the rest of the burst is held, not re-challenged",
    );
  }
  const got = pump({ A, B }, [{ to: "A", out: first.outbound[0]! }]);
  assert.deepEqual(
    got.bobSaw.map((m) => m.text),
    ["one", "two", "three"],
  );
});

test("a flood of forged inits neither opens nor crowds out Alice's init", async () => {
  const { alice, bob, A, B, M } = await scene();
  for (let i = 0; i < 10; i++) {
    // A fresh initiator session each time, so every forged init has its own transcript.
    delete M.peer(bob.id)!.session;
    const out = (await M.seal(bob.id, `forged ${i}`)).outbound;
    assert.equal(B.receive(out.topic, out.payload).outbound.length, 1, "each distinct init is challenged");
  }
  const genuine = (await A.seal(bob.id, "hello bob")).outbound;
  const got = pump({ A, B }, [{ to: "B", out: genuine }]);
  assert.deepEqual(got.bobSaw, [{ from: alice.id, text: "hello bob" }]);
});

test("the transcript covers every session-defining field", () => {
  const a = "a".repeat(64);
  const b = "b".repeat(64);
  const base: InitHeader = {
    ctId: Buffer.alloc(CT, 1),
    ctMt: Buffer.alloc(CT, 2),
    ctOt: Buffer.alloc(CT, 3),
    otId: 7,
    rk: Buffer.alloc(PK, 4),
    cid: "e".repeat(32),
  };
  const t = initTranscript(a, b, base);
  assert.equal(t.length, HANDSHAKE_TRANSCRIPT_BYTES);
  const flip = (buf: Buffer) => {
    const c = Buffer.from(buf);
    c[0]! ^= 1;
    return c;
  };
  const variants: Array<[string, Buffer]> = [
    ["sender", initTranscript(b, b, base)],
    ["recipient", initTranscript(a, a, base)],
    ["rk", initTranscript(a, b, { ...base, rk: flip(base.rk) })],
    ["ctId", initTranscript(a, b, { ...base, ctId: flip(base.ctId) })],
    ["ctMt", initTranscript(a, b, { ...base, ctMt: flip(base.ctMt) })],
    ["ctOt", initTranscript(a, b, { ...base, ctOt: flip(base.ctOt!) })],
    ["otId", initTranscript(a, b, { ...base, otId: 8 })],
    ["no one-time key", initTranscript(a, b, { ...base, ctOt: null, otId: null })],
  ];
  for (const [name, other] of variants) assert.ok(!other.equals(t), `changing ${name} changes the transcript`);
  // An otId without a ctOt is not part of the session, so it is not part of the transcript.
  assert.ok(
    initTranscript(a, b, { ...base, ctOt: null, otId: null }).equals(
      initTranscript(a, b, { ...base, ctOt: null, otId: 9 }),
    ),
  );
});
