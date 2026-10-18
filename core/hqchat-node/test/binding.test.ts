// The Node addon against the shared vectors, Node's own crypto, and the TS
// hqn/1 initiator (services/server/test/reference/protocol/noise.ts) driving the Rust
// gateway. Run from services/server after core/hqchat-node/build.sh:
//
//   node --import tsx --test ../../core/hqchat-node/test/*.test.ts

import assert from "node:assert/strict";
import { createHash, hkdfSync, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { FrameReader, HqnInitiator, type Kem, x25519KeyPair } from "../../../services/server/test/reference/protocol/noise";

const require = createRequire(__filename);
const core = require("../hqchat_node.node");
const helpers = path.join(__dirname, "..", "..", "..", "services", "server", "test", "helpers");
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

test("HQC matches the shipped known answers", () => {
  const { pk, sk } = core.hqcKeypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i)));
  assert.equal(sha(pk), "25cebbbb79c410d5b8c1ae0d5e5c35ff2735e7c1f51105a21e6ea7f83391f56c");
  assert.equal(sha(sk), "79471d21ef264d3f59c693ed20f44c0a59daec8b8b9c2708da529ef491a8022b");
  const ct = Buffer.alloc(14421);
  for (let i = 0; i < ct.length; i++) ct[i] = (i * 7 + 13) & 0xff;
  assert.equal(sha(core.hqcDecapsulate(sk, ct)), "8a380b3e4d305322ecb4f438bf060f4da8d0f395614be39c881f67018a3ad0f4");
  const e = core.hqcEncapsulate(pk);
  assert.ok(core.hqcDecapsulate(sk, e.ct).equals(e.ss));
  assert.throws(() => core.hqcEncapsulate(Buffer.alloc(10)), /7237/);
});

test("the sign-in proof is Node's HKDF", () => {
  const ss = randomBytes(32);
  const want = Buffer.from(hkdfSync("sha256", ss, Buffer.from("salt"), Buffer.from("auth"), 32));
  assert.ok(core.authProof(ss).equals(want));
  assert.equal(core.authProofMatches(want, want), true);
  assert.equal(core.authProofMatches(want, Buffer.alloc(32)), false);
  assert.equal(core.authProofMatches(want, want.subarray(1)), false);
});

test("ids and topics match identity-vectors.json", () => {
  const v = JSON.parse(fs.readFileSync(path.join(helpers, "identity-vectors.json"), "utf8"));
  for (const k of v.keys) {
    assert.equal(core.peerId(k.publicKeyHex), k.id, k.label);
    assert.equal(core.keyMatchesId(k.publicKeyHex, k.id), true);
    assert.equal(core.isPeerId(k.id), true);
  }
  assert.equal(core.isPeerId("ABC"), false);
  const t = "8".repeat(64);
  assert.equal(core.conversationTopic(t), `cv/${t}`);
  assert.equal(core.handshakeTopic(t), `hs/${t}`);
  assert.throws(() => core.conversationTopic("x"));
});

test("CONNECT proofs from mqtt-proof-vectors.json parse and verify, and nothing else does", () => {
  const v = JSON.parse(fs.readFileSync(path.join(helpers, "mqtt-proof-vectors.json"), "utf8"));
  for (const c of v.cases) {
    const p = core.parseConnectProof(c.connectField);
    assert.ok(p, c.label);
    assert.equal(p.keyId, c.keyId);
    assert.equal(p.ts, c.ts);
    assert.equal(core.verifyConnectProof(Buffer.from(c.publicKeyHex, "hex"), c.clientid, p), true, c.label);
    assert.equal(core.verifyConnectProof(Buffer.from(c.publicKeyHex, "hex"), "0".repeat(64), p), false);
  }
  assert.equal(core.parseConnectProof("v2.x"), null);
  assert.equal(core.isFreshTimestamp(1000, 1060), true);
  assert.equal(core.isFreshTimestamp(1000, 1061), false);
});

test("the Rust gateway completes a handshake with the TS initiator", () => {
  const key = { keyId: 1, x25519: randomBytes(32), hqcSeed: randomBytes(32) };
  const pair = new core.GatewayKeyPair(key);
  const pub = pair.publicKey();
  const { sk } = core.hqcKeypairFromSeed(key.hqcSeed);
  const kem: Kem = {
    encapsulate: (pk) => core.hqcEncapsulate(pk),
    decapsulate: (s, ct) => core.hqcDecapsulate(s, ct),
  };
  const client = new HqnInitiator({ keyId: 1, x25519: pub.x25519, hqc: pub.hqc }, { kem, ephemeral: x25519KeyPair() });
  const connect = Buffer.from("MQTT CONNECT bytes");
  const msg1 = client.writeMessage1(connect);
  assert.equal(msg1.length, core.hqnMsg1Length(connect.length));

  const gw = new core.HqnGatewayHandshake(pair);
  assert.ok(core.HqnGatewayHandshake.ephemeralOf(msg1).equals(msg1.subarray(0, 32)));
  const ct = gw.openMessage1(msg1);
  // The decapsulation a worker would run, with the gateway's HQC secret.
  assert.ok(gw.finishMessage1(core.hqcDecapsulate(sk, ct)).equals(connect));
  const m2 = gw.writeMessage2(Buffer.alloc(0));
  const msg2 = m2.takeMessage();
  const gt = m2.takeTransport();
  const { transport: ct2 } = client.readMessage2(msg2);
  assert.ok(gt.handshakeHash.equals(ct2.handshakeHash), "both ends agree on the channel binding");

  // Both directions of the transport.
  const up = ct2.send.encryptWithAd(Buffer.alloc(0), Buffer.from("PUBLISH"));
  assert.equal(gt.open(core.hqnFrame(up)).toString(), "PUBLISH");
  const reader = new FrameReader();
  reader.push(gt.seal(Buffer.from("CONNACK")));
  assert.equal(ct2.recv.decryptWithAd(Buffer.alloc(0), reader.next()!).toString(), "CONNACK");
  assert.throws(() => gt.open(core.hqnFrame(Buffer.alloc(40))), "a forged frame closes the connection");
});

test("random bytes fail the gateway's first phase", () => {
  const gw = new core.HqnGatewayHandshake(
    new core.GatewayKeyPair({ keyId: 1, x25519: randomBytes(32), hqcSeed: randomBytes(32) }),
  );
  assert.throws(() => gw.openMessage1(randomBytes(core.hqnMsg1Length(10))));
});

test("the Engine keeps an identity on disk and starts by signing in", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-node-"));
  try {
    const opts = { serverUrl: "https://hqchat.test", profileId: "bot", dir };
    const e = new core.Engine(opts);
    assert.equal(e.deviceKey, null);
    assert.deepEqual(e.createIdentity().map((x: { kind: string }) => x.kind), ["tierChanged"]);
    const deviceKey: Buffer = e.deviceKey;
    assert.equal(deviceKey.length, 32);
    const first = e.start(1_790_000_000_000, "wired");
    const http = first.find((x: { kind: string }) => x.kind === "http");
    assert.equal(http.path, "/auth/init");
    assert.equal(JSON.parse(http.body.toString()).pk.length, 7237 * 2);

    const again = new core.Engine({ ...opts, deviceKey });
    assert.deepEqual(again.unlock(0).map((x: { kind: string }) => x.kind), ["friendsChanged"]);
    assert.deepEqual(again.history("a".repeat(64), null, 10), []);
    assert.throws(() => new core.Engine({ ...opts, deviceKey: randomBytes(32) }).unlock(0), "another device key");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
