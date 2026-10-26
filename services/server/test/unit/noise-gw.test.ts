// noise-gw (noise-gw/gateway.ts): the first process on the public internet to
// read a raw-TCP client's bytes. Driven over real loopback sockets, against a
// fake broker, with a fake KEM of the real sizes — every check here is about
// what the gateway does with bytes, and the KEM is tested on its own.
//
// Most of these are refusals, because that is almost all an internet-facing
// listener ever does. The property that matters most: garbage never costs a
// decapsulation.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as net from "node:net";
import { after, test } from "node:test";
import { core, type GatewayKeyPair, type HqnSecret } from "@hqchat/common/core";
import { createGateway, type GatewayEvent, type GatewayLimits } from "../../src/gateway/gateway";
import { parseKeySeeds } from "../../src/gateway/keys";
import { connectClientId } from "../../src/gateway/mqtt-connect";
import {
  FrameReader,
  frame,
  HQC_CIPHERTEXT_BYTES,
  HQC_PUBLIC_KEY_BYTES,
  HQN_VERSION,
  HqnInitiator,
  type Kem,
  msg1Length,
  sealFrames,
  type Transport,
} from "../reference/protocol/noise";

// --- fixtures ----------------------------------------------------------------

const fakeKem: Kem = {
  encapsulate: () => {
    const ct = crypto.randomBytes(HQC_CIPHERTEXT_BYTES);
    return { ct, ss: crypto.createHash("sha256").update(ct).digest() };
  },
  decapsulate: (_sk, ct) => crypto.createHash("sha256").update(ct).digest(),
};

// The gateway's key is the core's; the client below is the TypeScript
// initiator with a fake KEM, so the two sides are independent implementations.
const KEY = new core.GatewayKeyPair({ keyId: 3, x25519: crypto.randomBytes(32), hqcSeed: crypto.randomBytes(32) });
const KEY_PUB = { keyId: KEY.keyId, x25519: KEY.publicKey().x25519, hqc: KEY.publicKey().hqc };

const CLIENT_ID = "ab".repeat(32);

/** A minimal MQTT 3.1.1 CONNECT with the given client id. */
function connectPacket(clientId = CLIENT_ID): Buffer {
  const vh = Buffer.concat([Buffer.from([0x00, 0x04]), Buffer.from("MQTT"), Buffer.from([0x04, 0x02, 0x00, 0x3c])]);
  const id = Buffer.from(clientId, "utf8");
  const payload = Buffer.concat([Buffer.from([id.length >> 8, id.length & 0xff]), id]);
  const body = Buffer.concat([vh, payload]);
  return Buffer.concat([Buffer.from([0x10, body.length]), body]);
}
const CONNACK = Buffer.from([0x20, 0x02, 0x00, 0x00]);

/** A fake broker: records what it receives, answers CONNECT with CONNACK, then
 *  echoes everything else back. */
async function fakeBroker() {
  const received: Buffer[] = [];
  const server = net.createServer((s) => {
    let first = true;
    s.on("data", (d: Buffer) => {
      received.push(d);
      if (first) {
        first = false;
        s.write(CONNACK);
      } else s.write(d);
    });
    s.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as net.AddressInfo).port, received, server };
}

async function gateway(opts: {
  limits?: Partial<GatewayLimits>;
  upstreamPort: number;
  decapsulate?: (k: number, ct: Buffer) => Promise<HqnSecret>;
}) {
  const events: GatewayEvent[] = [];
  let decaps = 0;
  const gw = createGateway({
    keys: new Map([[KEY.keyId, KEY]]),
    decapsulate:
      opts.decapsulate ??
      (async (_k, ct) => {
        decaps++;
        return core.HqnSecret.fromBytes(fakeKem.decapsulate(Buffer.alloc(0), ct));
      }),
    upstream: { host: "127.0.0.1", port: opts.upstreamPort },
    ...(opts.limits ? { limits: opts.limits } : {}),
    onEvent: (e) => events.push(e),
  });
  await new Promise<void>((r) => gw.server.listen(0, "127.0.0.1", r));
  const port = (gw.server.address() as net.AddressInfo).port;
  return { ...gw, port, events, decaps: () => decaps };
}

const toClose: net.Server[] = [];
after(() => {
  for (const s of toClose) s.close();
});

function dial(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect({ port, host: "127.0.0.1" }, () => resolve(s));
    s.on("error", reject);
  });
}

/** Resolves when the socket is closed by the far end. */
const closed = (s: net.Socket) =>
  new Promise<void>((r) => {
    if (s.destroyed) r();
    else s.once("close", () => r());
  });

/** A full client: header, msg1 carrying a CONNECT, msg2, then a transport. */
async function handshake(port: number, connect = connectPacket(), kem: Kem = fakeKem) {
  const s = await dial(port);
  const init = new HqnInitiator(KEY_PUB, { kem });
  const msg1 = init.writeMessage1(connect);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(msg1)]));
  const reader = new FrameReader();
  const frames: Buffer[] = [];
  let transport: Transport | null = null;
  const waiters: (() => void)[] = [];
  s.on("data", (d: Buffer) => {
    reader.push(d);
    for (let f = reader.next(); f; f = reader.next()) {
      if (!transport) transport = init.readMessage2(f).transport;
      else frames.push(transport.recv.decryptWithAd(Buffer.alloc(0), f));
      for (const w of waiters.splice(0)) w();
    }
  });
  const nextFrame = async (): Promise<Buffer> => {
    while (frames.length === 0) await new Promise<void>((r) => waiters.push(r));
    return frames.shift()!;
  };
  await new Promise<void>((r) => {
    const tick = () => (transport ? r() : waiters.push(tick));
    tick();
  });
  return { s, msg1, t: transport as unknown as Transport, nextFrame };
}

// --- the happy path -------------------------------------------------------------

test("a client's CONNECT reaches the broker verbatim, and the stream flows both ways", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  const connect = connectPacket();
  const c = await handshake(gw.port, connect);

  assert.ok((await c.nextFrame()).equals(CONNACK), "CONNACK arrives as the first transport frame");
  assert.ok(
    Buffer.concat(broker.received).subarray(0, connect.length).equals(connect),
    "the broker got the CONNECT as sent",
  );

  const publish = Buffer.from([0x30, 0x05, 0x00, 0x01, 0x74, 0x68, 0x69]);
  c.s.write(sealFrames(c.t.send, publish));
  assert.ok((await c.nextFrame()).equals(publish), "an upstream packet reaches the broker and its echo comes back");

  const est = gw.events.find((e) => e.t === "established");
  assert.ok(est && est.t === "established" && est.clientId === CLIENT_ID, "the log names the client id");
  assert.equal(gw.stats().established, 1);
  assert.equal(gw.stats().halfOpen, 0);
  c.s.destroy();
});

test("a large upstream write is split into frames and reassembled for the broker", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const big = crypto.randomBytes(200_000);
  c.s.write(sealFrames(c.t.send, big));
  const echoed: Buffer[] = [];
  let n = 0;
  while (n < big.length) {
    const f = await c.nextFrame();
    echoed.push(f);
    n += f.length;
  }
  assert.ok(Buffer.concat(echoed).equals(big));
  c.s.destroy();
});

// --- refusals: none of these may cost a decapsulation -----------------------------

test("a wrong version or unknown key id is closed at the header", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  for (const header of [
    [HQN_VERSION + 1, KEY.keyId],
    [HQN_VERSION, KEY.keyId + 1],
    [0x16, 0x03],
  ]) {
    const s = await dial(gw.port);
    s.write(Buffer.from(header));
    await closed(s);
  }
  assert.equal(gw.stats().refused.header, 3);
  assert.equal(gw.decaps(), 0);
});

test("a msg1 length outside what a CONNECT can produce is closed before any cryptography", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { maxConnectBytes: 1024 } });
  toClose.push(gw.server);
  for (const len of [0, msg1Length(0) - 1, msg1Length(1024) + 1, 65535]) {
    const s = await dial(gw.port);
    const pre = Buffer.alloc(4);
    pre[0] = HQN_VERSION;
    pre[1] = KEY.keyId;
    pre.writeUInt16BE(len, 2);
    s.write(pre);
    await closed(s);
  }
  assert.equal(gw.stats().refused.length, 4);
  assert.equal(gw.decaps(), 0);
});

test("random bytes of a valid length fail the X25519 layer and never reach decapsulation", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  for (let i = 0; i < 5; i++) {
    const s = await dial(gw.port);
    s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(crypto.randomBytes(msg1Length(100)))]));
    await closed(s);
  }
  assert.equal(gw.stats().refused.noise, 5);
  assert.equal(gw.decaps(), 0, "garbage must not cost a decapsulation");
});

test("bytes after msg1, before msg2, are refused", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  const msg1 = new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket());
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(msg1), Buffer.from([1, 2, 3])]));
  await closed(s);
  assert.equal(gw.stats().refused.length, 1);
});

test("a replayed msg1 is refused, and the broker never sees its CONNECT twice", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const s = await dial(gw.port);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(c.msg1)]));
  await closed(s);
  assert.equal(gw.stats().refused.replay, 1);
  const connects = broker.received.filter((b) => b[0] === 0x10).length;
  assert.equal(connects, 1);
  c.s.destroy();
});

test("a client that stalls mid-handshake is closed at the deadline", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { handshakeTimeoutMs: 150 } });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(Buffer.from([HQN_VERSION, KEY.keyId, 0x39])); // half a length prefix, then nothing
  const t0 = Date.now();
  await closed(s);
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(gw.stats().refused.timeout, 1);
  // The client can see the close before the gateway's own close handler runs.
  for (let i = 0; i < 50 && gw.stats().halfOpen !== 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(gw.stats().halfOpen, 0, "a timed-out handshake gives its slot back");
});

test("per-address limits: concurrent handshakes and handshake rate", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { perIpHandshakes: 2, handshakeTimeoutMs: 2000 } });
  toClose.push(gw.server);
  const a = await dial(gw.port),
    b = await dial(gw.port),
    c = await dial(gw.port);
  await closed(c);
  assert.equal(gw.stats().refused["ip-handshakes"], 1);
  a.destroy();
  b.destroy();

  const gw2 = await gateway({ upstreamPort: broker.port, limits: { perIpHandshakesPerMinute: 2 } });
  toClose.push(gw2.server);
  const x = await dial(gw2.port),
    y = await dial(gw2.port),
    z = await dial(gw2.port);
  await closed(z);
  assert.equal(gw2.stats().refused["ip-rate"], 1);
  x.destroy();
  y.destroy();
});

test("a full decapsulation queue sheds the handshake instead of queueing it", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({
    upstreamPort: broker.port,
    decapsulate: async () => {
      throw new Error("queue full");
    },
  });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(
    Buffer.concat([
      Buffer.from([HQN_VERSION, KEY.keyId]),
      frame(new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket())),
    ]),
  );
  await closed(s);
  assert.equal(gw.stats().refused.overloaded, 1);
});

test("a broker that is down closes the client rather than hanging it", async () => {
  const dead = net.createServer();
  await new Promise<void>((r) => dead.listen(0, "127.0.0.1", r));
  const port = (dead.address() as net.AddressInfo).port;
  dead.close();
  const gw = await gateway({ upstreamPort: port });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(
    Buffer.concat([
      Buffer.from([HQN_VERSION, KEY.keyId]),
      frame(new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket())),
    ]),
  );
  await closed(s);
  assert.equal(gw.stats().refused.upstream, 1);
});

test("a tampered transport frame closes both sides", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port });
  toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const f = sealFrames(c.t.send, Buffer.from([0xc0, 0x00]));
  f[f.length - 1]! ^= 1;
  c.s.write(f);
  await closed(c.s);
  assert.equal(gw.stats().refused.stream, 1);
});

// --- the helpers ----------------------------------------------------------------

test("connectClientId reads 3.1.1 and 5, and returns null for anything else", () => {
  assert.equal(connectClientId(connectPacket()), CLIENT_ID);
  // MQTT 5: level 5 and a (here empty) properties block before the payload.
  const v5 = Buffer.from(connectPacket());
  const body = Buffer.concat([
    Buffer.from([0x00, 0x04]),
    Buffer.from("MQTT"),
    Buffer.from([0x05, 0x02, 0x00, 0x3c, 0x00]),
    Buffer.from([0x00, 0x40]),
    Buffer.from(CLIENT_ID),
  ]);
  assert.equal(connectClientId(Buffer.concat([Buffer.from([0x10, body.length]), body])), CLIENT_ID);
  assert.ok(v5);
  for (const bad of [
    Buffer.alloc(0),
    Buffer.from([0x30, 0x00]),
    connectPacket("not-an-id"),
    connectPacket().subarray(0, 10),
    Buffer.from([0x10, 0xff, 0xff, 0xff, 0xff, 0x7f]),
  ]) {
    assert.equal(connectClientId(bad), null);
  }
  for (let i = 0; i < 2000; i++) connectClientId(crypto.randomBytes(1 + (i % 80))); // never throws
});

test("the key file is validated strictly", () => {
  const good = { keyId: 1, x25519: "11".repeat(32), hqcSeed: "22".repeat(32) };
  assert.equal(parseKeySeeds(JSON.stringify({ keys: [good] })).length, 1);
  for (const bad of [
    {},
    { keys: [] },
    { keys: [{ ...good, keyId: 256 }] },
    { keys: [{ ...good, x25519: "11" }] },
    { keys: [{ ...good, hqcSeed: "zz".repeat(32) }] },
    { keys: [good, good] },
  ]) {
    assert.throws(() => parseKeySeeds(JSON.stringify(bad)), Error, JSON.stringify(bad));
  }
});

// --- the real decapsulation pool ------------------------------------------------

test("the pool decapsulates with the core's HQC, and the handshake completes on the handle", async () => {
  const { DecapPool } = await import("../../src/gateway/decap-pool");
  const pool = new DecapPool(new Map([[KEY.keyId, KEY]]), 2, 8);
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, decapsulate: (k, ct) => pool.decapsulate(k, ct) });
  toClose.push(gw.server);
  try {
    // The real KEM on the client side: only the core's decapsulation opens it.
    const realKem: Kem = { encapsulate: (pk) => core.hqcEncapsulate(pk), decapsulate: () => Buffer.alloc(0) };
    const c = await handshake(gw.port, connectPacket(), realKem);
    assert.ok((await c.nextFrame()).equals(CONNACK));
    c.s.destroy();
    await assert.rejects(
      pool.decapsulate(9, Buffer.alloc(HQC_CIPHERTEXT_BYTES)),
      /unknown key id/,
      "an unknown key id is an error, not a crash",
    );
    await assert.rejects(pool.decapsulate(KEY.keyId, Buffer.alloc(3)), "a ciphertext of the wrong size");
  } finally {
    await pool.close();
  }
});

test("a full pool queue refuses at once rather than growing", async () => {
  const { DecapPool } = await import("../../src/gateway/decap-pool");
  const pool = new DecapPool(new Map(), 1, 0);
  try {
    await assert.rejects(pool.decapsulate(1, Buffer.alloc(HQC_CIPHERTEXT_BYTES)), /queue full/);
  } finally {
    await pool.close();
  }
});

test("noise-gw-keys fills an empty seed file, and appends rather than overwrites", async () => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const { readKeySeeds, loadServerKeys, publicKeys } = await import("../../src/gateway/keys");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noise-keys-"));
  const secret = path.join(dir, "keys.json");
  const run = (id: number) =>
    execFileSync("npx", ["tsx", "scripts/noise-gw-keys.ts", "--key-id", String(id), "--secret", secret], {
      cwd: path.join(__dirname, "..", ".."),
      encoding: "utf8",
    });
  try {
    fs.writeFileSync(secret, "", { mode: 0o600 });
    const pub1 = JSON.parse(run(1));
    assert.equal(pub1.keys.length, 1);
    assert.equal(fs.statSync(secret).mode & 0o777, 0o600, "the seed file is private");
    run(2);
    const keys = loadServerKeys(readKeySeeds(secret));
    assert.deepEqual([...keys.keys()], [1, 2], "rotation holds two key ids at once");
    const pub = publicKeys(keys);
    assert.equal(pub[0]!.x25519, pub1.keys[0].x25519, "the first key survived the second run");
    assert.equal(Buffer.from(pub[0]!.hqc, "base64").length, HQC_PUBLIC_KEY_BYTES);
    assert.throws(() => run(1), Error, "an existing key id is never overwritten");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- what a few hundred silent sockets can do ------------------------------------

test("a socket that never sends its header gives its slot back at the header deadline", async () => {
  const broker = await fakeBroker();
  toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { headerTimeoutMs: 100, handshakeTimeoutMs: 5000 } });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  const t0 = Date.now();
  await closed(s);
  assert.ok(Date.now() - t0 < 1000, "a silent socket held its slot for the whole handshake deadline");
  assert.equal(gw.stats().refused.timeout, 1);
});

test("half-open handshakes are capped per network, not only per address", async () => {
  const { Admission } = await import("../../src/gateway/admission");
  const { DEFAULT_LIMITS } = await import("../../src/gateway/gateway");
  const a = new Admission({ ...DEFAULT_LIMITS, perIpHandshakes: 8, perPrefixHandshakes: 3 }, Date.now);
  for (const ip of ["198.51.100.1", "198.51.100.2", "::ffff:198.51.100.3"]) {
    assert.equal(a.refusalFor(ip), null, ip);
    a.startHandshake(ip);
  }
  assert.equal(a.refusalFor("198.51.100.200"), "prefix-handshakes", "a fourth address in the /24 was admitted");
  assert.equal(a.refusalFor("198.51.101.1"), null, "the next /24 is a different network");

  const v6 = new Admission({ ...DEFAULT_LIMITS, perPrefixHandshakes: 1 }, Date.now);
  const leave = v6.startHandshake("2001:db8:aa:bb01::1");
  assert.equal(v6.refusalFor("2001:db8:aa:bbff:ffff::9"), "prefix-handshakes", "same /56");
  assert.equal(v6.refusalFor("2001:db8:aa:cc00::1"), null, "another /56");
  leave();
  assert.equal(v6.refusalFor("2001:db8:aa:bbff:ffff::9"), null, "a finished handshake frees its network's slot");
});

test("addressPrefix names the /24 or /56 an address is in", async () => {
  const { addressPrefix } = await import("../../src/gateway/admission");
  assert.equal(addressPrefix("203.0.113.77"), "203.0.113.0/24");
  assert.equal(addressPrefix("::ffff:203.0.113.77"), "203.0.113.0/24");
  assert.equal(addressPrefix("2001:db8::1"), "20010db8000000/56");
  assert.equal(addressPrefix("2001:0db8:0000:00ff:1::"), "20010db8000000/56");
  assert.equal(addressPrefix("fe80::1%en0"), "fe800000000000/56");
  assert.equal(addressPrefix("?"), "?");
  assert.equal(addressPrefix("1:2:3"), "1:2:3");
});

test("no more than `size` decapsulations run at once; the rest wait in order", async () => {
  const { DecapPool } = await import("../../src/gateway/decap-pool");
  let running = 0;
  let peak = 0;
  const slow = {
    keyId: 1,
    decapsulate: async () => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 20));
      running--;
      return core.HqnSecret.fromBytes(Buffer.alloc(32));
    },
  } as unknown as GatewayKeyPair;
  const pool = new DecapPool(new Map([[1, slow]]), 2, 8);
  await Promise.all(Array.from({ length: 6 }, () => pool.decapsulate(1, Buffer.alloc(1))));
  assert.equal(peak, 2);
  await pool.close();
});
