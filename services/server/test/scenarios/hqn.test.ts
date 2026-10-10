import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as net from "node:net";
import { test } from "node:test";
import { Transport } from "../../src/client";
import type { ServerStaticPublic } from "../../src/protocol/noise";
import { inboxTopic } from "../../src/protocol/topics";
import { newClient, pause, signIn, stackUp } from "./stack";

/**
 * hqn/1 against the gateway the server advertises at /auth/transport. Skipped
 * when the server does not advertise one.
 */

async function gateway(): Promise<{ host: string; port: number; server: ServerStaticPublic } | null> {
  const { hqn } = await newClient().api.transport();
  const k = hqn?.keys[0];
  if (!hqn || !k) return null;
  const server = { keyId: k.keyId, x25519: Buffer.from(k.x25519, "base64"), hqc: Buffer.from(k.hqc, "base64") };
  return { host: process.env.TEST_HQN_HOST || hqn.host, port: hqn.port, server };
}

async function overHqn(t: Parameters<typeof stackUp>[0]) {
  if (!(await stackUp(t))) return null;
  const hqn = await gateway();
  if (!hqn) {
    t.skip("the server advertises no hqn/1 gateway");
    return null;
  }
  const c = newClient({ hqn });
  await signIn(c);
  return { c, hqn };
}

test("a client connects over hqn/1 with a signed CONNECT and pub/sub works", async (t) => {
  const s = await overHqn(t);
  if (!s) return;
  const { c } = s;
  await c.connect();
  assert.ok(await c.publish(inboxTopic(c.id), "over raw tcp"));
  for (let i = 0; i < 40 && !c.drops.length; i++) await pause(50);
  assert.deepEqual(c.drops, [`not a frame on ${inboxTopic(c.id)}`], "the publish came back over hqn/1");
  await c.close();
});

test("the topic ACL applies to a client arriving through the gateway", async (t) => {
  const s = await overHqn(t);
  if (!s) return;
  await s.c.connect();
  const stranger = `u/${crypto.randomBytes(32).toString("hex")}/inbox`;
  assert.deepEqual(await s.c.subscribe([stranger]), [stranger]);
  await s.c.close();
});

test("a CONNECT for another client id is refused through the gateway", async (t) => {
  const s = await overHqn(t);
  if (!s) return;
  const victim = crypto.randomBytes(32).toString("hex");
  await assert.rejects(
    Transport.connect({ endpoint: { hqn: s.hqn }, clientId: victim, password: s.c.auth.mqttPassword(victim) }),
  );
});

test("a replayed opening neither connects nor kicks the live session", async (t) => {
  const s = await overHqn(t);
  if (!s) return;
  const { c, hqn } = s;
  await c.connect();
  const opening = c.hqnOpening!;
  const replay = net.connect({ host: hqn.host, port: hqn.port });
  await new Promise<void>((r) => replay.on("connect", () => r()));
  replay.write(opening);
  const outcome = await new Promise<string>((resolve) => {
    replay.on("data", () => resolve("answered"));
    replay.on("close", () => resolve("closed"));
    setTimeout(() => resolve("timeout"), 5000);
  });
  replay.destroy();
  assert.equal(outcome, "closed");
  await pause(500);
  assert.equal(c.connected, true, "the replay did not take over the session");
  assert.ok(await c.publish(inboxTopic(c.id), "still here"));
  await c.close();
});

test("messages flow end to end between a WSS client and an hqn/1 client", async (t) => {
  const s = await overHqn(t);
  if (!s) return;
  const { c: a } = s;
  const b = newClient();
  await signIn(b);
  await b.api.setUsername(`hq_${crypto.randomBytes(3).toString("hex")}`);
  await a.api.invite(b.id);
  await b.api.accept(a.id);
  await Promise.all([a.sync(), b.sync()]);
  await Promise.all([a.connect(), b.connect()]);
  await a.send(b.id, "from raw tcp");
  assert.equal((await b.next(a.id)).text, "from raw tcp");
  await b.send(a.id, "to raw tcp");
  assert.equal((await a.next(b.id)).text, "to raw tcp");
});
