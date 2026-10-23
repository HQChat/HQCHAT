// The auth service routes, driven through the real handler against a real database.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { createAuthHandler } from "../../src/server/auth";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { call as request } from "../helpers/http";
import { closePg, requirePg } from "../pg-helper";
import { formatProofPassword, proofMessage } from "../reference/protocol/mqtt-proof";

test.before(requirePg);

// --- harness ---------------------------------------------------------------

const call = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
  request(createAuthHandler(), method, path, { body, headers });

/** A client id: 64 lowercase hex, which is what everything downstream keys on. */
const someId = () => crypto.randomBytes(32).toString("hex");

// --- the shape of the service ----------------------------------------------

test("an unknown route is a 404, not a 200", async () => {
  for (const [m, p] of [
    ["GET", "/"],
    ["POST", "/auth"],
    ["GET", "/mqtt/authn"],
    ["POST", "/nope"],
  ] as const) {
    const r = await call(m, p);
    assert.equal(r.status, 404, `${m} ${p}`);
  }
});

// --- /mqtt/authn ------------------------------------------------------------
//
// EMQX expects HTTP 200 with { result: "allow" | "deny" } — a non-200 is a
// broker-side error, not a refusal, so EVERY outcome here is a 200 and the
// verdict rides in the body. A route that started returning 401 for a bad
// credential would read to EMQX as the auth service being broken rather than as
// the client being unwelcome.

test("/mqtt/authn denies a caller with no credentials at all", async () => {
  for (const body of [{}, { username: "" }, { password: "" }, { username: "", password: "" }]) {
    const r = await call("POST", "/mqtt/authn", body);
    assert.equal(r.status, 200, "EMQX needs a 200 even to be told no");
    assert.equal(r.body.result, "deny", JSON.stringify(body));
    assert.notEqual(r.body.is_superuser, true);
  }
});

test("/mqtt/authn denies an unknown id with a made-up token", async () => {
  const r = await call("POST", "/mqtt/authn", {
    username: someId(),
    password: crypto.randomBytes(32).toString("hex"),
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.result, "deny");
});

test("/mqtt/authn does not grant superuser without the internal secret", async () => {
  // The superuser arm is what push-bridge and the ops tools use, and it bypasses
  // the topic ACL entirely. Nothing that merely looks like the internal user may
  // reach it.
  const r = await call("POST", "/mqtt/authn", { username: "internal", password: "internal" });
  assert.equal(r.status, 200);
  assert.notEqual(r.body.is_superuser, true);
});

// --- /mqtt/authn: the v1 signed CONNECT proof --------------------------------
//
// test/reference/protocol/mqtt-proof.ts. The client registers the public half of a per-session
// Ed25519 key at sign-in or refresh, then signs every CONNECT. These drive the
// whole path: registration over /auth/refresh, then the hook.

function signingKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { raw: spki.subarray(spki.length - 32), privateKey };
}

function v1Password(
  signer: crypto.KeyObject,
  keyId: string,
  signedClientid: string,
  opts: { ts?: number; nonce?: Buffer } = {},
): string {
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? crypto.randomBytes(16);
  const sig = crypto.sign(null, proofMessage(signedClientid, keyId, ts, nonce), signer);
  return formatProofPassword({ keyId, ts, nonce, sig });
}

/** A signed-in client with a registered signing key, via the real route. */
async function v1Client() {
  const id = someId();
  const session = await DB.mintSessionToken(id);
  const key = signingKey();
  const r = await call(
    "POST",
    "/auth/refresh",
    { mqttSigningKey: key.raw.toString("base64") },
    { authorization: `Bearer ${session}` },
  );
  assert.equal(r.status, 200);
  return { id, session, key, keyId: r.body.mqttKeyId as string, refresh: r.body };
}

const authn = (id: string, password: string, clientid = id) =>
  call("POST", "/mqtt/authn", { username: id, password, clientid });

test("/auth/refresh registers a signing key and tells the client the server's time", async () => {
  const { refresh } = await v1Client();
  assert.match(refresh.mqttKeyId, /^[0-9a-f]{32}$/);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(Math.abs(refresh.serverTime - now) <= 2, "serverTime is this clock");
  assert.ok(refresh.mqttKeyExpiresAt > now);
});

test("/auth/refresh without a signing key is a 400", async () => {
  const session = await DB.mintSessionToken(someId());
  const r = await call("POST", "/auth/refresh", {}, { authorization: `Bearer ${session}` });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "INVALID_MQTT_SIGNING_KEY");
});

test("/auth/refresh refuses a malformed signing key with a 400", async () => {
  const id = someId();
  const session = await DB.mintSessionToken(id);
  for (const mqttSigningKey of [
    "",
    "not base64!",
    crypto.randomBytes(31).toString("base64"),
    crypto.randomBytes(33).toString("base64"),
    42,
    // 32 bytes but small order: the identity point, and an order-4 point.
    Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]).toString("base64"),
    Buffer.alloc(32).toString("base64"),
  ]) {
    const r = await call("POST", "/auth/refresh", { mqttSigningKey }, { authorization: `Bearer ${session}` });
    assert.equal(r.status, 400, JSON.stringify(mqttSigningKey));
    assert.equal(r.body.error, "INVALID_MQTT_SIGNING_KEY");
  }
});

test("/mqtt/authn allows a v1 proof and expires the session with the key", async () => {
  const { id, key, keyId, refresh } = await v1Client();
  const r = await authn(id, v1Password(key.privateKey, keyId, id));
  assert.equal(r.body.result, "allow");
  assert.equal(r.body.expire_at, refresh.mqttKeyExpiresAt, "EMQX disconnects when the key expires");
  assert.notEqual(r.body.is_superuser, true);
});

test("/mqtt/authn reads the username case-insensitively", async () => {
  const { id, key, keyId } = await v1Client();
  const r = await call("POST", "/mqtt/authn", {
    username: id.toUpperCase(),
    password: v1Password(key.privateKey, keyId, id),
    clientid: id,
  });
  assert.equal(r.body.result, "allow");
});

test("/mqtt/authn refuses a replayed v1 CONNECT", async () => {
  const { id, key, keyId } = await v1Client();
  const password = v1Password(key.privateKey, keyId, id);
  assert.equal((await authn(id, password)).body.result, "allow");
  // The captured packet, resent verbatim — the attack the proof exists to stop.
  assert.equal((await authn(id, password)).body.result, "deny");
  // A fresh proof from the same key still works.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id))).body.result, "allow");
});

test("/mqtt/authn holds a v1 timestamp to ±60 s", async () => {
  const { id, key, keyId } = await v1Client();
  const now = Math.floor(Date.now() / 1000);
  // ±58 rather than ±59: a second can tick between signing and checking.
  for (const ts of [now - 58, now + 58]) {
    assert.equal(
      (await authn(id, v1Password(key.privateKey, keyId, id, { ts }))).body.result,
      "allow",
      `ts ${ts - now}`,
    );
  }
  for (const ts of [now - 62, now + 62, 0]) {
    assert.equal(
      (await authn(id, v1Password(key.privateKey, keyId, id, { ts }))).body.result,
      "deny",
      `ts ${ts - now}`,
    );
  }
});

test("/mqtt/authn binds a v1 proof to the clientid it was signed for", async () => {
  const { id, key, keyId } = await v1Client();
  const victim = someId();
  // Our own proof, presented under a victim's clientid.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id), victim)).body.result, "deny");
  // A proof SIGNED for the victim's clientid, presented as the victim.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, victim), victim)).body.result, "deny");
  // …and as ourselves: the signature does not cover what is presented.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, victim), id)).body.result, "deny");
});

test("/mqtt/authn refuses a signature made with a different key", async () => {
  const a = await v1Client();
  const stranger = signingKey();
  assert.equal((await authn(a.id, v1Password(stranger.privateKey, a.keyId, a.id))).body.result, "deny");
  // Another client's registered key, under our key id.
  const b = await v1Client();
  assert.equal((await authn(a.id, v1Password(b.key.privateKey, a.keyId, a.id))).body.result, "deny");
  // Our key, under the other client's key id.
  assert.equal((await authn(a.id, v1Password(a.key.privateKey, b.keyId, a.id))).body.result, "deny");
});

test("/mqtt/authn does not spend a nonce on a proof that fails", async () => {
  const { id, key, keyId } = await v1Client();
  const nonce = crypto.randomBytes(16);
  const forged = v1Password(signingKey().privateKey, keyId, id, { nonce });
  assert.equal((await authn(id, forged)).body.result, "deny");
  // Had the forgery spent it, this — the genuine CONNECT — would be refused.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id, { nonce }))).body.result, "allow");
});

test("/mqtt/authn refuses a revoked or expired signing key", async () => {
  const revoked = await v1Client();
  await DB.revokeMqttKeys(revoked.id);
  assert.equal(
    (await authn(revoked.id, v1Password(revoked.key.privateKey, revoked.keyId, revoked.id))).body.result,
    "deny",
  );

  const id = someId();
  const key = signingKey();
  const { keyId } = await DB.registerMqttKey(id, key.raw);
  await q(`UPDATE mqtt_session_keys SET expires_at = now() WHERE id = $1`, [id]);
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id))).body.result, "deny");
});

test("a client keeps its two newest signing keys and no more", async () => {
  const id = someId();
  const keys = [signingKey(), signingKey(), signingKey()];
  const ids: string[] = [];
  for (const k of keys) ids.push((await DB.registerMqttKey(id, k.raw)).keyId);
  assert.equal(
    (await authn(id, v1Password(keys[0]!.privateKey, ids[0]!, id))).body.result,
    "deny",
    "the oldest is gone",
  );
  assert.equal(
    (await authn(id, v1Password(keys[1]!.privateKey, ids[1]!, id))).body.result,
    "allow",
    "the previous survives a refresh",
  );
  assert.equal((await authn(id, v1Password(keys[2]!.privateKey, ids[2]!, id))).body.result, "allow");
});

// --- /auth/refresh ----------------------------------------------------------

test("/auth/refresh needs a session bearer", async () => {
  for (const headers of [{}, { authorization: "Bearer " }, { authorization: "Bearer nonsense" }]) {
    const r = await call("POST", "/auth/refresh", {}, headers as Record<string, string>);
    assert.equal(r.status, 401, JSON.stringify(headers));
    assert.equal(r.body.error, "unauthenticated");
  }
});

test("a malformed body is a 400, not a 500", async () => {
  const r = await request(createAuthHandler(), "POST", "/mqtt/authn", { raw: "{not json" });
  assert.equal(r.status, 400);
});

test.after(async () => {
  await closePg();
});

// --- /auth/logout --------------------------------------------------------------

test("/auth/logout ends the session that asks, and only that one", async () => {
  const id = someId();
  const [mine, other] = [await DB.mintSessionToken(id), await DB.mintSessionToken(id)];
  const r = await call("POST", "/auth/logout", {}, { authorization: `Bearer ${mine}` });
  assert.equal(r.status, 200, r.text);
  assert.equal(await DB.resolveSessionToken(mine), null, "the token outlived its logout");
  assert.equal((await DB.resolveSessionToken(other))?.id, id, "another device was logged out too");
  const again = await call("POST", "/auth/logout", {}, { authorization: `Bearer ${mine}` });
  assert.equal(again.status, 401);
});

test("/auth/logout everywhere ends every session and signing key", async () => {
  const { id, session, keyId } = await v1Client();
  const other = await DB.mintSessionToken(id);
  const r = await call("POST", "/auth/logout", { everywhere: true }, { authorization: `Bearer ${session}` });
  assert.equal(r.status, 200, r.text);
  assert.equal(await DB.resolveSessionToken(other), null);
  assert.equal(await DB.getMqttSessionKey(id, keyId), null, "a signing key outlived logout everywhere");
});

test("token-bearing responses are never cached", async () => {
  const { session, refresh } = await v1Client();
  assert.ok(refresh.mqttKeyId);
  const r = await call(
    "POST",
    "/auth/refresh",
    { mqttSigningKey: signingKey().raw.toString("base64") },
    { authorization: `Bearer ${session}` },
  );
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal((await call("POST", "/auth/verify", {})).headers["cache-control"], "no-store");
});
