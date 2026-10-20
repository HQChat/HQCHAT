// The key-possession handshake end to end: real HQC, real HKDF proof, real database.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { setLogLevel } from "../../src/common/logger";
import { createAuthHandler } from "../../src/server/auth";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { call as request } from "../helpers/http";
import { closePg, requirePg } from "../pg-helper";
import { authProof } from "../reference/protocol/auth-proof";
import { peerId } from "../reference/protocol/identity";

test.before(requirePg);

setLogLevel("silent"); // the failure path logs per attempt; see the alert test
// Callers are told apart by X-Real-IP, as behind the production nginx.
process.env.TRUSTED_PROXY = "x-real-ip";

const handler = createAuthHandler();

const call = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  request(handler, "POST", path, { body, headers });

/** A real HQC identity. Deterministic from a seed so a failure is reproducible. */
function identity(seed?: Buffer) {
  const { HqcWrapper } = require("../reference/protocol/hqc") as typeof import("../reference/protocol/hqc");
  const { pk, sk } = HqcWrapper.keypairFromSeed(seed ?? crypto.randomBytes(32));
  return { pk, sk, pkHex: pk.toString("hex"), id: peerId(pk.toString("hex")) };
}

/** What a client does with the server's challenge: decapsulate, then HKDF. */
function solve(sk: Buffer, ctB64: string): string {
  const { HqcWrapper } = require("../reference/protocol/hqc") as typeof import("../reference/protocol/hqc");
  const ss = HqcWrapper.decapsulate(sk, Buffer.from(ctB64, "base64"));
  return authProof(ss).toString("base64");
}

/** A valid per-session Ed25519 public key; verify requires one. */
const SIGNING_KEY = (() => {
  const spki = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32).toString("base64");
})();

const created: string[] = [];

/** Everything this file wrote, by id. */
async function cleanup(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM mqtt_session_keys WHERE id = ANY($1::text[])`,
    `DELETE FROM sessions WHERE id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM auth_challenges WHERE id = ANY($1::text[])`,
    `DELETE FROM banned_ids WHERE id = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    await q(sql, [ids]);
  }
  await q(
    `DELETE FROM rate_counters
      WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%' OR key LIKE 'verify:fail:%' OR key LIKE 'verify:ip:%'`,
  );
  created.length = 0;
}

/** A full init → verify, as a client performs it. */
async function handshake(seed?: Buffer) {
  const me = identity(seed);
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex });
  assert.equal(init.status, 200, `init failed: ${init.text}`);
  const verify = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solve(me.sk, init.body.ct),
  });
  return { me, init, verify };
}

test.afterEach(async () => {
  await cleanup();
});
test.after(async () => {
  await cleanup();
  await closePg();
});

test("a client that holds the key gets a session", async () => {
  const { me, init, verify } = await handshake();

  assert.ok(init.body.ct, "init must answer with a KEM ciphertext");
  const ct = Buffer.from(init.body.ct, "base64");
  assert.equal(ct.length, 14421, "an HQC-256 KEM ciphertext");

  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.id, me.id, "the id is derived from the key, not chosen by the caller");
  assert.equal(verify.body.pk, me.pkHex, "the key is echoed so a client can confirm what was read");
  assert.ok(verify.body.sessionToken, "a session token");
  assert.match(verify.body.mqttKeyId, /^[0-9a-f]{32}$/, "the registered MQTT signing key");
  assert.ok(verify.body.mqttKeyExpiresAt > Math.floor(Date.now() / 1000));
});

test("the challenge never carries the secret, only something derived from it", async () => {
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex });
  const { HqcWrapper } = require("../reference/protocol/hqc") as typeof import("../reference/protocol/hqc");
  const ss = HqcWrapper.decapsulate(me.sk, Buffer.from(init.body.ct, "base64"));

  assert.ok(!init.text.includes(ss.toString("base64")), "the shared secret was returned");
  assert.ok(!init.text.includes(ss.toString("hex")));

  const solution = authProof(ss);
  assert.notDeepEqual(solution, ss, "the proof must not simply be the secret");
  const verify = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solution.toString("base64"),
  });
  assert.equal(verify.status, 200, verify.text);
  assert.ok(!verify.text.includes(ss.toString("base64")), "…and neither does the session response");
});

test("the stored challenge is the proof, not the secret", async () => {
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex });
  const { HqcWrapper } = require("../reference/protocol/hqc") as typeof import("../reference/protocol/hqc");
  const ss = HqcWrapper.decapsulate(me.sk, Buffer.from(init.body.ct, "base64"));

  const rows = await q<{ c: string }>(`SELECT * FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 1, "one open challenge");
  const stored = JSON.stringify(rows.rows[0]);
  assert.ok(!stored.includes(ss.toString("hex")), "the shared secret is in the database");
  assert.ok(stored.includes(authProof(ss).toString("hex")), "the expected proof should be");
});

test("a wrong proof is refused, and mints nothing", async () => {
  const me = identity();
  created.push(me.id);
  await call("/auth/init", { pk: me.pkHex });

  const bad = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: crypto.randomBytes(32).toString("base64"),
  });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, "auth failed");
  assert.ok(!bad.body.sessionToken && !bad.body.mqttKeyId, bad.text);
  const sessions = await q(`SELECT 1 FROM sessions WHERE id = $1`, [me.id]);
  assert.equal(sessions.rows.length, 0, "a refused proof must not leave a session behind");
});

test("a proof of the WRONG LENGTH is refused rather than throwing", async () => {
  const me = identity();
  created.push(me.id);
  await call("/auth/init", { pk: me.pkHex });

  for (const wrong of [
    Buffer.alloc(1).toString("base64"),
    Buffer.alloc(31).toString("base64"),
    Buffer.alloc(33).toString("base64"),
    Buffer.alloc(4096).toString("base64"),
    "",
    "not-base64-at-all!!",
  ]) {
    await call("/auth/init", { pk: me.pkHex });
    const res = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: wrong });
    assert.equal(res.status, 401, `length ${wrong.length} produced ${res.status}: ${res.text}`);
  }
});

test("a challenge is single-use, so a captured proof cannot be replayed", async () => {
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex });
  const solution = solve(me.sk, init.body.ct);

  const first = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution });
  assert.equal(first.status, 200, first.text);

  const replay = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution });
  assert.equal(replay.status, 401, "the same proof was accepted twice");
});

test("a second init opens a second challenge, and each verifies once", async () => {
  const me = identity();
  created.push(me.id);
  const a = await call("/auth/init", { pk: me.pkHex });
  const b = await call("/auth/init", { pk: me.pkHex });
  assert.equal(a.status, 200, a.text);
  assert.equal(b.status, 200, b.text);
  assert.notEqual(a.body.ct, b.body.ct, "each init must encapsulate afresh");
  assert.notEqual(a.body.challenge, b.body.challenge, "each init names its own challenge");

  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 2, "a later init must not replace an open challenge");

  for (const init of [b, a]) {
    const solution = solve(me.sk, init.body.ct);
    const ok = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution });
    assert.equal(ok.status, 200, `an open challenge should verify: ${ok.text}`);
    const replay = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution });
    assert.equal(replay.status, 401, "the same proof was accepted twice");
  }
});

test("one address keeps only its newest few challenges", async () => {
  const me = identity();
  created.push(me.id);
  const inits = [];
  for (let i = 0; i < 5; i++) inits.push(await call("/auth/init", { pk: me.pkHex }));
  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 4, "five inits from one address leave its four newest");
  const oldest = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solve(me.sk, inits[0]!.body.ct),
  });
  assert.equal(oldest.status, 401, "the dropped challenge still verified");
});

test("a stranger's inits from other addresses neither refuse nor displace the owner's", async () => {
  const me = identity();
  created.push(me.id);
  const mine = await call("/auth/init", { pk: me.pkHex }, { "x-real-ip": "198.51.100.10" });
  for (let i = 0; i < 12; i++) {
    const r = await call("/auth/init", { pk: me.pkHex }, { "x-real-ip": `203.0.113.${i + 1}` });
    assert.equal(r.status, 200, r.text);
  }
  const again = await call("/auth/init", { pk: me.pkHex }, { "x-real-ip": "198.51.100.10" });
  assert.equal(again.status, 200, "the owner's init budget was spent by strangers");
  const verify = await call(
    "/auth/verify",
    { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: solve(me.sk, mine.body.ct) },
    { "x-real-ip": "198.51.100.10" },
  );
  assert.equal(verify.status, 200, `the owner's first challenge was displaced: ${verify.text}`);
});

test("a wrong proof spends nothing, so a stranger's junk verify cannot lock the owner out", async () => {
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex });
  const good = solve(me.sk, init.body.ct);

  const wrong = await call(
    "/auth/verify",
    { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: crypto.randomBytes(32).toString("base64") },
    { "x-real-ip": "203.0.113.99" },
  );
  assert.equal(wrong.status, 401);
  const junk = await call(
    "/auth/verify",
    { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: "AAAA" },
    { "x-real-ip": "203.0.113.99" },
  );
  assert.equal(junk.status, 401);

  const retry = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: good });
  assert.equal(retry.status, 200, `the correct proof after wrong ones was refused: ${retry.text}`);
  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 0, "the answered challenge is spent");
});

test("a verify that names its challenge is held to that one", async () => {
  const me = identity();
  created.push(me.id);
  const a = await call("/auth/init", { pk: me.pkHex });
  const b = await call("/auth/init", { pk: me.pkHex });
  assert.match(a.body.challenge, /^[0-9a-f]{32}$/);

  const crossed = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solve(me.sk, a.body.ct),
    challenge: b.body.challenge,
  });
  assert.equal(crossed.status, 401, "a proof for one challenge verified under another's id");

  const named = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solve(me.sk, a.body.ct),
    challenge: a.body.challenge,
  });
  assert.equal(named.status, 200, named.text);
  const left = await q<{ challenge_id: string }>(`SELECT challenge_id FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.deepEqual(
    left.rows.map((r) => r.challenge_id),
    [b.body.challenge],
    "only the answered challenge is spent",
  );
});

test("verify is rate-limited per address", async () => {
  const me = identity();
  created.push(me.id);
  const statuses: number[] = [];
  for (let i = 0; i < 32; i++) {
    const r = await call(
      "/auth/verify",
      { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: "AAAA" },
      { "x-real-ip": "203.0.113.200" },
    );
    statuses.push(r.status);
  }
  assert.deepEqual(statuses.slice(0, 30), Array(30).fill(401), statuses.join(", "));
  assert.deepEqual(statuses.slice(30), [429, 429], statuses.join(", "));
  const elsewhere = await call("/auth/verify", { mqttSigningKey: SIGNING_KEY, pk: me.pkHex, solution: "AAAA" });
  assert.equal(elsewhere.status, 401, "another address is not affected");
});

test("a proof solved with another key does not authenticate", async () => {
  const victim = identity();
  const attacker = identity();
  created.push(victim.id, attacker.id);

  const victimInit = await call("/auth/init", { pk: victim.pkHex });
  const res = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: victim.pkHex,
    solution: solve(attacker.sk, victimInit.body.ct),
  });
  assert.equal(res.status, 401, "a proof from the wrong secret key was accepted");
});

test("verifying without an open challenge is refused", async () => {
  const me = identity();
  created.push(me.id);
  const res = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: crypto.randomBytes(32).toString("base64"),
  });
  assert.equal(res.status, 401, "no challenge was ever opened for this key");
});

test("a malformed public key is refused before anything expensive runs", async () => {
  for (const pk of ["", "zz", "0x1234", "ABCDEF".repeat(10), "12 34", null, 12345, {}]) {
    const res = await call("/auth/init", { pk });
    assert.equal(res.status, 400, `${JSON.stringify(pk)} produced ${res.status}`);
    assert.match(res.body.error, /public key/);
  }
});

test("hex of the right shape but the wrong length is still refused", async () => {
  for (const pk of ["ab", "00".repeat(100), "ff".repeat(7236), "ab".repeat(7238)]) {
    const res = await call("/auth/init", { pk });
    assert.equal(res.status, 400, `${pk.length / 2} bytes produced ${res.status}: ${res.text}`);
  }
});

test("an uppercase key is the same identity as its lowercase form", async () => {
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/init", { pk: me.pkHex.toUpperCase() });
  assert.equal(init.status, 200, init.text);
  const verify = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex.toUpperCase(),
    solution: solve(me.sk, init.body.ct),
  });
  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.id, me.id);
  assert.equal(verify.body.pk, me.pkHex, "normalised to lowercase on the way back");
});

test("a login records the identity key", async () => {
  const { me, verify } = await handshake();
  assert.equal(verify.status, 200, verify.text);

  const user = await q<{ identity_pk: string }>(`SELECT identity_pk FROM users WHERE id = $1`, [me.id]);
  assert.equal(user.rows.length, 1, "the login did not record the user");
  assert.equal(user.rows[0]!.identity_pk, me.pkHex);
});

test("a login is idempotent — the same key twice is one account", async () => {
  const seed = crypto.randomBytes(32);
  const first = await handshake(seed);
  assert.equal(first.verify.status, 200, first.verify.text);
  const second = await handshake(seed);
  assert.equal(second.verify.status, 200, second.verify.text);

  assert.equal(first.verify.body.id, second.verify.body.id);
  assert.notEqual(
    first.verify.body.sessionToken,
    second.verify.body.sessionToken,
    "each login mints a fresh session token",
  );
  const users = await q(`SELECT 1 FROM users WHERE id = $1`, [first.me.id]);
  assert.equal(users.rows.length, 1, "one row per identity");
});

test("a banned key proves possession and is still refused, before any session", async () => {
  const seed = crypto.randomBytes(32);
  const first = await handshake(seed);
  assert.equal(first.verify.status, 200, first.verify.text);
  await DB.banUser(first.me.id);

  const again = await handshake(seed);
  assert.equal(again.verify.status, 403, again.verify.text);
  assert.equal(again.verify.body.error, "BANNED");
  assert.ok(!again.verify.body.sessionToken, "a banned key was handed a session");
  assert.equal((await q(`SELECT 1 FROM users WHERE id = $1`, [first.me.id])).rows.length, 0, "the account came back");
  assert.equal((await q(`SELECT 1 FROM sessions WHERE id = $1`, [first.me.id])).rows.length, 0);
  await assert.rejects(DB.ensureUser(first.me.id, first.me.pkHex), /BANNED/);
});

test("a run of failed proofs raises exactly one alert, and a success clears it", async () => {
  const alerts: string[] = [];
  const savedError = console.error;
  setLogLevel("error");
  console.error = (...a: unknown[]) => alerts.push(a.map(String).join(" "));

  const me = identity();
  created.push(me.id);
  try {
    for (let i = 0; i < 8; i++) {
      const res = await call("/auth/verify", {
        mqttSigningKey: SIGNING_KEY,
        pk: me.pkHex,
        solution: crypto.randomBytes(32).toString("base64"),
      });
      assert.equal(res.status, 401);
    }
  } finally {
    console.error = savedError;
    setLogLevel("silent");
  }

  const raised = alerts.filter((l) => /failed key-possession proofs/.test(l));
  assert.equal(raised.length, 1, `eight failures raised ${raised.length} alerts:\n${alerts.join("\n")}`);
  assert.match(raised[0]!, /5 failed key-possession proofs in 15m/);

  const init = await call("/auth/init", { pk: me.pkHex });
  const ok = await call("/auth/verify", {
    mqttSigningKey: SIGNING_KEY,
    pk: me.pkHex,
    solution: solve(me.sk, init.body.ct),
  });
  assert.equal(ok.status, 200, ok.text);
  const counter = await q(`SELECT 1 FROM rate_counters WHERE key = $1`, [`verify:fail:${me.id}`]);
  assert.equal(counter.rows.length, 0, "a success must clear the failure run");
});

test("one key cannot open unlimited challenges from one address", async () => {
  const me = identity();
  created.push(me.id);
  const statuses: number[] = [];
  for (let i = 0; i < 8; i++) {
    statuses.push((await call("/auth/init", { pk: me.pkHex })).status);
  }
  assert.deepEqual(
    statuses.slice(0, 6),
    [200, 200, 200, 200, 200, 200],
    `the first six must be served: ${statuses.join(", ")}`,
  );
  assert.deepEqual(statuses.slice(6), [429, 429], `the rest must be refused: ${statuses.join(", ")}`);
});

test("the rate-limit key is the id, not the 14 kB public key", async () => {
  const me = identity();
  created.push(me.id);
  await call("/auth/init", { pk: me.pkHex });

  const rows = await q<{ key: string }>(`SELECT key FROM rate_counters WHERE key LIKE 'init:pk:%'`);
  assert.ok(rows.rows.length >= 1, "no per-key counter was written");
  for (const r of rows.rows) {
    assert.ok(r.key.length < 100, `a ${r.key.length}-character counter key`);
    assert.ok(!r.key.includes(me.pkHex), "the public key itself is the counter key");
  }
  assert.ok(
    rows.rows.some((r) => r.key === `init:pk:${me.id}`),
    rows.rows.map((r) => r.key).join(", "),
  );
});

test("a refused init does not open a challenge", async () => {
  const me = identity();
  created.push(me.id);
  for (let i = 0; i < 6; i++) await call("/auth/init", { pk: me.pkHex });
  await q(`DELETE FROM auth_challenges WHERE id = $1`, [me.id]);

  const refused = await call("/auth/init", { pk: me.pkHex });
  assert.equal(refused.status, 429, refused.text);
  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 0, "a refused init wrote a challenge anyway");
});

test("a malformed key costs nothing — not even a counter row", async () => {
  await q(`DELETE FROM rate_counters WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%'`);
  for (const pk of ["zz", "0x1234", "not a key", "12 34"]) {
    const res = await call("/auth/init", { pk });
    assert.equal(res.status, 400, `${pk} -> ${res.status}`);
  }
  const rows = await q<{ key: string }>(
    `SELECT key FROM rate_counters WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%'`,
  );
  assert.deepEqual(
    rows.rows,
    [],
    `a malformed key reached the rate counters: ${rows.rows.map((r) => r.key).join(", ")}`,
  );
});
