// The report an operator reads when a phone does not buzz.
//
// Both of this repo's diagnostics were untested, and the previous round showed
// what that costs: `check-mqtt-acl` called an ACL complete while the one topic
// first contact needs was missing — during the outage it was written to
// diagnose. A diagnostic that lies is worse than none, because it ends the
// investigation.
//
// So this asserts the VERDICT, not the prose. Every step of the push path exits
// silently when it cannot proceed — no APNs config, no registered token, no
// bundle id — so a stack that has never sent a single push looks exactly like
// one that works. Which step stops is the only thing this tool is for.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { setLogLevel } from "@hqchat/common/logger";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { closePg, requirePg } from "../pg-helper";
import { peerId } from "../reference/protocol/identity";

test.before(requirePg);

setLogLevel("silent");

const ENV_KEYS = [
  "APNS_KEY_ID",
  "APNS_TEAM_ID",
  "APNS_KEY_P8",
  "APNS_TOPIC_IOS",
  "APNS_TOPIC_MACOS",
  "APNS_ENV",
] as const;

const EC_KEY = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256",
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

const CONFIGURED: Record<string, string> = {
  APNS_KEY_ID: "ABC123DEF4",
  APNS_TEAM_ID: "TEAM123456",
  APNS_KEY_P8: EC_KEY,
  APNS_TOPIC_IOS: "app.hqchat.ios",
  APNS_TOPIC_MACOS: "app.hqchat.macos",
};

const checkPushPath = require.resolve("../../scripts/check-push");
const apnsPath = require.resolve("../../src/server/apns");

/** Run the report under a given environment and return everything it printed. */
async function reportUnder(env: Record<string, string | undefined>, arg?: string): Promise<string> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) {
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const savedConsole = { log: console.log, error: console.error };
  console.log = (...a: unknown[]) => out.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => out.push(a.map(String).join(" "));

  // The APNs module caches the parsed key, and this report asks it whether the
  // key is usable — so both are reloaded, or every case after the first sees
  // the first case's verdict.
  delete require.cache[checkPushPath];
  delete require.cache[apnsPath];
  try {
    const { report } = require(checkPushPath) as typeof import("../../scripts/check-push");
    await report(arg);
    return out.join("\n");
  } finally {
    Object.assign(console, savedConsole);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const created: string[] = [];

async function account(username?: string): Promise<{ id: string; username: string }> {
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  const name = username ?? `p${crypto.randomBytes(6).toString("hex")}`;
  await DB.ensureUser(id, pkHex);
  await DB.setUsername(id, name);
  created.push(id);
  return { id, username: name };
}

async function cleanup(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM push_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try {
      await q(sql, [ids]);
    } catch {
      /* not this schema */
    }
  }
  created.length = 0;
}

test.afterEach(async () => {
  await cleanup();
});
test.after(async () => {
  await cleanup();
  await closePg();
});

// --- the config verdict, which decides whether anything else matters -------------------

test("an incomplete APNs config stops the report at the top", async () => {
  // With APNs incomplete, `send()` returns before it builds a request: no device
  // is woken and no error is logged, for any account. Everything further down is
  // therefore irrelevant, and a report that buried that under an account's
  // details would send an operator looking at the wrong thing.
  const out = await reportUnder({ APNS_KEY_P8: EC_KEY });
  assert.match(out, /Nothing below matters until this is fixed/);
  // And it names where each half belongs: the environment file and the secret.
  assert.match(out, /infra\/environments/);
  assert.match(out, /apns_key_p8/);
});

test("a complete config does not raise that alarm", async () => {
  // A report that cried "nothing matters" on a healthy stack would be ignored on
  // the day it was right.
  const out = await reportUnder(CONFIGURED);
  assert.doesNotMatch(out, /Nothing below matters/);
  assert.match(out, /APNs ready/);
});

test("a key that is present but unloadable is called out with its remedy", async () => {
  // "Set" and "usable" are different questions: a .p8 OpenSSL will not load
  // passes every presence check and fails every push. The remedy names the
  // secret to set from the file, not a paste.
  const rsa = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;
  const out = await reportUnder({ ...CONFIGURED, APNS_KEY_P8: rsa });
  assert.match(out, /⛔️/);
  assert.match(out, /EC key/);
  assert.match(out, /gh secret set APNS_KEY_P8/, "the remedy must be a command, not advice");
});

test("no key at all is not reported as an unloadable key", async () => {
  // Two different problems with two different fixes. Conflating them sends an
  // operator to re-copy a file that was never there.
  const out = await reportUnder({ APNS_KEY_P8: undefined });
  assert.doesNotMatch(out, /Re-install it from the file Apple gave you/);
});

// --- the whole-table view ------------------------------------------------------------------

test("with no argument it reports the shape of the table", async () => {
  // A stack where NOBODY has a token is a different problem from one person's
  // device, and the two look identical from a single account's report.
  const a = await account();
  await DB.setPushToken(a.id, "ios", "production", "t".repeat(64));
  const out = await reportUnder(CONFIGURED);
  assert.match(out, /registered devices/);
  assert.match(out, /ios: \d+/, out);
  assert.match(out, /Pass a username or client id/);
});

// --- one account ---------------------------------------------------------------------------

test("an account nobody has ever registered is named as such", async () => {
  // Not "no push token": the account does not exist, which means it never
  // completed the handshake, which is a different investigation entirely.
  const out = await reportUnder(CONFIGURED, "definitely-not-a-real-handle");
  assert.match(out, /no account "definitely-not-a-real-handle"/);
  assert.match(out, /never completed \/auth/);
});

test("an account with no device says so, and says why that happens", async () => {
  const a = await account();
  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /push token: NONE/);
  // The two real causes, because "no token" on its own is not actionable.
  assert.match(out, /permission denied|aps-environment/);
  assert.match(out, /this account has no device to send to/);
});

test("an account with a device reports the topic that will be used", async () => {
  // One bundle id per platform. A macOS device sent to the iOS topic
  // authenticates and delivers nothing — the silent failure this whole tool is
  // about.
  const a = await account();
  await DB.setPushToken(a.id, "macos", "production", "m".repeat(64));
  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /\(macos\)/);
  // Scoped to the per-account line. The summary at the top names every
  // CONFIGURED topic, quite correctly — asserting over the whole report would
  // fail on a healthy stack, which is what my first version of this did.
  const line = out.split("\n").find((l) => /topic for macos:/.test(l));
  assert.ok(line, `no per-platform topic line:\n${out}`);
  assert.ok(line!.includes(CONFIGURED.APNS_TOPIC_MACOS!), line);
  assert.ok(!line!.includes(CONFIGURED.APNS_TOPIC_IOS!), `the iOS topic is not the one that will be used: ${line}`);
});

test("a missing topic for that platform is named at the point of use", async () => {
  // `apnsGaps` reports the missing topic at the top too; this names it for the
  // one device an operator is asking about.
  const a = await account();
  await DB.setPushToken(a.id, "ios", "production", "t".repeat(64));
  const out = await reportUnder({ ...CONFIGURED, APNS_TOPIC_IOS: undefined }, a.username);
  assert.match(out, /UNSET — send\(\) returns silently/);
});

test("the full device token is never printed", async () => {
  // It identifies one person's phone, and this runs in a terminal an operator
  // may well paste into an issue.
  const a = await account();
  const token = crypto.randomBytes(32).toString("hex");
  await DB.setPushToken(a.id, "ios", "production", token);
  const out = await reportUnder(CONFIGURED, a.username);
  assert.ok(out.includes(token.slice(0, 12)), "a prefix should be shown, to correlate");
  assert.ok(!out.includes(token), "the whole device token was printed");
});

test("it counts the conversations that could wake an account", async () => {
  // A friendship whose hash is not in the ACL is one the bridge would see a
  // message on and find no members for — the count is what makes "nobody can
  // wake them" visible.
  const [a, b, c] = [await account(), await account(), await account()];
  await DB.setPushToken(a.id, "ios", "production", "t".repeat(64));
  await DB.createFriendship(a.id, b.id);
  await DB.createFriendship(a.id, c.id);

  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /conversations that could wake them: 2/);
  assert.match(out, /Nothing in the server's state blocks a wake/);
});

test("a lookup works by client id as well as by handle", async () => {
  // An operator reading a log has an id, not a handle.
  const a = await account();
  const { resolve } = require("../../scripts/check-push") as typeof import("../../scripts/check-push");
  assert.deepEqual(await resolve(a.id), { id: a.id, username: a.username });
  assert.deepEqual(await resolve(a.username), { id: a.id, username: a.username });
  assert.equal(await resolve(peerId("nothing")), null, "an id nobody holds resolves to nothing");

  const out = await reportUnder(CONFIGURED, a.id);
  assert.match(out, new RegExp(`@${a.username} = ${a.id}`));
});

test("importing the script reports nothing", async () => {
  // `require.main === module`: a test that wants `resolve` should not print a
  // whole diagnostic and close the connection pool as a side effect.
  const out: string[] = [];
  const savedLog = console.log;
  console.log = (...a: unknown[]) => out.push(a.map(String).join(" "));
  try {
    delete require.cache[checkPushPath];
    require(checkPushPath);
  } finally {
    console.log = savedLog;
  }
  assert.deepEqual(out, [], `importing printed:\n${out.join("\n")}`);
});
