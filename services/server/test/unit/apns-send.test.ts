// The APNs sender: the provider JWT, the request Apple receives, and every
// reason a phone does or does not buzz.
//
// A real HTTP/2 server runs on localhost and only `http2.connect` is
// redirected to it, so headers, framing, the response and `client.close()` are
// the real thing. The authority the code asked for is recorded before the
// redirect, so host selection and the sandbox/production failover are still
// asserted. Cleartext h2c, to avoid a certificate fixture.
//
// The module is reloaded per test: `cachedKey` and `cachedJwt` are
// module-level with no reset (one parse per process in production).

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { once } from "node:events";
import * as http2 from "node:http2";
import Module from "node:module";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { logger, setLogLevel } from "../../src/common/logger";

setLogLevel("debug");

// --- keys ------------------------------------------------------------------------

/** A genuine P-256 key in the PKCS#8 container Apple's .p8 uses. */
const EC = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256",
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

/** Right container, wrong algorithm — the mistake that surfaces as Apple's
 *  "InvalidProviderToken" hours later, about pushes nobody saw fail. */
const RSA_PEM = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

/** How the key actually arrives: one env line with escaped newlines. */
const ESCAPED_EC = EC.privateKey.replace(/\n/g, "\\n");

// --- the local APNs double ----------------------------------------------------------

interface Seen {
  headers: http2.IncomingHttpHeaders;
  body: string;
}

const seen: Seen[] = [];
const authorities: string[] = [];
let replies: Array<{ status: number; body: string }> = [];

/** Raw arguments handed to the logger during the current `withApns` call. */
const handed: string[] = [];

let server: http2.Http2Server;
let port = 0;

// The CommonJS module object, NOT the `http2` namespace above: esbuild compiles
// `import * as` to an object of getter-only properties, so assigning to
// `http2.connect` throws under strict mode. Writing to the underlying module
// works, and the namespace's getters forward to it.
const h2mod = require("node:http2");
const realConnect = h2mod.connect.bind(h2mod);
/** Where `connect` is pointed. Overridden by one test to a closed port. */
let redirectTo: () => string = () => `http://127.0.0.1:${port}`;

test.before(async () => {
  server = http2.createServer();
  server.on("stream", (stream: http2.ServerHttp2Stream, headers) => {
    let body = "";
    stream.setEncoding("utf8");
    stream.on("data", (c) => (body += c));
    stream.on("error", () => {});
    stream.on("end", () => {
      seen.push({ headers, body });
      const r = replies.shift() ?? { status: 200, body: "" };
      stream.respond({ ":status": r.status });
      stream.end(r.body);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  port = (server.address() as AddressInfo).port;

  h2mod.connect = (authority: any, opts?: any) => {
    authorities.push(String(authority));
    return realConnect(redirectTo(), opts);
  };
});

test.after(async () => {
  h2mod.connect = realConnect;
  server.close();
});

// --- loading the module under test ----------------------------------------------------

/** A mutable stand-in for the push-token table. */
let pushToken: { token: string; platform: string; environment: string } | null = null;
let pushTokenError: Error | null = null;

const dbPath = require.resolve("../../src/server/db/api");

const dbStub = {
  DB: {
    async getPushToken(_id: string) {
      if (pushTokenError) throw pushTokenError;
      return pushToken;
    },
  },
};
const dbCalls: string[] = [];
const realGetPushToken = dbStub.DB.getPushToken;
dbStub.DB.getPushToken = async (id: string) => {
  dbCalls.push(id);
  return realGetPushToken(id);
};

{
  const m = new Module(dbPath, module);
  m.filename = dbPath;
  m.loaded = true;
  m.exports = dbStub;
  require.cache[dbPath] = m;
}

const apnsPath = require.resolve("../../src/server/apns");

type Apns = typeof import("../../src/server/apns");

const ENV_KEYS = ["APNS_KEY_ID", "APNS_TEAM_ID", "APNS_KEY_P8", "APNS_TOPIC_IOS", "APNS_TOPIC_MACOS"] as const;

const FULL: Record<string, string> = {
  APNS_KEY_ID: "ABC123DEF4",
  APNS_TEAM_ID: "TEAM123456",
  APNS_KEY_P8: EC.privateKey,
  APNS_TOPIC_IOS: "app.hqchat.ios",
  APNS_TOPIC_MACOS: "app.hqchat.macos",
};

/**
 * A fresh copy of the module with a fresh key cache, under the given env.
 * Restores the environment and leaves the reloaded module in place — the next
 * call replaces it again.
 */
async function withApns(
  env: Record<string, string | undefined>,
  fn: (apns: Apns, log: string[]) => Promise<void> | void,
): Promise<void> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) {
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  delete require.cache[apnsPath];

  const log: string[] = [];
  const savedConsole = { log: console.log, warn: console.warn, error: console.error };
  for (const k of ["log", "warn", "error"] as const) {
    (console as any)[k] = (...a: unknown[]) => log.push(a.map(String).join(" "));
  }

  // What this module PASSES to the logger, before src/common/scrub.ts redacts it.
  // Asserting on the console output alone proves nothing about this file: the
  // scrubber already masks a 64-hex device token, so an `[apns]` line that
  // interpolated one would still come out clean. Verified — that exact
  // injection passed every console-level assertion.
  handed.length = 0;
  const savedLogger = { error: logger.error, warn: logger.warn, debug: logger.debug };
  for (const k of ["error", "warn", "debug"] as const) {
    const real = savedLogger[k];
    (logger as any)[k] = (...a: unknown[]) => {
      handed.push(a.map(String).join(" "));
      return (real as any)(...a);
    };
  }

  seen.length = 0;
  authorities.length = 0;
  dbCalls.length = 0;
  replies = [];

  const apns = require(apnsPath) as Apns;
  try {
    await fn(apns, log);
  } finally {
    apns.closeApnsConnections();
    Object.assign(logger, savedLogger);
    Object.assign(console, savedConsole);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/** Decode one part of a JWT. */
const part = (jwt: string, i: number) => JSON.parse(Buffer.from(jwt.split(".")[i]!, "base64url").toString("utf8"));

/** The bearer token from the last request the server saw. */
const lastJwt = () => String(seen.at(-1)!.headers.authorization).replace(/^bearer /, "");

// --- what is wrong with the key, in words --------------------------------------------

test("an unset key is named as unset", async () => {
  await withApns({ ...FULL, APNS_KEY_P8: undefined }, (apns) => {
    assert.match(apns.keyProblem()!, /APNS_KEY_P8 is empty/);
  });
  await withApns({ ...FULL, APNS_KEY_P8: "   \n  " }, (apns) => {
    assert.match(apns.keyProblem()!, /empty/, "whitespace is unset, not set");
  });
});

test("the wrong PEM container is named, with the right one", async () => {
  // Two real pastes: an `EC PRIVATE KEY` (SEC1, what openssl emits by default)
  // and one line of a multi-line file. Both look like a key from a distance.
  const sec1 = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----";
  for (const bad of [sec1, "-----BEGIN PRIVATE KEY-----", "hunter2", "{}"]) {
    await withApns({ ...FULL, APNS_KEY_P8: bad }, (apns) => {
      const p = apns.keyProblem();
      assert.ok(p, `"${bad.slice(0, 24)}" was accepted`);
      assert.match(p!, /BEGIN PRIVATE KEY/, "the message must name the container that works");
    });
  }
});

test("a PEM-shaped key OpenSSL cannot load is distinguished from a mis-pasted one", async () => {
  // The two mistakes have different fixes: re-export the key, versus re-paste
  // it. `normalizeP8` already refuses anything that is not DER, so reaching the
  // second message needs a body that IS a well-formed SEQUENCE and still will
  // not load — the real key with its middle bytes corrupted, which is what a
  // mangled copy actually looks like.
  const der = crypto.createPrivateKey(EC.privateKey).export({ type: "pkcs8", format: "der" }) as Buffer;
  const broken = Buffer.from(der);
  for (let i = 20; i < 40; i++) broken[i] = broken[i]! ^ 0xff;
  const corrupt =
    "-----BEGIN PRIVATE KEY-----\n" +
    (broken.toString("base64").match(/.{1,64}/g) ?? []).join("\n") +
    "\n-----END PRIVATE KEY-----\n";

  await withApns({ ...FULL, APNS_KEY_P8: corrupt }, (apns) => {
    assert.match(
      apns.keyProblem()!,
      /OpenSSL will not load it as an EC key/,
      "a corrupt key body must not be reported as the wrong container",
    );
  });
});

test("an RSA key in the right container is refused", async () => {
  // ES256 is ECDSA on P-256 and Apple issues nothing else. Without this check
  // the failure is "InvalidProviderToken", from Apple, hours later, about a push
  // nobody saw fail.
  await withApns({ ...FULL, APNS_KEY_P8: RSA_PEM }, (apns) => {
    assert.match(apns.keyProblem()!, /EC key/);
    assert.equal(apns.ApnsService.gaps().length > 0, true, "an unusable key is a gap");
  });
});

test("a good key has no problem, escaped newlines and all", async () => {
  await withApns({ ...FULL, APNS_KEY_P8: EC.privateKey }, (apns) => {
    assert.equal(apns.keyProblem(), null);
  });
  // How it actually arrives — one env line with \n escapes.
  await withApns({ ...FULL, APNS_KEY_P8: ESCAPED_EC }, (apns) => {
    assert.equal(apns.keyProblem(), null, "the deployed \\n-escaped form must load");
    assert.deepEqual(apns.ApnsService.gaps(), []);
  });
});

test("no key material reaches the log or the message", async () => {
  // OpenSSL's parse errors can echo the input, which is why the catch in
  // `privateKey` is deliberately silent. This is that promise, asserted.
  const secret = EC.privateKey.split("\n")[1]!;
  const corrupt = `-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----\n`;
  await withApns({ ...FULL, APNS_KEY_P8: corrupt }, (apns, log) => {
    const problem = apns.keyProblem() ?? "";
    assert.ok(!problem.includes(secret), "the key body is in the error message");
    const written = `${handed.join("\n")}\n${log.join("\n")}`;
    assert.ok(!written.includes(secret), `the key body was logged:\n${written}`);
  });
});

// --- the provider JWT -------------------------------------------------------------------

test("the provider token is a real ES256 JWT over the configured ids", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "aa".repeat(32), platform: "ios", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "sent");

    const jwt = lastJwt();
    assert.equal(jwt.split(".").length, 3);
    assert.deepEqual(part(jwt, 0), { alg: "ES256", kid: FULL.APNS_KEY_ID });
    const payload = part(jwt, 1);
    assert.equal(payload.iss, FULL.APNS_TEAM_ID);
    assert.ok(Math.abs(payload.iat - Math.floor(Date.now() / 1000)) < 5, "iat is now, in seconds");

    // The signature must be the raw r‖s pair, not DER. Node's default for
    // `crypto.sign` on an EC key IS DER, and APNs rejects it — `dsaEncoding:
    // 'ieee-p1363'` is the whole difference and nothing was holding it.
    const sig = Buffer.from(jwt.split(".")[2]!, "base64url");
    assert.equal(sig.length, 64, `ES256 is 64 raw bytes; got ${sig.length} (DER starts 0x30: ${sig[0]?.toString(16)})`);
    assert.notEqual(sig[0], 0x30, "the signature is DER-encoded");

    // And it verifies. A well-formed JWT signed with the wrong bytes would pass
    // every assertion above.
    const ok = crypto.verify(
      "SHA256",
      Buffer.from(jwt.split(".").slice(0, 2).join(".")),
      { key: EC.publicKey, dsaEncoding: "ieee-p1363" },
      sig,
    );
    assert.ok(ok, "the JWT does not verify against the configured key");
  });
});

test("the token is reused within its window and refreshed past it", async () => {
  // APNs accepts a provider token for an hour and rate-limits token creation;
  // re-signing per push is how a busy server gets throttled.
  await withApns(FULL, async (apns) => {
    pushToken = { token: "bb".repeat(32), platform: "ios", environment: "production" };
    const realNow = Date.now;
    try {
      let clock = 1_700_000_000_000;
      Date.now = () => clock;

      await apns.ApnsService.send("u1", "t", "b");
      const first = lastJwt();
      clock += 2999 * 1000;
      await apns.ApnsService.send("u1", "t", "b");
      assert.equal(lastJwt(), first, "the token was re-signed inside its window");

      clock += 2 * 1000; // now 3001s old
      await apns.ApnsService.send("u1", "t", "b");
      assert.notEqual(lastJwt(), first, "the token was not refreshed past the window");
      assert.equal(part(lastJwt(), 1).iat, Math.floor(clock / 1000));
    } finally {
      Date.now = realNow;
    }
  });
});

// --- every outcome ---------------------------------------------------------------------

test("no configuration is reported as no-config, and nothing is looked up", async () => {
  await withApns({ ...FULL, APNS_KEY_ID: undefined }, async (apns) => {
    pushToken = { token: "cc".repeat(32), platform: "ios", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "no-config");
    assert.equal(apns.ApnsService.enabled(), false);
    assert.equal(seen.length, 0);
  });
});

test("an unusable key is reported before the recipient is looked up", async () => {
  // The order is load-bearing and stated in the source: a key OpenSSL cannot
  // load is a property of the deployment, not of this recipient. Querying first
  // would make a deploy mistake look like a per-user problem.
  await withApns({ ...FULL, APNS_KEY_P8: RSA_PEM }, async (apns) => {
    pushToken = { token: "dd".repeat(32), platform: "ios", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "bad-key");
    assert.deepEqual(dbCalls, [], "the database was queried for a push that could never be signed");
  });
});

test("a peer with no registered device is an ordinary no-token", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = null;
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "no-token");
    assert.deepEqual(dbCalls, ["u1"]);
    assert.equal(seen.length, 0);
  });
});

test("a missing topic is named per platform", async () => {
  // The quietest misconfiguration in the stack: the key authenticates fine and
  // delivers to nowhere.
  await withApns({ ...FULL, APNS_TOPIC_IOS: undefined }, async (apns) => {
    pushToken = { token: "ee".repeat(32), platform: "ios", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "no-topic-ios");
    assert.equal(seen.length, 0, "nothing may be sent without a topic");
  });
  await withApns({ ...FULL, APNS_TOPIC_MACOS: undefined }, async (apns) => {
    pushToken = { token: "ee".repeat(32), platform: "macos", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "no-topic-macos");
  });
});

test("a rejection from Apple is reported as rejected, not as success", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ff".repeat(32), platform: "ios", environment: "production" };
    replies = [{ status: 403, body: '{"reason":"ExpiredProviderToken"}' }];
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
  });
});

test("a 410 Unregistered is a rejection like any other", async () => {
  // Apple's signal that the app was deleted. Nothing here acts on it — the token
  // is not pruned — which is worth pinning: a later change to prune on 410 is a
  // deliberate one, and today it simply retries forever.
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ab".repeat(32), platform: "ios", environment: "production" };
    replies = [{ status: 410, body: '{"reason":"Unregistered"}' }];
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
    assert.deepEqual(dbCalls, ["u1"], "no token is deleted on 410 today");
  });
});

test("a database failure is an error outcome, never a throw", async () => {
  // `send` is called from the message path. A throw here would turn a push
  // problem into a delivery problem.
  await withApns(FULL, async (apns) => {
    pushTokenError = new Error("connection terminated");
    try {
      assert.equal(await apns.ApnsService.send("u1", "t", "b"), "error");
    } finally {
      pushTokenError = null;
    }
  });
});

test("a host that will not answer is a rejection, not a hang", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ba".repeat(32), platform: "ios", environment: "production" };
    const saved = redirectTo;
    // A port nothing is listening on: connect fails, `client.on("error")` fires,
    // and the promise must still resolve.
    redirectTo = () => `http://127.0.0.1:1`;
    try {
      assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
    } finally {
      redirectTo = saved;
    }
  });
});

// --- the request Apple actually receives ------------------------------------------------

test("the push is addressed to the device and typed as an alert", async () => {
  await withApns(FULL, async (apns) => {
    const device = "0123456789abcdef".repeat(4);
    pushToken = { token: device, platform: "ios", environment: "production" };
    assert.equal(await apns.ApnsService.send("u1", "New message", "from Ada"), "sent");

    const req = seen[0]!;
    assert.equal(req.headers[":method"], "POST");
    assert.equal(req.headers[":path"], `/3/device/${device}`);
    assert.equal(req.headers["apns-topic"], FULL.APNS_TOPIC_IOS);
    assert.equal(req.headers["apns-push-type"], "alert", "the wrong push type is silently dropped by iOS");
    assert.equal(req.headers["apns-collapse-id"], "new-message", "repeated wakes replace each other on the device");
    assert.equal(req.headers["content-type"], "application/json");
    assert.match(String(req.headers.authorization), /^bearer ey/);
    assert.deepEqual(JSON.parse(req.body), {
      aps: { alert: { title: "New message", body: "from Ada" }, sound: "default" },
    });
  });
});

test("a macOS device is sent to the macOS topic", async () => {
  // One bundle id per platform. Sending an iOS topic to a Mac authenticates and
  // delivers nothing — the same silent failure as an unset topic.
  await withApns(FULL, async (apns) => {
    pushToken = { token: "cd".repeat(32), platform: "macos", environment: "production" };
    await apns.ApnsService.send("u1", "t", "b");
    assert.equal(seen[0]!.headers["apns-topic"], FULL.APNS_TOPIC_MACOS);
  });
});

test("the message body is carried verbatim, however it is written", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "de".repeat(32), platform: "ios", environment: "production" };
    const body = `"quotes", <tags>, emoji 🔒👨‍👩‍👧‍👦, and a\nnewline`;
    await apns.ApnsService.send("u1", "Ada — 🎉", body);
    const sent = JSON.parse(seen[0]!.body);
    assert.equal(sent.aps.alert.body, body);
    assert.equal(sent.aps.alert.title, "Ada — 🎉");
  });
});

// --- sandbox and production ----------------------------------------------------------------

test("each device is sent to the APNs environment it registered with", async () => {
  for (const [environment, expected] of [
    ["production", "api.push.apple.com"],
    ["sandbox", "api.sandbox.push.apple.com"],
  ] as const) {
    await withApns(FULL, async (apns) => {
      pushToken = { token: "ef".repeat(32), platform: "ios", environment };
      await apns.ApnsService.send("u1", "t", "b");
      assert.deepEqual(authorities, [`https://${expected}`], environment);
    });
  }
});

test("a rejection is not retried elsewhere", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "fd".repeat(32), platform: "ios", environment: "production" };
    replies = [{ status: 400, body: '{"reason":"BadDeviceToken"}' }];
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
    assert.equal(authorities.length, 1);
  });
});

// --- what a failure is allowed to say ---------------------------------------------------

test("a rejection logs Apple's reason and not the device token", async () => {
  // The device token identifies one person's phone. Apple's reason is the
  // diagnosis and carries nothing about them.
  await withApns(FULL, async (apns, log) => {
    const device = "9".repeat(64);
    pushToken = { token: device, platform: "ios", environment: "production" };
    replies = [{ status: 403, body: '{"reason":"ExpiredProviderToken"}' }];
    await apns.ApnsService.send("u1", "t", "b");
    assert.match(handed.join("\n"), /ExpiredProviderToken/, "the reason should survive");
    assert.ok(!handed.join("\n").includes(device), `the device token was handed to the logger:\n${handed.join("\n")}`);
    // And the console line is clean too — the scrubber is the second net, not
    // the first.
    assert.ok(!log.join("\n").includes(device));
  });
});

test("neither the title nor the body of a message is logged", async () => {
  // These are the notification's plaintext. The server holds them only for as
  // long as this call.
  await withApns(FULL, async (apns, log) => {
    pushToken = { token: "1".repeat(64), platform: "ios", environment: "production" };
    replies = [{ status: 500, body: '{"reason":"InternalServerError"}' }];
    await apns.ApnsService.send("u1", "Ada Lovelace", "meet me at midnight");
    const all = `${handed.join("\n")}\n${log.join("\n")}`;
    assert.ok(!all.includes("midnight"), `the message body was logged:\n${all}`);
    assert.ok(!all.includes("Ada Lovelace"), `the sender was logged:\n${all}`);
  });
});

// --- readiness ----------------------------------------------------------------------------

test("gaps names what is missing without repeating itself", async () => {
  await withApns(FULL, (apns) => {
    assert.deepEqual(apns.ApnsService.gaps(), [], "a full configuration has no gaps");
  });
  await withApns({ ...FULL, APNS_KEY_P8: undefined }, (apns) => {
    const gaps = apns.ApnsService.gaps();
    assert.ok(gaps.includes("APNS_KEY_P8"));
    // The key problem is only appended when the variable itself is not already
    // listed, or an operator reads the same fault twice under two names.
    assert.equal(gaps.filter((g) => /APNS_KEY_P8/.test(g)).length, 1, gaps.join(" | "));
  });
  await withApns({ ...FULL, APNS_KEY_P8: RSA_PEM }, (apns) => {
    const gaps = apns.ApnsService.gaps();
    assert.ok(
      gaps.some((g) => /EC key/.test(g)),
      "a present-but-unusable key must be a gap",
    );
  });
  await withApns({ ...FULL, APNS_TOPIC_IOS: undefined, APNS_TOPIC_MACOS: undefined }, (apns) => {
    assert.ok(apns.ApnsService.gaps().some((g) => /bundle id/.test(g)));
  });
});

test("one topic set and the other missing IS reported as a gap", async () => {
  // A host with only APNS_TOPIC_MACOS is incomplete (`apnsGaps` names the
  // missing iPhone topic), but it still boots: gaps are warnings, and only
  // errors stop the process (see "a host serving one platform on purpose still
  // boots" in apns-config.test.ts).
  await withApns({ ...FULL, APNS_TOPIC_IOS: undefined }, async (apns) => {
    const gaps = apns.ApnsService.gaps();
    assert.equal(gaps.length, 1, gaps.join(" | "));
    assert.match(gaps[0]!, /APNS_TOPIC_IOS/, "the gap names the variable to set");
    assert.match(gaps[0]!, /iPhone/, "…and the devices it costs");
    pushToken = { token: "11".repeat(32), platform: "ios", environment: "production" };
    assert.equal(
      await apns.ApnsService.send("u1", "t", "b"),
      "no-topic-ios",
      "…which is what send has always done about it",
    );
  });
});

test("enabled is about the three ids, and says nothing about whether a push lands", async () => {
  // Deliberate: `enabled()` gates whether push is attempted at all, and the
  // topics are checked per platform inside `send`. Pinning it so the two
  // questions do not get conflated back together.
  await withApns({ ...FULL, APNS_TOPIC_IOS: undefined, APNS_TOPIC_MACOS: undefined }, (apns) => {
    assert.equal(apns.ApnsService.enabled(), true);
    assert.ok(apns.ApnsService.gaps().length > 0, "…but it is not ready");
  });
});

// --- one connection, not one per push ----------------------------------------------------

test("pushes share one connection per APNs host", async () => {
  // Apple treats a connect per push as a denial of service, and a flood of
  // wakes would otherwise be a flood of TLS handshakes.
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ac".repeat(32), platform: "ios", environment: "production" };
    for (let i = 0; i < 5; i++) assert.equal(await apns.ApnsService.send("u1", "t", "b"), "sent");
    await Promise.all(Array.from({ length: 5 }, () => apns.ApnsService.send("u1", "t", "b")));
    assert.equal(seen.length, 10);
    assert.deepEqual(authorities, ["https://api.push.apple.com"], "a connection was opened per push");
  });
});

test("a dead connection is replaced on the next push", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ad".repeat(32), platform: "ios", environment: "production" };
    const saved = redirectTo;
    redirectTo = () => `http://127.0.0.1:1`;
    try {
      assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
    } finally {
      redirectTo = saved;
    }
    assert.equal(await apns.ApnsService.send("u1", "t", "b"), "sent", "the failed connection was reused");
    assert.equal(authorities.length, 2);
  });
});

test("a request APNs never answers is given up on", async () => {
  await withApns(FULL, async (apns) => {
    pushToken = { token: "ae".repeat(32), platform: "ios", environment: "production" };
    const silent = http2.createServer();
    silent.on("stream", () => {
      /* never respond */
    });
    silent.listen(0, "127.0.0.1");
    await once(silent, "listening");
    const saved = redirectTo;
    redirectTo = () => `http://127.0.0.1:${(silent.address() as AddressInfo).port}`;
    try {
      const started = Date.now();
      assert.equal(await apns.ApnsService.send("u1", "t", "b"), "rejected");
      assert.ok(Date.now() - started < 15_000);
    } finally {
      redirectTo = saved;
      apns.closeApnsConnections();
      silent.close();
    }
  });
});
