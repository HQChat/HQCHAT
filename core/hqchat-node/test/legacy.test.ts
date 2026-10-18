// The bot's move to the core: a state file written by the TS reference
// client's own FileStore imports into the Engine, under the id the bot's seed
// always had. Run with the other addon tests (see binding.test.ts).

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { FileStore } from "../../../services/server/src/client/store";
import { type Kem, startAsInitiator, startAsResponder } from "../../../services/server/src/protocol/ratchet";

const require = createRequire(__filename);
const core = require("../hqchat_node.node");

// The TS ratchet over the core's HQC, so the test needs no other native library.
const kem: Kem = {
  generateKeypair: () => core.hqcKeypairFromSeed(randomBytes(32)),
  encapsulate: (pk) => core.hqcEncapsulate(pk),
  decapsulate: (sk, ct) => core.hqcDecapsulate(sk, ct),
};

test("a TS client's state file imports with its sessions, under the seed's id", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-legacy-"));
  try {
    const botSeed = randomBytes(32);
    const bot = core.hqcKeypairFromSeed(botSeed);
    const botId = core.peerId(bot.pk.toString("hex"));
    const medium = core.hqcKeypairFromSeed(randomBytes(32));
    const oneTime = core.hqcKeypairFromSeed(randomBytes(32));
    const alice = core.hqcKeypairFromSeed(randomBytes(32));
    const aliceId = core.peerId(alice.pk.toString("hex"));

    // Alice opened a session with the bot, which answered: the bot's half is
    // what its FileStore held.
    const { header } = startAsInitiator(kem, {
      identityPk: bot.pk,
      mediumPk: medium.pk,
      oneTimePk: null,
      oneTimeId: null,
    });
    const botSession = startAsResponder(
      kem,
      { identitySk: bot.sk, mediumSk: medium.sk, oneTimeSk: () => null },
      header,
    );
    assert.ok(botSession);
    const file = path.join(dir, "state.json");
    new FileStore(file).save({
      peers: {
        [aliceId]: {
          id: aliceId,
          username: "alice",
          pk: alice.pk.toString("hex"),
          session: botSession,
          convoId: "c".repeat(64),
          handshakeId: "d".repeat(64),
        },
      },
      prekeys: {
        mediumPk: medium.pk,
        mediumSk: medium.sk,
        oneTime: new Map([[7, oneTime.sk]]),
        nextId: 8,
        rotatedAt: 1_790_000_000_000,
      },
    });
    // A friend whose session was cut short on disk.
    const broken = "e".repeat(64);
    const json = JSON.parse(fs.readFileSync(file, "utf8"));
    json.peers[broken] = { id: broken, session: { root: "AAAA", rkPub: "AA", rkSec: "AA" } };

    const engine = new core.Engine({ serverUrl: "https://hqchat.test", profileId: "bot", dir: path.join(dir, "core") });
    const result = engine.importLegacy(botSeed, JSON.stringify(json));
    assert.deepEqual(result.unreadable, [broken], "the cut-short session is reported, not fatal");
    assert.deepEqual(
      result.effects.map((e: { kind: string }) => e.kind),
      ["tierChanged"],
    );
    const friends = engine.friends();
    const a = friends.find((f: { id: string }) => f.id === aliceId);
    assert.ok(a?.hasSession, "alice's session came across");
    assert.equal(a.username, "alice");
    assert.equal(friends.find((f: { id: string }) => f.id === broken)?.hasSession, false);
    assert.throws(() => engine.importLegacy(botSeed, null), /already has an identity/);

    // The engine signs in as the seed's identity: the id the server's BOT_ID names.
    const start = engine.start(1_790_000_000_000, "wired");
    const init = start.find((e: { kind: string; path?: string }) => e.path === "/auth/init");
    assert.equal(core.peerId(JSON.parse(init.body.toString()).pk), botId);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a garbled state file is refused, and leaves the profile importable", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-legacy-"));
  try {
    const engine = new core.Engine({ serverUrl: "https://hqchat.test", profileId: "bot", dir });
    const seed = randomBytes(32);
    assert.throws(() => engine.importLegacy(seed, "{ not json"), /state file/);
    assert.throws(() => engine.importLegacy(seed, JSON.stringify({ prekeys: { mediumPk: 1 } })), /prekeys/);
    assert.throws(() => engine.importLegacy(Buffer.alloc(31), null), /32 bytes/);
    engine.importLegacy(seed, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
