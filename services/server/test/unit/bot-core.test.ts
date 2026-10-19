// The bot's move to the core (src/bot/bot.ts openBot): the first start
// imports the seed and the TS client's state file, saves the device key and
// keeps the old file as a backup; later starts reopen the same profile.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { idOfSeed, openBot } from "../../src/bot/bot";
import { core } from "../../src/common/core";
import { FileStore } from "../reference/client/store";

const OPTS = { serverUrl: "https://hqchat.test", hqn: false };

function signInKey(client: ReturnType<typeof openBot>): string {
  const now = 1_790_000_000_000;
  let effects = client.engine.start(now, "test");
  // A restarted profile is locked until the device key opens it, as CoreClient does on needUnlock.
  if (effects.some((e) => e.kind === "needUnlock")) effects = client.engine.unlock(now);
  const init = effects.find((e) => e.path === "/auth/init");
  assert.ok(init?.body, "the engine signs in");
  return JSON.parse(init.body.toString()).pk;
}

test("the first start imports the TS state under the seed's id, and later starts reopen it", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-bot-"));
  try {
    const seed = crypto.randomBytes(32);
    const friend = core.hqcKeypairFromSeed(crypto.randomBytes(32));
    const friendId = core.peerId(friend.pk.toString("hex"));
    new FileStore(path.join(dir, "state.json")).save({
      peers: { [friendId]: { id: friendId, username: "alice", pk: friend.pk.toString("hex") } },
      prekeys: null,
    });

    const first = openBot(dir, seed, OPTS);
    assert.equal(core.peerId(signInKey(first)), idOfSeed(seed), "same id as before the move");
    assert.deepEqual(
      first.engine.friends().map((f) => [f.id, f.username]),
      [[friendId, "alice"]],
    );
    assert.equal(fs.statSync(path.join(dir, "device-key")).mode & 0o777, 0o600);
    assert.ok(fs.existsSync(path.join(dir, "state.json.imported")), "the TS state is kept as a backup");
    assert.ok(!fs.existsSync(path.join(dir, "state.json")));

    const again = openBot(dir, seed, OPTS);
    assert.equal(core.peerId(signInKey(again)), idOfSeed(seed), "a restart opens the same profile");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a start that lost the device key rebuilds the profile from the seed and the backup", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-bot-"));
  try {
    const seed = crypto.randomBytes(32);
    openBot(dir, seed, OPTS);
    fs.rmSync(path.join(dir, "device-key"));
    const rebuilt = openBot(dir, seed, OPTS);
    assert.equal(core.peerId(signInKey(rebuilt)), idOfSeed(seed));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
