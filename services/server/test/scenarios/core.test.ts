// The Rust core against the real stack: a user on the core (the Engine the
// apps link, over hqn/1 when the server offers it) and a user on the TS
// reference client befriend each other and talk both ways; the core user is
// also welcomed by the helper bot, which runs on the core too.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { after, test } from "node:test";
import type { CoreEffect, CoreMessage } from "../../src/common/core";
import { CoreClient } from "../../src/common/core-client";
import { BASE_URL, BOT_USERNAME, MQTT_URL, signedUp, stackUp, tag } from "./stack";

const dirs: string[] = [];
const clients: CoreClient[] = [];

after(() => {
  for (const c of clients) {
    c.run(() => c.engine.deleteAccount());
    c.stop();
  }
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

/** A user on the core, signed in and connected, with the effects and messages it saw. */
async function coreUser(): Promise<{ client: CoreClient; messages: CoreMessage[]; effects: CoreEffect[] }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-core-scenario-"));
  dirs.push(dir);
  const client = new CoreClient({ serverUrl: BASE_URL, wssUrl: MQTT_URL, profileId: "scenario", dir });
  clients.push(client);
  const messages: CoreMessage[] = [];
  const effects: CoreEffect[] = [];
  client.onMessage((m) => messages.push(m));
  client.onEffect((e) => effects.push(e));
  client.run(() => client.engine.createIdentity());
  client.start();
  await until(() => effects.some((e) => e.kind === "connection" && e.state === "connected"), "connected");
  return { client, messages, effects };
}

async function until(done: () => boolean, what: string, ms = 30_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!done()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

test("a core user and a TS user befriend each other and talk both ways", async (t) => {
  if (!(await stackUp(t))) return;
  const core = await coreUser();
  const { client: ts, username } = await signedUp("ts");
  core.client.run(() => core.client.engine.invite(username));
  let accepted = false;
  for (let i = 0; i < 50 && !accepted; i++) {
    const [mine] = await ts.api.invites();
    if (mine) {
      await ts.api.accept(mine.id);
      accepted = true;
    } else await new Promise((r) => setTimeout(r, 200));
  }
  assert.ok(accepted, "the TS user sees the core user's invite");
  await ts.sync();
  await ts.connect();
  await until(() => core.client.engine.friends().some((f) => f.id === ts.id), "the friendship on the core side");

  // The bot greets the TS user too, so its messages are told apart by sender.
  const coreId = (await ts.api.friends()).find((f) => f.username !== BOT_USERNAME)!.id;
  const text = `from the core ${tag()}`;
  core.client.send(ts.id, text);
  assert.equal((await ts.next(coreId, 30_000)).text, text);
  await ts.send(coreId, "from typescript");
  await until(() => core.messages.some((m) => m.text === "from typescript"), "the TS reply on the core side");
});

test("the helper bot, on the core, welcomes a new user who is on the core", async (t) => {
  if (!(await stackUp(t))) return;
  const core = await coreUser();
  await until(() => core.messages.some((m) => m.text.startsWith("welcome to hqchat")), "the bot's welcome", 60_000);
  const bot = core.messages.find((m) => m.text.startsWith("welcome to hqchat"))!.peer;
  core.client.send(bot, "/help");
  await until(() => core.messages.filter((m) => m.peer === bot).length >= 2, "the bot's answer");
});
