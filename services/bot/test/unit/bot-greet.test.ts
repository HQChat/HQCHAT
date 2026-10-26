// The bot's welcome (src/bot.ts Bot): the server befriends a new account
// before its app publishes prekeys, so the first welcome fails; the bot sends
// the same message again until the broker takes it, and greets once.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import type { CoreEffect } from "@hqchat/common/core";
import type { CoreClient } from "@hqchat/common/core-client";
import { Bot, Greeted } from "../../src/bot";

function fakeClient() {
  let emit: (e: CoreEffect) => void = () => {};
  const sent: string[] = [];
  const retried: string[] = [];
  const client = {
    onMessage: () => {},
    onEffect: (fn: (e: CoreEffect) => void) => {
      emit = fn;
    },
    run: (command: () => CoreEffect[]) => command(),
    send: (_peer: string, text: string) => {
      sent.push(text);
      return `m${sent.length}`;
    },
    engine: {
      friends: () => [{ id: "friend", username: "alice" }],
      retry: (msgId: string) => {
        retried.push(msgId);
        return [];
      },
    },
  };
  return { client: client as unknown as CoreClient, emit: (e: CoreEffect) => emit(e), sent, retried };
}

test("a failed welcome is retried as the same message until the broker takes it, and only once", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-bot-greet-"));
  try {
    const greeted = new Greeted(path.join(dir, "greeted.json"));
    const { client, emit, sent, retried } = fakeClient();
    const bot = new Bot(client, greeted, "helper", 60_000);

    bot.greetFriends();
    assert.equal(sent.length, 1);
    assert.match(sent.join(), /welcome to hqchat, @alice/);

    emit({ kind: "messageStatus", msgId: "m1", state: "failed" } as CoreEffect);
    bot.greetFriends();
    assert.equal(sent.length, 1, "a friend change does not send a second welcome");
    bot.retryGreetings();
    assert.deepEqual(retried, ["m1"]);
    bot.retryGreetings();
    assert.deepEqual(retried, ["m1"], "nothing is retried while the retry is under way");

    emit({ kind: "messageStatus", msgId: "m1", state: "sent" } as CoreEffect);
    assert.ok(greeted.has("friend"));
    bot.greetFriends();
    bot.retryGreetings();
    assert.equal(sent.length, 1);
    assert.deepEqual(retried, ["m1"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
