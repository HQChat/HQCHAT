// The helper's AI replies (src/bot.ts, src/assistant.ts, src/quota.ts): off
// until a friend sends /ai on, commands never reach the model, limits refuse
// before any call, and what was said is remembered in memory only.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import Anthropic from "@anthropic-ai/sdk";
import type { CoreEffect } from "@hqchat/common/core";
import type { CoreClient } from "@hqchat/common/core-client";
import { Assistant, MODEL, openAssistant } from "../../src/assistant";
import { AI_MAX_INPUT, Bot, type BotAi, Greeted } from "../../src/bot";
import { IdSet } from "../../src/ids";
import { Quota, type QuotaLimits } from "../../src/quota";
import { AI_BUSY, AI_FAILED, AI_LIMIT, AI_NUDGE, AI_TOO_LONG, AI_UNAVAILABLE } from "../../src/replies";

type Body = Anthropic.MessageCreateParamsNonStreaming;

function message(over: Partial<Anthropic.Message> = {}): Anthropic.Message {
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: MODEL,
    content: [{ type: "text", text: "hi from haiku", citations: null }],
    stop_reason: "end_turn",
    stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
    ...over,
  } as Anthropic.Message;
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

function harness(
  opts: { ai?: boolean; limits?: Partial<QuotaLimits>; reply?: (body: Body) => Promise<Anthropic.Message> } = {},
) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-bot-ai-"));
  const sent: string[] = [];
  const bodies: Body[] = [];
  let deliver: (m: { peer: string; text: string }) => void = () => {};
  const client = {
    onMessage: (fn: typeof deliver) => {
      deliver = fn;
    },
    onEffect: (_fn: (e: CoreEffect) => void) => {},
    run: (command: () => CoreEffect[]) => command(),
    send: (_peer: string, text: string) => {
      sent.push(text);
      return `m${sent.length}`;
    },
    engine: { friends: () => [{ id: "friend", username: "alice" }], retry: () => [] },
  } as unknown as CoreClient;
  const ai: BotAi | undefined =
    opts.ai === false
      ? undefined
      : {
          assistant: new Assistant((body) => {
            bodies.push(structuredClone(body));
            return opts.reply ? opts.reply(body) : Promise.resolve(message());
          }),
          optIn: new IdSet(path.join(dir, "ai-optin.json")),
          quota: new Quota(path.join(dir, "quota.json"), {
            perMinute: 10,
            perDay: 50,
            globalPerDay: 2000,
            ...opts.limits,
          }),
        };
  const bot = new Bot(client, new Greeted(path.join(dir, "greeted.json")), "helper", 60_000, ai);
  const say = async (text: string, peer = "friend") => {
    deliver({ peer, text });
    await settle();
    return sent.at(-1);
  };
  const done = () => fs.rmSync(dir, { recursive: true, force: true });
  return { dir, sent, bodies, bot, say, done };
}

test("without a key there is no AI: /ai says so, the welcome does not offer it, text is echoed", async () => {
  const h = harness({ ai: false });
  try {
    h.bot.greetFriends();
    assert.doesNotMatch(h.sent[0] ?? "", /\/ai/);
    assert.equal(await h.say("/ai on"), AI_UNAVAILABLE);
    assert.equal(await h.say("what is the time"), 'You said: "what is the time"');
  } finally {
    h.done();
  }
});

test("AI is off until /ai on: the welcome offers it, text gets a nudge, commands stay local", async () => {
  const h = harness();
  try {
    h.bot.greetFriends();
    assert.match(h.sent[0] ?? "", /Claude, by Anthropic/);
    assert.match(h.sent[0] ?? "", /only if you send \/ai on/);
    assert.equal(await h.say("what is hqc?"), AI_NUDGE);
    assert.match((await h.say("/ai")) ?? "", /only the text you send in this chat goes to Anthropic[\s\S]*off for you/);
    await h.say("/ai on");
    for (const cmd of ["/help", "/game prc rock", "/support", "/ai", "/forget"]) await h.say(cmd);
    assert.equal(h.bodies.length, 0, "no command reaches the model");
  } finally {
    h.done();
  }
});

test("after /ai on, free text goes to Haiku and the reply comes back; history follows", async () => {
  const h = harness();
  try {
    await h.say("/ai on");
    assert.equal(await h.say("what is hqc?"), "hi from haiku");
    const [first] = h.bodies;
    assert.ok(first);
    assert.equal(first.model, "claude-haiku-5-5");
    assert.deepEqual(first.output_config, { effort: "low" });
    assert.match(String(first.system), /You are "helper"/);
    for (const banned of ["temperature", "top_p", "top_k", "thinking"]) assert.ok(!(banned in first), banned);
    assert.deepEqual(first.messages, [{ role: "user", content: "what is hqc?" }]);

    await h.say("and kyber?");
    const second = h.bodies[1];
    assert.deepEqual(
      second?.messages.map((m) => m.role),
      ["user", "assistant", "user"],
      "the history ends on the new user turn, never an assistant prefill",
    );
  } finally {
    h.done();
  }
});

test("/forget and /ai off clear the memory; after /ai off text gets the nudge again", async () => {
  const h = harness();
  try {
    await h.say("/ai on");
    await h.say("one");
    await h.say("/forget");
    await h.say("two");
    assert.deepEqual(h.bodies[1]?.messages, [{ role: "user", content: "two" }]);
    await h.say("/ai off");
    assert.equal(await h.say("three"), AI_NUDGE);
    assert.equal(h.bodies.length, 2);
    await h.say("/ai on");
    await h.say("four");
    assert.deepEqual(h.bodies[2]?.messages, [{ role: "user", content: "four" }]);
  } finally {
    h.done();
  }
});

test("limits refuse before any call, per friend", async () => {
  const h = harness({ limits: { perMinute: 2, perDay: 3, globalPerDay: 5 } });
  try {
    await h.say("/ai on");
    await h.say("/ai on", "other");
    await h.say("a");
    await h.say("b");
    assert.equal(await h.say("c"), AI_LIMIT.minute);
    assert.equal(h.bodies.length, 2);
    await h.say("d", "other");
    await h.say("e", "other");
    assert.equal(await h.say("f", "other"), AI_LIMIT.minute);
    assert.equal(h.bodies.length, 4);
  } finally {
    h.done();
  }
});

test("the global limit holds across peers, and day counts survive a restart", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-quota-"));
  try {
    const file = path.join(dir, "quota.json");
    const limits = { perMinute: 100, perDay: 2, globalPerDay: 3 };
    const t = Date.UTC(2026, 9, 25, 12);
    const q = new Quota(file, limits);
    assert.equal(q.take("a", t), null);
    assert.equal(q.take("a", t + 1), null);
    assert.equal(q.take("a", t + 2), "day");
    assert.equal(new Quota(file, limits).take("b", t + 3), null, "a restart keeps the day's counts");
    assert.equal(new Quota(file, limits).take("c", t + 4), "global");
    assert.equal(new Quota(file, limits).take("c", t + 86_400_000), null, "a new day starts again");
    assert.doesNotMatch(fs.readFileSync(file, "utf8"), /text|content/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("too long a message and a second one in flight are refused without a call", async () => {
  let release: () => void = () => {};
  const h = harness({
    reply: () =>
      new Promise((resolve) => {
        release = () => resolve(message());
      }),
  });
  try {
    await h.say("/ai on");
    assert.equal(await h.say("x".repeat(AI_MAX_INPUT + 1)), AI_TOO_LONG);
    await h.say("first");
    assert.equal(await h.say("second"), AI_BUSY);
    assert.equal(h.bodies.length, 1);
    release();
    await settle();
    assert.equal(h.sent.at(-1), "hi from haiku");
  } finally {
    h.done();
  }
});

test("refusals, cut replies, errors and empty replies get the fixed line; thinking is not sent", async () => {
  const cases: Array<[string, () => Promise<Anthropic.Message>, string]> = [
    ["refusal", () => Promise.resolve(message({ stop_reason: "refusal", content: [] })), AI_FAILED],
    ["cut", () => Promise.resolve(message({ stop_reason: "max_tokens" })), AI_FAILED],
    ["empty", () => Promise.resolve(message({ content: [] })), AI_FAILED],
    [
      "server error",
      () => Promise.reject(new Anthropic.InternalServerError(500, undefined, "boom", new Headers())),
      AI_FAILED,
    ],
    ["network", () => Promise.reject(new Anthropic.APIConnectionError({ message: "down" })), AI_FAILED],
    [
      "thinking first",
      () =>
        Promise.resolve(
          message({
            content: [
              { type: "thinking", thinking: "", signature: "sig" },
              { type: "text", text: "the answer", citations: null },
            ] as Anthropic.ContentBlock[],
          }),
        ),
      "the answer",
    ],
  ];
  for (const [name, reply, expected] of cases) {
    const h = harness({ reply });
    try {
      await h.say("/ai on");
      assert.equal(await h.say("q"), expected, name);
    } finally {
      h.done();
    }
  }
});

test("a refused key turns AI replies off until a restart", async () => {
  let calls = 0;
  const h = harness({
    reply: () => {
      calls += 1;
      return Promise.reject(new Anthropic.AuthenticationError(401, undefined, "invalid x-api-key", new Headers()));
    },
  });
  try {
    await h.say("/ai on");
    assert.equal(await h.say("q1"), AI_FAILED);
    assert.equal(await h.say("q2"), AI_FAILED);
    assert.equal(calls, 1);
  } finally {
    h.done();
  }
});

test("nothing anyone says to the AI is written to the state folder", async () => {
  const h = harness({
    reply: () => Promise.resolve(message({ content: [{ type: "text", text: "zebra-reply", citations: null }] })),
  });
  try {
    await h.say("/ai on");
    await h.say("my secret is aardvark-question");
    const files = fs.readdirSync(h.dir);
    for (const f of files) {
      const body = fs.readFileSync(path.join(h.dir, f), "utf8");
      assert.doesNotMatch(body, /aardvark|zebra/, f);
    }
  } finally {
    h.done();
  }
});

test("the key comes from a file, never the environment", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-key-"));
  try {
    assert.equal(openAssistant({}), undefined, "no key, no AI");
    assert.throws(
      () => openAssistant({ NODE_ENV: "production", ANTHROPIC_API_KEY: "sk-ant-placeholder" }),
      /ANTHROPIC_API_KEY_PATH/,
    );
    const file = path.join(dir, "anthropic_api_key");
    fs.writeFileSync(file, "");
    assert.equal(openAssistant({ ANTHROPIC_API_KEY_PATH: file }), undefined, "an empty file turns AI off");
    fs.writeFileSync(file, "sk-ant-placeholder\n");
    const before = process.env.ANTHROPIC_API_KEY;
    assert.ok(openAssistant({ ANTHROPIC_API_KEY_PATH: file }) instanceof Assistant);
    assert.equal(process.env.ANTHROPIC_API_KEY, before, "the key is not put in the environment");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
