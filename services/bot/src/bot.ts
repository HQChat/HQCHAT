/**
 * The helper bot: an ordinary HQChat account on the Rust core (the same Engine
 * the apps link, through services/common/src/core-client.ts), so it uses nothing a
 * third-party client could not. It accepts every invite, greets each new
 * friend once and answers messages: commands locally (replies.ts), anything
 * else with Claude Haiku (assistant.ts) for those who sent `/ai on`, when the
 * deployment gives the bot a key.
 *
 *   BASE_URL        the server's origin                (http://127.0.0.1:8090)
 *   MQTT_URL        the broker's WebSocket endpoint     (ws://127.0.0.1:8083/mqtt)
 *   BOT_USERNAME    handle to claim                     (helper)
 *   BOT_SEED        32-byte hex identity seed; generated into BOT_STATE_DIR when unset
 *   BOT_STATE_DIR   where the seed and state persist    (./.bot)
 *   SUPPORT_EMAIL   address given by /support
 *   ANTHROPIC_API_KEY_PATH  file holding the Anthropic key; unset, AI replies are off
 *   BOT_AI_DAILY_LIMIT      AI replies a day, everyone together (2000)
 *
 * The identity still derives from the seed, so the bot keeps its id across
 * the move to the core. The server befriends every new account to the
 * identity named by BOT_ID; `bot --print-id` prints that id for the
 * configured seed and exits.
 *
 * State in BOT_STATE_DIR: `seed` (when BOT_SEED is unset; in production the
 * seed is a credential and is not here), `core/` (the engine's sealed blobs,
 * under a device key derived from the seed), `greeted.json`,
 * `ai-optin.json` (ids that sent `/ai on`), `quota.json` (today's AI reply
 * counts), and `state.json.imported`, the TS client's state
 * the core imported on its first start, kept as a backup. What people say to
 * the AI is kept in memory only, never in BOT_STATE_DIR.
 */

import "@hqchat/common/file-env";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { core } from "@hqchat/common/core";
import { CoreClient, type CoreClientOptions } from "@hqchat/common/core-client";
import { startHealthMonitor } from "@hqchat/common/health-monitor";
import { logger } from "@hqchat/common/logger";
import { initObservability } from "@hqchat/common/observability";
import { type Assistant, MODEL, openAssistant } from "./assistant";
import { IdSet } from "./ids";
import { Quota } from "./quota";
import {
  AI_ABOUT,
  AI_BUSY,
  AI_FAILED,
  AI_FORGOT,
  AI_LIMIT,
  AI_NUDGE,
  AI_OFF,
  AI_ON,
  AI_TOO_LONG,
  AI_UNAVAILABLE,
  command,
  reply,
} from "./replies";

const BASE_URL = (process.env.BASE_URL || "http://127.0.0.1:8090").replace(/\/$/, "");
const MQTT_URL = process.env.MQTT_URL || "ws://127.0.0.1:8083/mqtt";
const USERNAME = process.env.BOT_USERNAME || "helper";
const STATE_DIR = process.env.BOT_STATE_DIR || path.join(process.cwd(), ".bot");
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@example.com";
/** How often a welcome that failed is sent again. */
const GREET_RETRY_MS = 15_000;
const AI_DAILY_LIMIT = positive(process.env.BOT_AI_DAILY_LIMIT) ?? 2000;
/** Longer messages are refused, not cut: a cut question gets a wrong answer. */
export const AI_MAX_INPUT = 4000;
/** Exchanges remembered per friend, in memory only. */
const AI_MEMORY_TURNS = 10;

const WELCOME = (name: string, ai: boolean) =>
  [
    `welcome to hqchat, @${name}.`,
    "",
    "i'm helper — the account you start with, so your first conversation isn't an empty screen. this chat is end-to-end encrypted like every other one: the server relays it and can't read it.",
    ...(ai
      ? [
          "",
          "i can also answer with AI (Claude, by Anthropic), but only if you send /ai on — /ai says what that shares first. your other chats are never part of it.",
        ]
      : []),
    "",
    "try /help for what i can do, or just say hello.",
  ].join("\n");

function positive(value: string | undefined): number | undefined {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

/** The identity seed: BOT_SEED, else the one saved in `dir`, else a new one saved there. */
export function loadSeed(dir: string): Buffer {
  if (process.env.BOT_SEED) return Buffer.from(process.env.BOT_SEED.trim(), "hex");
  const file = path.join(dir, "seed");
  try {
    return Buffer.from(fs.readFileSync(file, "utf8").trim(), "hex");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  fs.mkdirSync(dir, { recursive: true });
  const seed = crypto.randomBytes(32);
  try {
    fs.writeFileSync(file, seed.toString("hex"), { mode: 0o600, flag: "wx" });
    return seed;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    return Buffer.from(fs.readFileSync(file, "utf8").trim(), "hex");
  }
}

/** The id a seed derives: what the server's BOT_ID names. */
export function idOfSeed(seed: Buffer): string {
  return core.peerId(core.hqcKeypairFromSeed(seed).pk.toString("hex"));
}

/**
 * The bot's client on the core: the engine under `dir/core`, sealed to a
 * device key derived from the seed (in production a credential, not in
 * `dir`), so a copy of `dir` opens nothing. A first start builds the profile
 * from the seed, importing the friends, sessions and prekeys the TS client
 * left in `state.json`. A `device-key` file from a build that stored the key
 * is deleted, with the store it sealed, and the profile is built again.
 */
export function openBot(
  dir: string,
  seed: Buffer,
  opts: Omit<CoreClientOptions, "dir" | "deviceKey" | "profileId">,
): CoreClient {
  const coreDir = path.join(dir, "core");
  const deviceKey = core.deviceKeyFromSeed(seed);
  const stored = path.join(dir, "device-key");
  if (fs.existsSync(stored)) {
    fs.rmSync(coreDir, { recursive: true, force: true });
    fs.rmSync(stored, { force: true });
  }
  if (fs.existsSync(path.join(coreDir, "state"))) {
    return new CoreClient({ ...opts, profileId: "bot", dir: coreDir, deviceKey });
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.rmSync(coreDir, { recursive: true, force: true });
  const client = new CoreClient({ ...opts, profileId: "bot", dir: coreDir, deviceKey });
  const legacy = [path.join(dir, "state.json"), path.join(dir, "state.json.imported")].find((f) => fs.existsSync(f));
  const imported = client.engine.importLegacy(seed, legacy ? fs.readFileSync(legacy, "utf8") : null, Date.now());
  for (const id of imported.unreadable) {
    logger.warn(`[bot] the session with ${id.slice(0, 12)}… could not be read; the next message opens a new one`);
  }
  if (legacy?.endsWith("state.json")) fs.renameSync(legacy, `${legacy}.imported`);
  logger.startup(`[bot] moved to the core${legacy ? ` with the state in ${path.basename(legacy)}` : ""}`);
  return client;
}

/** The ids already welcomed, persisted so a restart never greets twice. */
export class Greeted extends IdSet {}

/** What AI replies need; absent when the deployment gives the bot no key. */
export interface BotAi {
  assistant: Assistant;
  /** Who sent `/ai on`. */
  optIn: IdSet;
  quota: Quota;
}

/** The bot's behaviour on top of a started client. */
export class Bot {
  /** Welcomes in flight, by message id: a friend counts as greeted once the broker has it. */
  private readonly greeting = new Map<string, string>();
  /** Welcomes the core marked failed, by message id, waiting to be sent again. */
  private readonly failed = new Set<string>();
  private claimed = false;
  /** The conversation with the AI, per friend: memory only, never written to disk. */
  private readonly memory = new Map<string, Anthropic.MessageParam[]>();
  /** Bumped by /forget and /ai off, so an answer in flight is not remembered after them. */
  private readonly forgets = new Map<string, number>();
  /** Friends with an AI call in flight: one at a time each. */
  private readonly asking = new Set<string>();

  constructor(
    private readonly client: CoreClient,
    private readonly greeted: Greeted,
    private readonly username = USERNAME,
    retryMs = GREET_RETRY_MS,
    private readonly ai?: BotAi,
  ) {
    setInterval(() => this.retryGreetings(), retryMs).unref();
    client.onMessage((m) => this.answer(m.peer, m.text));
    client.onEffect((e) => {
      if (e.kind === "invitesChanged") this.acceptInvites();
      else if (e.kind === "friendsChanged") this.greetFriends();
      else if (e.kind === "messageStatus") this.settleGreeting(e.msgId!, e.state!);
      else if (e.kind === "connection" && e.state === "connected") this.claimUsername();
    });
  }

  private answer(peer: string, text: string): void {
    const local = this.localAnswer(peer, text);
    if (local !== null) this.say(peer, local);
    else if (this.ai) void this.askAi(this.ai, peer, text);
  }

  /** The answer that needs no AI call, or null when the AI answers. */
  private localAnswer(peer: string, text: string): string | null {
    const deps = { supportEmail: SUPPORT_EMAIL };
    const lower = text.trim().toLowerCase();
    const { ai } = this;
    if (lower === "/ai" || lower.startsWith("/ai ")) {
      if (!ai) return AI_UNAVAILABLE;
      const arg = lower.slice("/ai".length).trim();
      if (arg === "on") {
        ai.optIn.add(peer);
        return AI_ON;
      }
      if (arg === "off") {
        ai.optIn.delete(peer);
        this.forget(peer);
        return AI_OFF;
      }
      const state = ai.optIn.has(peer)
        ? `they're on for you, with ${ai.quota.left(peer, Date.now())} left today.`
        : "they're off for you.";
      return `${AI_ABOUT}\n\n${state}`;
    }
    if (lower === "/forget") {
      this.forget(peer);
      return AI_FORGOT;
    }
    const cmd = command(text, deps);
    if (cmd !== null) return cmd;
    if (!ai) return reply(text, deps);
    if (!ai.optIn.has(peer)) return lower.includes("hello") ? reply(text, deps) : AI_NUDGE;
    return null;
  }

  private forget(peer: string): void {
    this.memory.delete(peer);
    this.forgets.set(peer, (this.forgets.get(peer) ?? 0) + 1);
  }

  /** Checks run before any call: one in flight, the length, then the quota (which counts the call). */
  private async askAi(ai: BotAi, peer: string, text: string): Promise<void> {
    if (this.asking.has(peer)) return this.say(peer, AI_BUSY);
    if (text.length > AI_MAX_INPUT) return this.say(peer, AI_TOO_LONG);
    const refused = ai.quota.take(peer, Date.now());
    if (refused) return this.say(peer, AI_LIMIT[refused]);
    this.asking.add(peer);
    try {
      const history = this.memory.get(peer) ?? [];
      const epoch = this.forgets.get(peer);
      const answer = await ai.assistant.answer(history, text);
      // Turned off while the call ran: the reply is dropped with the rest.
      if (!ai.optIn.has(peer)) return;
      if (!answer.ok) return this.say(peer, AI_FAILED);
      if (this.forgets.get(peer) === epoch) {
        const turns: Anthropic.MessageParam[] = [
          ...history,
          { role: "user", content: text },
          { role: "assistant", content: answer.text },
        ];
        this.memory.set(peer, turns.slice(-2 * AI_MEMORY_TURNS));
      }
      this.say(peer, answer.text);
    } finally {
      this.asking.delete(peer);
    }
  }

  private say(peer: string, text: string): void {
    try {
      this.client.send(peer, text);
    } catch (e) {
      logger.warn(`[bot] could not reply to ${peer.slice(0, 12)}…: ${(e as Error).message}`);
    }
  }

  private claimUsername(): void {
    if (this.claimed) return;
    this.claimed = true;
    this.client.run(() => this.client.engine.setUsername(this.username));
  }

  acceptInvites(): void {
    for (const invite of this.client.engine.invites()) {
      this.client.run(() => this.client.engine.accept(invite.id));
    }
  }

  greetFriends(): void {
    const pending = new Set(this.greeting.values());
    for (const friend of this.client.engine.friends()) {
      if (this.greeted.has(friend.id) || pending.has(friend.id)) continue;
      try {
        this.greeting.set(this.client.send(friend.id, WELCOME(friend.username || "there", !!this.ai)), friend.id);
      } catch (e) {
        logger.warn(`[bot] could not greet ${friend.id.slice(0, 12)}…: ${(e as Error).message}`);
      }
    }
  }

  /**
   * The server befriends a new account before its app publishes prekeys, so
   * the first welcome usually fails: the same message goes again until the
   * broker takes it.
   */
  retryGreetings(): void {
    for (const msgId of this.failed) {
      this.failed.delete(msgId);
      this.client.run(() => this.client.engine.retry(msgId, Date.now()));
    }
  }

  /** A welcome the broker took counts; a failed one waits for retryGreetings. */
  private settleGreeting(msgId: string, state: string): void {
    const id = this.greeting.get(msgId);
    if (!id) return;
    if (state === "failed") this.failed.add(msgId);
    else if (state === "sent" || state === "queued" || state === "delivered") {
      this.greeting.delete(msgId);
      this.failed.delete(msgId);
      this.greeted.add(id);
    }
  }
}

function main(): void {
  initObservability("bot");
  startHealthMonitor();
  const seed = loadSeed(STATE_DIR);
  logger.startup(`[bot] id ${idOfSeed(seed)} (set BOT_ID to this on the server)`);
  const client = openBot(STATE_DIR, seed, {
    serverUrl: BASE_URL,
    wssUrl: MQTT_URL,
    // The broker's WebSocket is the bot's private path; hqn/1 is for the internet.
    hqn: false,
    log: (line) => logger.debug(`[bot] ${line}`),
  });
  const assistant = openAssistant();
  const ai = assistant && {
    assistant,
    optIn: new IdSet(path.join(STATE_DIR, "ai-optin.json")),
    quota: new Quota(path.join(STATE_DIR, "quota.json"), { perMinute: 10, perDay: 50, globalPerDay: AI_DAILY_LIMIT }),
  };
  logger.startup(
    ai ? `[bot] AI replies on for those who opt in (${MODEL}, ${AI_DAILY_LIMIT} a day)` : "[bot] AI replies off",
  );
  new Bot(client, new Greeted(path.join(STATE_DIR, "greeted.json")), USERNAME, GREET_RETRY_MS, ai);
  client.onEffect((e) => {
    if (e.kind === "connection") logger.debug(`[bot] ${e.state}`);
    if (e.kind === "connection" && e.state === "connected")
      logger.startup(`[bot] connected to the broker at ${MQTT_URL}`);
  });
  client.start();
}

if (require.main === module) {
  if (process.argv.includes("--print-id")) console.log(idOfSeed(loadSeed(STATE_DIR)));
  else main();
}
