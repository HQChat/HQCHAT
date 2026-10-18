/**
 * The helper bot: an ordinary HQChat account on the Rust core (the same Engine
 * the apps link, through src/common/core-client.ts), so it uses nothing a
 * third-party client could not. It accepts every invite, greets each new
 * friend once and answers messages (replies.ts).
 *
 *   BASE_URL        the server's origin                (http://127.0.0.1:8090)
 *   MQTT_URL        the broker's WebSocket endpoint     (ws://127.0.0.1:8083/mqtt)
 *   BOT_USERNAME    handle to claim                     (helper)
 *   BOT_SEED        32-byte hex identity seed; generated into BOT_STATE_DIR when unset
 *   BOT_STATE_DIR   where the seed and state persist    (./.bot)
 *   SUPPORT_EMAIL   address given by /support
 *
 * The identity still derives from the seed, so the bot keeps its id across
 * the move to the core. The server befriends every new account to the
 * identity named by BOT_ID; `bot --print-id` prints that id for the
 * configured seed and exits.
 *
 * State in BOT_STATE_DIR: `seed` (when BOT_SEED is unset), `device-key` (the
 * software key the core's state is sealed to), `core/` (the engine's sealed
 * blobs), `greeted.json`, and `state.json.imported`, the TS client's state
 * the core imported on its first start, kept as a backup.
 */

import "../common/config";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { core } from "../common/core";
import { CoreClient, type CoreClientOptions } from "../common/core-client";
import { startHealthMonitor } from "../common/health-monitor";
import { logger } from "../common/logger";
import { initObservability } from "../common/observability";
import { reply } from "./replies";

const BASE_URL = (process.env.BASE_URL || "http://127.0.0.1:8090").replace(/\/$/, "");
const MQTT_URL = process.env.MQTT_URL || "ws://127.0.0.1:8083/mqtt";
const USERNAME = process.env.BOT_USERNAME || "helper";
const STATE_DIR = process.env.BOT_STATE_DIR || path.join(process.cwd(), ".bot");
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@example.com";

const WELCOME = (name: string) =>
  [
    `welcome to hqchat, @${name}.`,
    "",
    "i'm helper — the account you start with, so your first conversation isn't an empty screen. this chat is end-to-end encrypted like every other one: the server relays it and can't read it.",
    "",
    "try /help for what i can do, or just say hello.",
  ].join("\n");

/** The identity seed: BOT_SEED, else the one saved in `dir`, else a new one saved there. */
export function loadSeed(dir: string): Buffer {
  if (process.env.BOT_SEED) return Buffer.from(process.env.BOT_SEED.trim(), "hex");
  const file = path.join(dir, "seed");
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, "utf8").trim(), "hex");
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
 * The bot's client on the core: the engine under `dir/core`, sealed to the
 * device key in `dir/device-key`. Without that key nothing under `core/` can
 * be opened, so a first start (or one that stopped before saving the key)
 * builds the profile from the seed, importing the friends, sessions and
 * prekeys the TS client left in `state.json`.
 */
export function openBot(
  dir: string,
  seed: Buffer,
  opts: Omit<CoreClientOptions, "dir" | "deviceKey" | "profileId">,
): CoreClient {
  const keyFile = path.join(dir, "device-key");
  const coreDir = path.join(dir, "core");
  if (fs.existsSync(keyFile)) {
    const deviceKey = Buffer.from(fs.readFileSync(keyFile, "utf8").trim(), "hex");
    return new CoreClient({ ...opts, profileId: "bot", dir: coreDir, deviceKey });
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.rmSync(coreDir, { recursive: true, force: true });
  const client = new CoreClient({ ...opts, profileId: "bot", dir: coreDir });
  const legacy = [path.join(dir, "state.json"), path.join(dir, "state.json.imported")].find((f) => fs.existsSync(f));
  const imported = client.engine.importLegacy(seed, legacy ? fs.readFileSync(legacy, "utf8") : null);
  for (const id of imported.unreadable) {
    logger.warn(`[bot] the session with ${id.slice(0, 12)}… could not be read; the next message opens a new one`);
  }
  const deviceKey = client.deviceKey;
  if (!deviceKey) throw new Error("the core made no device key");
  fs.writeFileSync(keyFile, deviceKey.toString("hex"), { mode: 0o600, flag: "wx" });
  if (legacy?.endsWith("state.json")) fs.renameSync(legacy, `${legacy}.imported`);
  logger.startup(`[bot] moved to the core${legacy ? ` with the state in ${path.basename(legacy)}` : ""}`);
  return client;
}

/** The ids already welcomed, persisted so a restart never greets twice. */
export class Greeted {
  private readonly ids: Set<string>;

  constructor(private readonly file: string) {
    this.ids = new Set(fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as string[]) : []);
  }

  has(id: string): boolean {
    return this.ids.has(id);
  }

  add(id: string): void {
    this.ids.add(id);
    fs.writeFileSync(this.file, JSON.stringify([...this.ids]), { mode: 0o600 });
  }
}

/** The bot's behaviour on top of a started client. */
export class Bot {
  /** Welcomes in flight, by message id: a friend counts as greeted once the broker has it. */
  private readonly greeting = new Map<string, string>();
  private claimed = false;

  constructor(
    private readonly client: CoreClient,
    private readonly greeted: Greeted,
    private readonly username = USERNAME,
  ) {
    client.onMessage((m) => this.answer(m.peer, m.text));
    client.onEffect((e) => {
      if (e.kind === "invitesChanged") this.acceptInvites();
      else if (e.kind === "friendsChanged") this.greetFriends();
      else if (e.kind === "messageStatus") this.settleGreeting(e.msgId!, e.state!);
      else if (e.kind === "connection" && e.state === "connected") this.claimUsername();
    });
  }

  private answer(peer: string, text: string): void {
    try {
      this.client.send(peer, reply(text, { supportEmail: SUPPORT_EMAIL }));
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
        this.greeting.set(this.client.send(friend.id, WELCOME(friend.username || "there")), friend.id);
      } catch (e) {
        logger.warn(`[bot] could not greet ${friend.id.slice(0, 12)}…: ${(e as Error).message}`);
      }
    }
  }

  /** A welcome the broker took counts; a failed one is retried at the next friend change. */
  private settleGreeting(msgId: string, state: string): void {
    const id = this.greeting.get(msgId);
    if (!id) return;
    if (state === "failed") this.greeting.delete(msgId);
    else if (state === "sent" || state === "queued" || state === "delivered") {
      this.greeting.delete(msgId);
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
  new Bot(client, new Greeted(path.join(STATE_DIR, "greeted.json")));
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
