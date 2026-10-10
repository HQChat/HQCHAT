/**
 * The helper bot: an ordinary HQChat account built on the reference client
 * (src/client), so it uses nothing a third-party client could not. It accepts
 * every invite, greets each new friend once and answers messages (replies.ts).
 *
 *   BASE_URL        the server's origin                (http://127.0.0.1:8090)
 *   MQTT_URL        the broker's WebSocket endpoint     (ws://127.0.0.1:8083/mqtt)
 *   BOT_USERNAME    handle to claim                     (helper)
 *   BOT_SEED        32-byte hex identity seed; generated into BOT_STATE_DIR when unset
 *   BOT_STATE_DIR   where the seed and state persist    (./.bot)
 *   SUPPORT_EMAIL   address given by /support
 *   FRIEND_POLL_MS  how often the friend graph is re-read  (15000)
 *
 * The server befriends every new account to the identity named by BOT_ID;
 * `bot --print-id` prints that id for the configured seed and exits.
 */

import "../common/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { ApiError, Client, FileStore, identityFromSeed, newSeed } from "../client";
import { startHealthMonitor } from "../common/health-monitor";
import { logger } from "../common/logger";
import { initObservability } from "../common/observability";
import { reply } from "./replies";

const BASE_URL = (process.env.BASE_URL || "http://127.0.0.1:8090").replace(/\/$/, "");
const MQTT_URL = process.env.MQTT_URL || "ws://127.0.0.1:8083/mqtt";
const USERNAME = process.env.BOT_USERNAME || "helper";
const STATE_DIR = process.env.BOT_STATE_DIR || path.join(process.cwd(), ".bot");
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@example.com";
const FRIEND_POLL_MS = Number(process.env.FRIEND_POLL_MS || 15_000);

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
  const seed = newSeed();
  try {
    fs.writeFileSync(file, seed.toString("hex"), { mode: 0o600, flag: "wx" });
    return seed;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    return Buffer.from(fs.readFileSync(file, "utf8").trim(), "hex");
  }
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

/** The bot's behaviour on top of a connected client. */
export class Bot {
  private readonly greeting = new Set<string>();

  constructor(
    private readonly client: Client,
    private readonly greeted: Greeted,
  ) {
    client.onGraphChanged(() => this.syncGraph());
    client.onMessage((m) => {
      client.send(m.from, reply(m.text, { supportEmail: SUPPORT_EMAIL })).catch((e: Error) => {
        logger.warn(`[bot] could not reply to ${m.from.slice(0, 12)}…: ${e.message}`);
      });
    });
  }

  /** Accepts pending invites, re-reads the graph and greets new friends. */
  async syncGraph(): Promise<void> {
    for (const invite of await this.client.api.invites()) await this.client.api.accept(invite.id);
    await this.client.sync();
    if (!this.client.connected) return;
    for (const id of Object.keys(this.client.conversations.state.peers)) await this.greet(id);
  }

  private async greet(id: string): Promise<void> {
    if (this.greeted.has(id) || this.greeting.has(id)) return;
    this.greeting.add(id);
    try {
      const name = this.client.conversations.peer(id)?.username || "there";
      await this.client.send(id, WELCOME(name));
      this.greeted.add(id);
    } catch (e) {
      if (e instanceof ApiError && e.code === "NO_PREKEYS") return;
      logger.warn(`[bot] could not greet ${id.slice(0, 12)}…: ${(e as Error).message}`);
    } finally {
      this.greeting.delete(id);
    }
  }
}

async function main(): Promise<void> {
  initObservability("bot");
  startHealthMonitor();
  const identity = identityFromSeed(loadSeed(STATE_DIR));
  logger.startup(`[bot] id ${identity.id} (set BOT_ID to this on the server)`);
  const client = new Client({
    baseUrl: BASE_URL,
    endpoint: { url: MQTT_URL },
    identity,
    store: new FileStore(path.join(STATE_DIR, "state.json")),
    reconnect: true,
    log: (line) => logger.debug(`[bot] ${line}`),
  });
  const bot = new Bot(client, new Greeted(path.join(STATE_DIR, "greeted.json")));

  for (let attempt = 1; ; attempt++) {
    try {
      await client.signIn();
      await client.api.setUsername(USERNAME).catch((e: Error) => {
        logger.warn(`[bot] could not claim @${USERNAME}: ${e.message}`);
      });
      await client.connect();
      logger.startup(`[bot] connected to the broker at ${MQTT_URL}`);
      break;
    } catch (e) {
      const wait = Math.min(30_000, 2_000 * attempt);
      logger.warn(`[bot] start attempt ${attempt} failed (${(e as Error).message}); retrying in ${wait}ms`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }

  const poll = async () => {
    try {
      await bot.syncGraph();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) await client.auth.signIn();
      else logger.warn(`[bot] friend poll: ${(e as Error).message}`);
    }
  };
  await poll();
  setInterval(() => void poll(), FRIEND_POLL_MS);
}

if (require.main === module) {
  if (process.argv.includes("--print-id")) console.log(identityFromSeed(loadSeed(STATE_DIR)).id);
  else void main();
}
