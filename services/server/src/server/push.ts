import mqtt from "mqtt";
import { logger } from "../common/logger";
import { ApnsService, keyProblem, type SendOutcome } from "./apns";
import { apnsGaps, apnsIntended, apnsSummary } from "./apns-config";
import { DB } from "./db/api";

/**
 * The push bridge: subscribes (as the internal superuser) to every presence
 * topic and, shared across replicas, every conversation topic and every
 * inbox, and sends a content-free APNs wake to each offline member of a
 * conversation and to the offline owner of an inbox (where a first message,
 * an `init`, arrives before the conversation topic is in use). The phone
 * shows that a message is waiting; opening it still needs the unlock. The
 * bridge sees ciphertext and topic metadata only.
 *
 * Any account may publish into any inbox, and the bridge cannot see who
 * published, so the bridge itself bounds what a publisher can make it do: one
 * wake per recipient per wake interval, whatever arrives meanwhile, and a
 * remembered "no such conversation" for ids nobody holds, so junk topics do
 * not cost a database query each. Every map it keeps is bounded.
 */

const SHARE_GROUP = process.env.PUSH_SHARE_GROUP || "pushbridge";

/** What the bridge needs from the database and APNs, injectable for tests. */
export interface PushDeps {
  getTopicMembers: (convoId: string) => Promise<string[]>;
  send: (id: string, title: string, body: string) => Promise<SendOutcome>;
}

/** How the bridge paces itself; injectable for tests. */
export interface PushOptions {
  now?: () => number;
  /** At most one wake per recipient per this many ms. */
  wakeIntervalMs?: number;
  /** How long an unknown conversation id is remembered as unknown. */
  unknownTtlMs?: number;
  /** Entries each of the bridge's maps may hold. */
  maxTracked?: number;
}

const WAKE_INTERVAL_MS = Number(process.env.PUSH_WAKE_INTERVAL_MS) || 60_000;
const UNKNOWN_TTL_MS = 5 * 60_000;
const MAX_TRACKED = 100_000;

/**
 * A map of id → expiry, oldest first, that never holds more than `max`:
 * expired entries are swept from the front, and past the bound the oldest
 * live one goes too.
 */
class ExpiringSet {
  private readonly until = new Map<string, number>();
  constructor(private readonly max: number) {}

  has(key: string, now: number): boolean {
    const t = this.until.get(key);
    return t !== undefined && t > now;
  }

  add(key: string, until: number, now: number): void {
    this.until.delete(key);
    this.until.set(key, until);
    for (const [k, t] of this.until) {
      if (t > now && this.until.size <= this.max) break;
      this.until.delete(k);
    }
  }

  get size(): number {
    return this.until.size;
  }
}

/** The bridge's decision logic, separate from the MQTT client that feeds it. */
export function createPushBridge(deps: PushDeps, presence: Set<string> = new Set(), opts: PushOptions = {}) {
  const now = opts.now ?? Date.now;
  const wakeIntervalMs = opts.wakeIntervalMs ?? WAKE_INTERVAL_MS;
  const unknownTtlMs = opts.unknownTtlMs ?? UNKNOWN_TTL_MS;
  const maxTracked = opts.maxTracked ?? MAX_TRACKED;
  /** Recipients woken within the interval. */
  const recentlyWoken = new ExpiringSet(maxTracked);
  /** Conversation ids no friendship held when last asked. */
  const unknownConvos = new ExpiringSet(maxTracked);

  /** Wakes an offline recipient, at most once per interval. */
  async function wake(id: string): Promise<void> {
    if (presence.has(id)) return;
    const t = now();
    if (recentlyWoken.has(id, t)) return;
    recentlyWoken.add(id, t + wakeIntervalMs, t);
    report(id, await deps.send(id, "New message", "You have a new message"));
  }

  async function handleMessage(topic: string, payload: Buffer): Promise<void> {
    try {
      const pres = topic.match(/^u\/([0-9a-f]{64})\/presence$/);
      if (pres?.[1]) {
        if (payloadState(payload) === "online") presence.add(pres[1]);
        else presence.delete(pres[1]);
        return;
      }
      const inbox = topic.match(/^u\/([0-9a-f]{64})\/inbox$/);
      if (inbox?.[1]) return await wake(inbox[1]);
      const convo = topic.match(/^cv\/([0-9a-f]{64})$/);
      if (!convo?.[1]) return;
      if (unknownConvos.has(convo[1], now())) return;
      const members = await deps.getTopicMembers(convo[1]);
      if (members.length === 0) {
        unknownConvos.add(convo[1], now() + unknownTtlMs, now());
        sayOnce(`convo:${convo[1]}`, `[push] no friendship holds ${short(convo[1])}; nobody to wake`);
        return;
      }
      for (const id of members) await wake(id);
    } catch (e) {
      logger.error(`[push] handling ${topic}: ${(e as Error).message}`);
    }
  }
  return { handleMessage, presence, tracked: () => ({ woken: recentlyWoken.size, unknown: unknownConvos.size }) };
}

/** Presence unshared (every replica needs all of it), conversations and inboxes shared. */
export function pushSubscriptions(shareGroup: string = SHARE_GROUP): Array<{ topic: string; qos: 0 | 1 }> {
  return [
    { topic: "u/+/presence", qos: 0 },
    { topic: `$share/${shareGroup}/cv/+`, qos: 1 },
    { topic: `$share/${shareGroup}/u/+/inbox`, qos: 1 },
  ];
}

/** Connects to the broker's internal listener and starts waking offline members. */
export function startPushBridge(opts: { brokerUrl: string; username: string; secret: string }): {
  online: () => number;
} {
  const issue = keyProblem();
  if (issue && apnsIntended(process.env)) logger.error(`[push] ${issue}`);
  if (apnsGaps(process.env).length && apnsIntended(process.env)) {
    logger.error(`[push] ${apnsSummary(process.env)}; every wake will be dropped`);
  }

  const presence = new Set<string>();
  const bridge = createPushBridge(
    {
      getTopicMembers: (convoId) => DB.getTopicMembers(convoId),
      send: (id, title, body) => ApnsService.send(id, title, body),
    },
    presence,
  );

  const client = mqtt.connect(opts.brokerUrl, {
    clientId: `pushbridge-${Math.random().toString(16).slice(2, 10)}`,
    username: opts.username,
    password: opts.secret,
    clean: true,
    reconnectPeriod: 5000,
    keepalive: 30,
  });
  client.on("connect", () => {
    logger.startup(`[push] connected to EMQX at ${opts.brokerUrl}; ${apnsSummary(process.env)}`);
    for (const { topic, qos } of pushSubscriptions()) client.subscribe(topic, { qos });
  });
  client.on("error", (e) => logger.error(`[push] mqtt: ${e.message}`));
  client.on("reconnect", () => logger.warn("[push] reconnecting to EMQX"));
  client.on("message", (topic, payload) => void bridge.handleMessage(topic, payload));
  return { online: () => presence.size };
}

function short(id: string): string {
  return `${id.slice(0, 8)}…`;
}

/** Keys already said, oldest first; bounded, so a stream of new keys cannot grow it. */
const said = new Set<string>();
const SAID_MAX = 10_000;

function sayOnce(key: string, message: string): void {
  if (said.has(key)) return;
  said.add(key);
  if (said.size > SAID_MAX) said.delete(said.values().next().value as string);
  logger.warn(message);
}

/** Logs a wake outcome; configuration problems once globally, device problems once per device. */
function report(id: string, outcome: SendOutcome): void {
  switch (outcome) {
    case "sent":
      logger.debug(`[push] woke ${short(id)}`);
      return;
    case "no-token":
      logger.debug(`[push] ${short(id)} is offline and has no push token`);
      return;
    case "bad-key":
    case "no-config":
    case "no-topic-ios":
    case "no-topic-macos":
      sayOnce(outcome, `[push] waking nobody: ${outcome}. ${apnsSummary(process.env)}; see scripts/check-push.ts`);
      return;
    case "rejected":
    case "error":
      sayOnce(`${id}:${outcome}`, `[push] could not wake ${short(id)}: ${outcome}`);
      return;
  }
}

/** A presence payload's state; an empty (cleared) retained message is offline. */
function payloadState(payload: Buffer): "online" | "offline" {
  const raw = payload.toString("utf8").trim();
  if (!raw) return "offline";
  try {
    return JSON.parse(raw)?.s === "online" ? "online" : "offline";
  } catch {
    return raw === "online" ? "online" : "offline";
  }
}
