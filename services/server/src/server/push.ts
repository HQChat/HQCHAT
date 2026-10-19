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
 */

const SHARE_GROUP = process.env.PUSH_SHARE_GROUP || "pushbridge";

/** What the bridge needs from the database and APNs, injectable for tests. */
export interface PushDeps {
  getTopicMembers: (convoId: string) => Promise<string[]>;
  send: (id: string, title: string, body: string) => Promise<SendOutcome>;
}

/** The bridge's decision logic, separate from the MQTT client that feeds it. */
export function createPushBridge(deps: PushDeps, presence: Set<string> = new Set()) {
  async function handleMessage(topic: string, payload: Buffer): Promise<void> {
    try {
      const pres = topic.match(/^u\/([0-9a-f]{64})\/presence$/);
      if (pres?.[1]) {
        if (payloadState(payload) === "online") presence.add(pres[1]);
        else presence.delete(pres[1]);
        return;
      }
      const inbox = topic.match(/^u\/([0-9a-f]{64})\/inbox$/);
      if (inbox?.[1]) {
        if (!presence.has(inbox[1]))
          report(inbox[1], await deps.send(inbox[1], "New message", "You have a new message"));
        return;
      }
      const convo = topic.match(/^cv\/([0-9a-f]{64})$/);
      if (!convo?.[1]) return;
      const members = await deps.getTopicMembers(convo[1]);
      if (members.length === 0) {
        sayOnce(`convo:${convo[1]}`, `[push] no friendship holds ${short(convo[1])}; nobody to wake`);
        return;
      }
      for (const id of members) {
        if (!presence.has(id)) report(id, await deps.send(id, "New message", "You have a new message"));
      }
    } catch (e) {
      logger.error(`[push] handling ${topic}: ${(e as Error).message}`);
    }
  }
  return { handleMessage, presence };
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

const said = new Set<string>();

function sayOnce(key: string, message: string): void {
  if (said.has(key)) return;
  said.add(key);
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
