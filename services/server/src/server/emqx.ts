/**
 * EMQX admin API (v5) client, authenticated with EMQX_API_KEY/EMQX_API_SECRET
 * against EMQX_API_URL. It makes revocation immediate (kick, unsubscribe)
 * and to nudge clients when their friend graph changes. Every call is best
 * effort: failures are logged and never fail the operation that triggered them.
 */

import { core } from "@hqchat/common/core";
import { logger } from "@hqchat/common/logger";

function credentials(): { key: string; secret: string } | null {
  const key = process.env.EMQX_API_KEY || "";
  const secret = process.env.EMQX_API_SECRET || "";
  return key && secret ? { key, secret } : null;
}

/** Whether an admin API credential is configured. */
export function emqxApiConfigured(): boolean {
  return credentials() !== null;
}

/** Calls `<EMQX_API_URL>/api/v5/<path>` with the API key; times out after 5 s. */
export async function emqxApi(method: string, path: string, body?: unknown): Promise<Response> {
  const creds = credentials();
  if (!creds) throw new Error("no EMQX API key configured");
  const base = process.env.EMQX_API_URL || "http://127.0.0.1:18083";
  return fetch(`${base}/api/v5/${path}`, {
    method,
    headers: {
      authorization: `Basic ${Buffer.from(`${creds.key}:${creds.secret}`).toString("base64")}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  });
}

export const EMQX = {
  /** Whether an admin credential is configured. */
  get enabled(): boolean {
    return emqxApiConfigured();
  },

  /**
   * Disconnects a client and drops its session (account deletion, revoked
   * keys). A 404 means it was not connected, which counts as success.
   */
  async kick(clientId: string): Promise<boolean> {
    if (!EMQX.enabled) return false;
    try {
      const res = await emqxApi("DELETE", `clients/${encodeURIComponent(clientId)}`);
      if (res.ok || res.status === 404) return true;
      logger.warn(`[emqx] kick ${clientId.slice(0, 12)}… → ${res.status}`);
      return false;
    } catch (e) {
      logger.error(`[emqx] kick failed for ${clientId.slice(0, 12)}…: ${(e as Error).message}`);
      return false;
    }
  },

  /**
   * Drops one live subscription, leaving the connection intact. A 404 counts
   * as success only for CLIENTID_NOT_FOUND; any other 404 is a failure.
   */
  async unsubscribe(clientId: string, topic: string): Promise<boolean> {
    if (!EMQX.enabled) return false;
    try {
      const res = await emqxApi("POST", `clients/${encodeURIComponent(clientId)}/unsubscribe`, { topic });
      if (res.ok) return true;
      if (res.status === 404) {
        const body = (await res.json().catch(() => null)) as { code?: string } | null;
        if (body?.code === "CLIENTID_NOT_FOUND") return true;
      }
      // The topic is a capability: log its kind, never its id.
      logger.warn(`[emqx] unsubscribe ${clientId.slice(0, 12)}… from ${topic.slice(0, 3)}… → ${res.status}`);
      return false;
    } catch (e) {
      logger.error(`[emqx] unsubscribe failed: ${(e as Error).message}`);
      return false;
    }
  },

  /** Both members of a friendship, off the shared topic. */
  async revokeTopic(pkA: string, pkB: string, topic: string): Promise<void> {
    await Promise.all([EMQX.unsubscribe(pkA, topic), EMQX.unsubscribe(pkB, topic)]);
  },

  /** Both members off an ended friendship's conversation and handshake topics. */
  async revokeFriendshipTopics(
    idA: string,
    idB: string,
    topics: { convoId: string; handshakeId: string },
  ): Promise<void> {
    await Promise.all([
      EMQX.revokeTopic(idA, idB, core.conversationTopic(topics.convoId)),
      EMQX.revokeTopic(idA, idB, core.handshakeTopic(topics.handshakeId)),
    ]);
  },

  /**
   * Publishes a content-free `{t:"graph"}` nudge on each owner-only
   * `u/<id>/graph` topic, so clients refetch `/friends` now instead of on
   * their next poll. Not retained: clients fetch the directory on connect.
   */
  async notifyGraphChanged(ids: string[]): Promise<void> {
    if (!EMQX.enabled) return;
    await Promise.all(
      ids.filter(Boolean).map(async (id) => {
        try {
          const res = await emqxApi("POST", "publish", {
            topic: `u/${id}/graph`,
            payload: JSON.stringify({ t: "graph" }),
            qos: 1,
            retain: false,
          });
          // 202: accepted with no subscriber (the client is offline).
          if (!res.ok && res.status !== 202) {
            logger.warn(`[emqx] graph nudge ${id.slice(0, 12)}… → ${res.status}`);
          }
        } catch (e) {
          logger.warn(`[emqx] graph nudge failed for ${id.slice(0, 12)}…: ${(e as Error).message}`);
        }
      }),
    );
  },
};
