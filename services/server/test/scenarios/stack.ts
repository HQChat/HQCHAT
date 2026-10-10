/**
 * The stack under test and the accounts the scenarios create. Point it at any
 * deployment:
 *
 *   TEST_BASE_URL       the server's origin                 (http://127.0.0.1:8090)
 *   TEST_MQTT_URL       the broker's WebSocket endpoint      (ws://127.0.0.1:8083/mqtt)
 *   TEST_BOT_USERNAME   the helper bot's handle              (helper)
 *   SCENARIOS_REQUIRED  "1" to fail, rather than skip, when the stack is unreachable
 *
 * Every account a scenario signs up is deleted when the file's tests finish.
 */

import * as crypto from "node:crypto";
import { after, type TestContext } from "node:test";
import { ApiError, Client, type Endpoint, identityFromSeed, newSeed } from "../../src/client";

export const BASE_URL = (process.env.TEST_BASE_URL || "http://127.0.0.1:8090").replace(/\/$/, "");
export const MQTT_URL = process.env.TEST_MQTT_URL || "ws://127.0.0.1:8083/mqtt";
export const BOT_USERNAME = process.env.TEST_BOT_USERNAME || "helper";

const created: Client[] = [];

after(async () => {
  for (const c of created) {
    await c.close().catch(() => {});
    await c.api.deleteAccount().catch(() => {});
  }
});

let reachable: Promise<boolean> | null = null;

/** True when the stack answers; otherwise skips the test, or fails it under SCENARIOS_REQUIRED=1. */
export async function stackUp(t: TestContext): Promise<boolean> {
  reachable ??= fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(5000) })
    .then((r) => r.ok)
    .catch(() => false);
  if (await reachable) return true;
  if (process.env.SCENARIOS_REQUIRED === "1") throw new Error(`no server answers at ${BASE_URL}/health`);
  t.skip(`no stack at ${BASE_URL}`);
  return false;
}

export const tag = () => crypto.randomBytes(4).toString("hex");

/** A new client with a fresh identity, deleted after the file's tests. */
export function newClient(endpoint: Endpoint = { url: MQTT_URL }): Client {
  const c = new Client({ baseUrl: BASE_URL, endpoint, identity: identityFromSeed(newSeed()) });
  created.push(c);
  return c;
}

/** Signs in, waiting out the server's per-address sign-in limit when a run hits it. */
export async function signIn(client: Client): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await client.signIn();
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 429) || attempt >= 12) throw e;
      await pause(10_000);
    }
  }
}

/** A signed-in client with a username. */
export async function signedUp(prefix = "sc"): Promise<{ client: Client; username: string }> {
  const client = newClient();
  const username = `${prefix}_${tag()}`;
  await signIn(client);
  await client.api.setUsername(username);
  return { client, username };
}

/** Two connected friends with prekeys published and each other's topics subscribed. */
export async function friends(): Promise<{ a: Client; b: Client }> {
  const [{ client: a }, { client: b, username }] = await Promise.all([signedUp("sa"), signedUp("sb")]);
  await a.api.invite(username);
  await b.api.accept(a.id);
  await Promise.all([a.sync(), b.sync()]);
  await Promise.all([a.connect(), b.connect()]);
  return { a, b };
}

/** Waits `ms` milliseconds. */
export const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
