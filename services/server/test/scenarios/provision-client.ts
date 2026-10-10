/**
 * Signs up a test client and prints what a non-TypeScript client needs to
 * connect as it: its id, a registered Ed25519 signing key (raw private half),
 * the server clock and the hqn/1 gateway. Used by apps/apple/e2e/hqn-live.
 *
 *   TEST_BASE_URL=… TEST_MQTT_URL=… npx tsx test/scenarios/provision-client.ts
 */

import * as crypto from "node:crypto";
import { Client, identityFromSeed, newSeed } from "../../src/client";
import { requestJson } from "../../src/client/http";
import { newSigningKey } from "../../src/protocol/mqtt-proof";
import { BASE_URL, MQTT_URL } from "./stack";

async function main(): Promise<void> {
  const c = new Client({ baseUrl: BASE_URL, endpoint: { url: MQTT_URL }, identity: identityFromSeed(newSeed()) });
  await c.signIn();
  await c.api.setUsername(`swift_${crypto.randomBytes(3).toString("hex")}`);
  const key = newSigningKey();
  const grant = await requestJson<{ mqttKeyId: string; serverTime: number }>(`${BASE_URL}/auth/refresh`, {
    method: "POST",
    bearer: c.auth.bearer,
    body: { mqttSigningKey: key.publicKeyB64 },
  });
  const pkcs8 = key.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const { hqn } = await c.api.transport();
  process.stdout.write(
    `${JSON.stringify({
      id: c.id,
      keyId: grant.mqttKeyId,
      signingSeedHex: pkcs8.subarray(pkcs8.length - 32).toString("hex"),
      serverTime: grant.serverTime,
      gateway: hqn && { host: process.env.TEST_HQN_HOST || hqn.host, port: hqn.port, keys: hqn.keys },
      wss: MQTT_URL,
    })}\n`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
