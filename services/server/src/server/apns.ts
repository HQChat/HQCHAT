import * as crypto from "node:crypto";
import * as http2 from "node:http2";
import { logger } from "../common/logger";
import { apnsGaps, normalizeP8 } from "./apns-config";
import { DB } from "./db/api";

/** Why a push was or was not delivered. `no-config`, `no-topic-*` and `bad-key`
 *  are deployment errors; `no-token` is ordinary; `rejected`/`error` come from Apple. */
export type SendOutcome =
  | "sent"
  | "no-config"
  | "bad-key"
  | "no-token"
  | "no-topic-ios"
  | "no-topic-macos"
  | "rejected"
  | "error";

let cachedJwt: { token: string; iat: number } | null = null;
let cachedKey: crypto.KeyObject | null | undefined;

/** The APNs signing key, parsed once; null when the .p8 is not a usable P-256 key. */
function privateKey(): crypto.KeyObject | null {
  if (cachedKey !== undefined) return cachedKey;
  cachedKey = null;
  const pem = normalizeP8(process.env.APNS_KEY_P8);
  if (!pem) return cachedKey;
  try {
    const key = crypto.createPrivateKey(pem);
    if (key.asymmetricKeyType !== "ec") return cachedKey;
    cachedKey = key;
  } catch {
    // Not logged: OpenSSL's message can echo key material.
  }
  return cachedKey;
}

/** What is wrong with the configured .p8 (by shape, never content), or null. */
export function keyProblem(): string | null {
  if (!process.env.APNS_KEY_P8?.trim()) return "APNS_KEY_P8 is empty";
  if (!normalizeP8(process.env.APNS_KEY_P8)) {
    return (
      "APNS_KEY_P8 is not a PKCS#8 private key — Apple's .p8 starts " +
      "'-----BEGIN PRIVATE KEY-----'. An 'EC PRIVATE KEY' or 'RSA PRIVATE KEY' " +
      "header is the wrong container, and a truncated paste (one line of a " +
      "multi-line file) looks the same from here"
    );
  }
  if (!privateKey()) {
    return (
      "APNS_KEY_P8 is PEM-shaped but OpenSSL will not load it as an EC key — " +
      "the base64 body is corrupt or it is not the P-256 key ES256 needs"
    );
  }
  return null;
}

function getJwt(): string | null {
  const now = Math.floor(Date.now() / 1000);
  // Provider tokens are valid for an hour; refresh after 50 minutes.
  if (cachedJwt && now - cachedJwt.iat < 3000) return cachedJwt.token;

  const key = privateKey();
  if (!key) return null;

  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = { alg: "ES256", kid: process.env.APNS_KEY_ID };
  const payload = { iss: process.env.APNS_TEAM_ID, iat: now };
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const sig = crypto
    .sign("SHA256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
    .toString("base64url");

  const token = `${signingInput}.${sig}`;
  cachedJwt = { token, iat: now };
  return token;
}

/**
 * Token-based APNs sender over node:http2. Configured by APNS_KEY_ID,
 * APNS_TEAM_ID, APNS_KEY_P8 and APNS_TOPIC_IOS/APNS_TOPIC_MACOS; the APNs host
 * follows the environment the device registered with. Never throws.
 */
export const ApnsService = {
  enabled(): boolean {
    return !!(process.env.APNS_KEY_ID && process.env.APNS_TEAM_ID && process.env.APNS_KEY_P8);
  },

  /** Sends an alert push to the client's registered device and reports the outcome. */
  async send(id: string, title: string, body: string): Promise<SendOutcome> {
    try {
      if (!this.enabled()) return "no-config";
      const jwt = getJwt();
      if (!jwt) return "bad-key";
      const info = await DB.getPushToken(id);
      if (!info) return "no-token";

      const topic = info.platform === "macos" ? process.env.APNS_TOPIC_MACOS : process.env.APNS_TOPIC_IOS;
      if (!topic) return info.platform === "macos" ? "no-topic-macos" : "no-topic-ios";

      const host = info.environment === "production" ? "api.push.apple.com" : "api.sandbox.push.apple.com";
      const res = await sendToHost(host, info.token, topic, title, body, jwt);
      if (res.status !== 200) {
        logger.error(`[apns] ${res.status} ${res.data}`);
        return "rejected";
      }
      return "sent";
    } catch (e) {
      logger.error("[apns] send failed", e);
      return "error";
    }
  },

  /** What is missing or unusable before pushes can be sent; empty when ready. */
  gaps(): string[] {
    const gaps = apnsGaps(process.env);
    const problem = keyProblem();
    if (problem && !gaps.includes("APNS_KEY_P8")) gaps.push(problem);
    return gaps;
  },
};

/** POSTs one alert to an APNs host; resolves with the status and body, never rejects. */
function sendToHost(
  host: string,
  token: string,
  topic: string,
  title: string,
  body: string,
  jwt: string,
): Promise<{ status: number; data: string }> {
  return new Promise((resolve) => {
    const client = http2.connect(`https://${host}`);
    client.on("error", (e) => {
      logger.error("[apns] connection error", e);
      resolve({ status: 0, data: String(e) });
    });

    const payload = JSON.stringify({ aps: { alert: { title, body }, sound: "default" } });
    const req = client.request({
      ":method": "POST",
      ":path": `/3/device/${token}`,
      authorization: `bearer ${jwt}`,
      "apns-topic": topic,
      "apns-push-type": "alert",
      "content-type": "application/json",
    });

    let status = 0;
    let data = "";
    req.setEncoding("utf8");
    req.on("response", (h) => {
      status = Number(h[":status"]);
    });
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      client.close();
      resolve({ status, data });
    });
    req.on("error", (e) => {
      client.close();
      resolve({ status: 0, data: String(e) });
    });
    req.write(payload);
    req.end();
  });
}
