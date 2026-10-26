import * as crypto from "node:crypto";
import type * as http from "node:http";
import { core } from "@hqchat/common/core";
import { logger } from "@hqchat/common/logger";
import { DB } from "./db/api";
import { EMQX } from "./emqx";
import { bearer, clientIp, HttpError, type JsonBody, readJson, send, textField } from "./http";
import { resolveTransportInfo } from "./transport-config";

/**
 * The auth service.
 *
 *   POST /auth/init        { pk, origin }                  → { ct, challenge }  KEM challenge to the public key
 *   POST /auth/verify      { pk, solution, mqttSigningKey, challenge? } → session and MQTT signing-key id
 *   POST /auth/refresh     (Bearer) { mqttSigningKey }     → a new MQTT signing-key id
 *   POST /auth/logout      (Bearer) { everywhere? }        → ends this session, or every session and MQTT key
 *   GET  /auth/transport                                   → the hqn/1 gateway, when enabled
 *   POST /mqtt/authn       EMQX hook: verifies a signed, single-use CONNECT proof
 *   POST /mqtt/authn/internal  EMQX hook for the internal listener (push bridge)
 */

const INIT_PER_IP_PER_MIN = Number(process.env.AUTH_INIT_IP_LIMIT || 20);
/** Inits for one key from one address. Per address, so a stranger cannot spend the owner's budget. */
const INIT_PER_PK_PER_MIN = Number(process.env.AUTH_INIT_PK_LIMIT || 6);
/** Inits for one key from every address together: an alert, never a refusal. */
const INIT_PER_PK_ALERT = Number(process.env.AUTH_INIT_PK_ALERT || 60);
const VERIFY_PER_IP_PER_MIN = Number(process.env.AUTH_VERIFY_IP_LIMIT || 30);
const VERIFY_FAILURE_ALERT = Number(process.env.AUTH_VERIFY_FAILURE_ALERT || 5);
/** The internal MQTT identity's username; the push bridge connects as it. */
export const INTERNAL_MQTT_USER = "svc-internal";
/** The deployment's helper bot; every new account is befriended to it. */
const BOT_ID = (process.env.BOT_ID || "").toLowerCase();

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/**
 * The origins a client may sign in at (`scheme://host[:port]`). The proof is
 * bound to the one it names, so a server that relays a client's sign-in here
 * gains nothing: its own origin is refused, and ours makes the client's proof
 * the wrong one. Outside production, unset means the request's own Host.
 */
function allowedOrigins(): string[] {
  return (process.env.AUTH_ORIGINS || "")
    .split(",")
    .map((o) => core.originOf(o.trim()))
    .filter((o): o is string => o !== null);
}

function originAllowed(origin: string | null, req: http.IncomingMessage): boolean {
  if (!origin) return false;
  const allowed = allowedOrigins();
  if (allowed.length) return allowed.includes(origin);
  if (process.env.NODE_ENV === "production") return false;
  const own = core.originOf(
    `${req.headers["x-forwarded-proto"] === "https" ? "https" : "http"}://${req.headers.host || ""}`,
  );
  return origin === own;
}

/**
 * A challenge to `pk` for a sign-in at `origin`, and the proof that answers
 * it, in the stored form (hex). The only place the proof is derived; the
 * shared secret stays inside the core.
 */
function newChallenge(pk: Buffer, origin: string): { ct: Buffer; proof: string } {
  const { ct, proof } = core.authChallenge(pk, origin);
  return { ct, proof: proof.toString("hex") };
}

/** The client's proof from the verify body (base64 on the wire), in the stored form. */
function presentedProof(body: JsonBody): string {
  return Buffer.from(textField(body, "solution"), "base64").toString("hex");
}

/** A short, stable stand-in for the caller's address, so challenge rows hold no address. */
function sourceOf(req: http.IncomingMessage): string {
  return crypto.createHash("sha256").update(clientIp(req)).digest("hex").slice(0, 16);
}

/**
 * Which of the open challenges `proof` answers, or null. With a challenge id
 * only that one is considered; without one (the current clients) every open
 * challenge is compared, each in constant time and with no early exit.
 */
function matchChallenge(
  open: Array<{ challengeId: string; proof: string }>,
  proof: string,
  challengeId: string,
): string | null {
  let match: string | null = null;
  for (const c of open) {
    if (challengeId && c.challengeId !== challengeId) continue;
    if (safeEqual(proof, c.proof) && match === null) match = c.challengeId;
  }
  return match;
}

async function befriendBot(id: string): Promise<void> {
  if (!BOT_ID || BOT_ID === id) return;
  try {
    await DB.createFriendship(id, BOT_ID);
    // As for an accepted invite: the bot greets now, not at its next poll.
    await EMQX.notifyGraphChanged([BOT_ID, id]);
  } catch (e) {
    logger.warn(`[auth] befriending the bot failed for ${id.slice(0, 12)}…: ${(e as Error).message}`);
  }
}

/** The client's per-session Ed25519 public key: raw 32 bytes, base64. */
function readSigningKey(body: JsonBody): Buffer {
  const encoded = textField(body, "mqttSigningKey");
  const raw = Buffer.from(encoded, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== encoded || !core.isSigningKey(raw)) {
    throw new HttpError(
      400,
      "INVALID_MQTT_SIGNING_KEY",
      "mqttSigningKey must be a raw 32-byte Ed25519 public key, base64",
    );
  }
  return raw;
}

async function signingKeyFields(id: string, signingKey: Buffer) {
  const { keyId, expiresAt } = await DB.registerMqttKey(id, signingKey);
  return { serverTime: Math.floor(Date.now() / 1000), mqttKeyId: keyId, mqttKeyExpiresAt: expiresAt };
}

async function handleInit(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const body = await readJson(req);
  const pkHex = textField(body, "pk").toLowerCase();
  if (!/^[0-9a-f]+$/.test(pkHex)) return send(res, 400, { error: "bad public key" });
  const origin = core.originOf(typeof body.origin === "string" ? body.origin : "");
  if (!originAllowed(origin, req)) return send(res, 400, { error: "BAD_ORIGIN" });
  const id = core.peerId(pkHex);
  const ip = clientIp(req);

  const [ipHits, pkHits, pkAll] = await Promise.all([
    DB.bumpCounter(`init:ip:${ip}`, 60),
    DB.bumpCounter(`init:pk:${id}:${sourceOf(req)}`, 60),
    DB.bumpCounter(`init:pk:${id}`, 60),
  ]);
  if (pkAll === INIT_PER_PK_ALERT) {
    logger.error(`[auth] ${pkAll} sign-in inits in 1m for one public key, from several addresses`);
  }
  if (ipHits > INIT_PER_IP_PER_MIN || pkHits > INIT_PER_PK_PER_MIN) {
    logger.warn(`[auth] init rate-limited (ip=${ipHits}, pk=${pkHits})`);
    return send(res, 429, { error: "RATE_LIMITED" });
  }

  if (pkHex.length !== core.HQC_PUBLIC_KEY_BYTES * 2) return send(res, 400, { error: "bad public key" });
  const { ct, proof } = newChallenge(Buffer.from(pkHex, "hex"), origin as string);
  const challenge = await DB.startAuthChallenge(id, sourceOf(req), proof);
  return send(res, 200, { ct: ct.toString("base64"), challenge });
}

async function handleVerify(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if ((await DB.bumpCounter(`verify:ip:${clientIp(req)}`, 60)) > VERIFY_PER_IP_PER_MIN) {
    return send(res, 429, { error: "RATE_LIMITED" });
  }
  const body = await readJson(req);
  const signingKey = readSigningKey(body);
  const pkHex = textField(body, "pk").toLowerCase();
  const id = core.peerId(pkHex);

  // A wrong proof spends nothing: only the challenge it answers is deleted.
  const matched = matchChallenge(await DB.openAuthChallenges(id), presentedProof(body), textField(body, "challenge"));
  if (!matched || !(await DB.spendAuthChallenge(id, matched))) {
    const failures = await DB.bumpCounter(`verify:fail:${id}`, 15 * 60);
    if (failures === VERIFY_FAILURE_ALERT) {
      // The alert carries nothing per key or address, so its throttle is global.
      logger.warn(`[auth] repeated failed proofs for one public key from ip=${clientIp(req)}`);
      logger.error(`[auth] ${failures} failed key-possession proofs in 15m for one public key`);
    }
    return send(res, 401, { error: "auth failed" });
  }
  await DB.clearCounter(`verify:fail:${id}`);

  // Checked only after the proof, so only the key's holder learns of a ban.
  if (await DB.isBanned(id)) return send(res, 403, { error: "BANNED" });
  await DB.ensureUser(id, pkHex);
  await befriendBot(id);

  return send(res, 200, {
    id,
    pk: pkHex,
    username: await DB.getUsername(id),
    sessionToken: await DB.mintSessionToken(id),
    ...(await signingKeyFields(id, signingKey)),
  });
}

/**
 * Verifies a CONNECT proof: shape, clientid binding, timestamp window, key,
 * signature, then the nonce, spent last so only a valid proof consumes one.
 */
async function verifyConnect(id: string, clientid: string, password: string): Promise<number | null> {
  const proof = core.parseConnectProof(password);
  if (!proof || clientid !== id) return null;
  if (!core.isFreshTimestamp(proof.ts, Math.floor(Date.now() / 1000))) return null;
  const key = await DB.getMqttSessionKey(id, proof.keyId);
  if (!key) return null;
  if (!core.verifyConnectProof(key.publicKey, clientid, proof)) return null;
  if (!(await DB.useNonce(`v1:${id}:${proof.nonce.toString("hex")}`, core.MQTT_PROOF_NONCE_TTL_SECONDS))) {
    logger.warn(`[auth] replayed CONNECT for ${id.slice(0, 12)}…`);
    return null;
  }
  return key.expireAt;
}

/**
 * Every route of the auth service, as a request listener. `internalMqttSecret`
 * is the password the internal listener's hook accepts for INTERNAL_MQTT_USER;
 * empty refuses everyone there.
 */
export function createAuthHandler(opts: { internalMqttSecret?: string } = {}): http.RequestListener {
  const internalSecret = opts.internalMqttSecret ?? process.env.INTERNAL_MQTT_SECRET ?? "";
  return async (req, res) => {
    const url = req.url || "";
    const method = req.method || "GET";
    try {
      if (method === "GET" && url === "/auth/transport") return send(res, 200, await resolveTransportInfo());
      if (method === "POST" && url === "/auth/init") return await handleInit(req, res);
      if (method === "POST" && url === "/auth/verify") return await handleVerify(req, res);

      if (method === "POST" && url === "/auth/refresh") {
        const session = await DB.resolveSessionToken(bearer(req));
        if (!session) return send(res, 401, { error: "unauthenticated" });
        return send(res, 200, await signingKeyFields(session.id, readSigningKey(await readJson(req))));
      }

      if (method === "POST" && url === "/auth/logout") {
        const token = bearer(req);
        const session = await DB.resolveSessionToken(token);
        if (!session) return send(res, 401, { error: "unauthenticated" });
        if ((await readJson(req)).everywhere === true) {
          await DB.revokeAllSessions(session.id);
          await EMQX.kick(session.id);
        } else {
          await DB.revokeSessionToken(token);
        }
        return send(res, 200, { ok: true });
      }

      if (method === "POST" && url === "/mqtt/authn/internal") {
        const body = await readJson(req);
        const ok =
          !!internalSecret &&
          textField(body, "username") === INTERNAL_MQTT_USER &&
          safeEqual(textField(body, "password"), internalSecret);
        return send(res, 200, ok ? { result: "allow", is_superuser: true } : { result: "deny" });
      }

      if (method === "POST" && url === "/mqtt/authn") {
        const body = await readJson(req);
        const id = textField(body, "username").toLowerCase();
        const password = textField(body, "password");
        const expireAt = id && password ? await verifyConnect(id, textField(body, "clientid"), password) : null;
        return send(res, 200, expireAt === null ? { result: "deny" } : { result: "allow", expire_at: expireAt });
      }

      return send(res, 404, { error: "not found" });
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.code, message: e.message });
      logger.error(`[auth] ${method} ${url}: ${(e as Error).message}`, e as Error);
      return send(res, 500, { error: "INTERNAL" });
    }
  };
}
