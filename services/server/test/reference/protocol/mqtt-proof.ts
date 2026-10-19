import * as crypto from "node:crypto";

/**
 * The MQTT CONNECT password: an Ed25519 signature by a per-session key the
 * client registered over HTTPS at sign-in or refresh. The signed message is
 *
 *   "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16 raw bytes)
 *
 * and the password is
 *
 *   v1.<keyId: 32 hex>.<ts: unix seconds>.<nonce: 16 B base64url>.<sig: 64 B base64url>
 *
 * The server stores only public keys. A captured CONNECT is useless after its
 * single-use nonce or its ±60 s timestamp, and cannot be moved to another
 * client id. No field can contain 0x00, so the encoding is unambiguous.
 *
 * Mirrored by apps/apple/HQChat/Services/MQTTConnectProof.swift and pinned by
 * test/helpers/mqtt-proof-vectors.json.
 */

export const MQTT_PROOF_CONTEXT = "hqchat-mqtt-connect/1";

/** Allowed distance between a CONNECT timestamp and the server clock. Clients
 *  offset their clock by the `serverTime` returned at sign-in. */
export const MQTT_PROOF_SKEW_SECONDS = 60;

/** How long a spent nonce is remembered: the whole window in which its
 *  timestamp could still be accepted. */
export const MQTT_PROOF_NONCE_TTL_SECONDS = 2 * MQTT_PROOF_SKEW_SECONDS;

export interface ParsedProof {
  keyId: string;
  ts: number;
  nonce: Buffer;
  sig: Buffer;
}

const PASSWORD_RE = /^v1\.([0-9a-f]{32})\.(0|[1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$/;

/** Strict parse; anything not exactly the v1 shape is null. */
export function parseProofPassword(password: string): ParsedProof | null {
  const m = PASSWORD_RE.exec(password);
  if (!m) return null;
  const [, keyId, ts, nonceText, sigText] = m;
  if (!keyId || !ts || !nonceText || !sigText) return null;
  const nonce = Buffer.from(nonceText, "base64url");
  const sig = Buffer.from(sigText, "base64url");
  // Only the canonical base64url spelling is accepted, so a proof has one password.
  if (nonce.length !== 16 || sig.length !== 64) return null;
  if (nonce.toString("base64url") !== nonceText || sig.toString("base64url") !== sigText) return null;
  return { keyId, ts: Number(ts), nonce, sig };
}

export function formatProofPassword(p: ParsedProof): string {
  return `v1.${p.keyId}.${p.ts}.${p.nonce.toString("base64url")}.${p.sig.toString("base64url")}`;
}

/** The exact bytes that are signed. */
export function proofMessage(clientid: string, keyId: string, ts: number, nonce: Buffer): Buffer {
  const sep = Buffer.from([0]);
  return Buffer.concat([
    Buffer.from(MQTT_PROOF_CONTEXT, "utf8"),
    sep,
    Buffer.from(clientid, "utf8"),
    sep,
    Buffer.from(keyId, "utf8"),
    sep,
    Buffer.from(String(ts), "utf8"),
    sep,
    nonce,
  ]);
}

/** Whether `ts` (unix seconds) is inside the accepted window around `nowSec`. */
export function isFreshTimestamp(ts: number, nowSec: number): boolean {
  return Number.isSafeInteger(ts) && Math.abs(nowSec - ts) <= MQTT_PROOF_SKEW_SECONDS;
}

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** A raw 32-byte Ed25519 public key as a KeyObject, or null if it is not one. */
export function ed25519PublicKey(raw: Buffer): crypto.KeyObject | null {
  if (raw.length !== 32) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
  } catch {
    return null;
  }
}

/** Verify a signature against a raw public key. Never throws. */
export function verifyProofSignature(publicKeyRaw: Buffer, message: Buffer, sig: Buffer): boolean {
  const key = ed25519PublicKey(publicKeyRaw);
  if (!key || sig.length !== 64) return false;
  try {
    return crypto.verify(null, message, key, sig);
  } catch {
    return false;
  }
}

/** A client's per-session CONNECT signing key. */
export interface SigningKey {
  privateKey: crypto.KeyObject;
  /** Raw 32-byte public key, base64 — the `mqttSigningKey` field. */
  publicKeyB64: string;
}

/** A fresh signing key; register `publicKeyB64` as `mqttSigningKey`. */
export function newSigningKey(): SigningKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { privateKey, publicKeyB64: spki.subarray(spki.length - 32).toString("base64") };
}

/** A fresh v1 password: new nonce every call. `nowSec` must be SERVER time. */
export function signConnect(o: {
  clientid: string;
  keyId: string;
  privateKey: crypto.KeyObject;
  nowSec: number;
}): string {
  const ts = Math.floor(o.nowSec);
  const nonce = crypto.randomBytes(16);
  const sig = crypto.sign(null, proofMessage(o.clientid, o.keyId, ts, nonce), o.privateKey);
  return formatProofPassword({ keyId: o.keyId, ts, nonce, sig });
}
