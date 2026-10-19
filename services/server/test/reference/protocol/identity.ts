import * as crypto from "node:crypto";

/**
 * Client identifiers: `id = sha256(lowercase hex of the HQC public key)`, 64
 * lowercase hex characters. Everything that names a client (MQTT client id,
 * topics, the friend graph, routes) uses the id; the 7237-byte key is kept only
 * where key material is needed.
 *
 * An id is a commitment to its key: `keyMatchesId` proves a received key is the
 * one an id names. An id is a name, never an authenticator: anyone holding the
 * public key can compute it.
 */

/** Length of an id in hex characters. */
export const PEER_ID_LENGTH = 64;

/** Matches an id exactly: 64 lowercase hex characters. */
export const PEER_ID_RE = /^[0-9a-f]{64}$/;

/** The id of a public key, given as hex in either case. */
export function peerId(publicKeyHex: string): string {
  return crypto.createHash("sha256").update(publicKeyHex.toLowerCase(), "utf8").digest("hex");
}

/** Whether `value` has the shape of an id. */
export function isPeerId(value: unknown): value is string {
  return typeof value === "string" && PEER_ID_RE.test(value);
}

/** Whether `publicKeyHex` is the key `id` names. A key that fails must be refused, never pinned. */
export function keyMatchesId(publicKeyHex: string, id: string): boolean {
  return peerId(publicKeyHex) === id.toLowerCase();
}
