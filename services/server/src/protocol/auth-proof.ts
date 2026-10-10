import * as crypto from "node:crypto";

/**
 * Proof of key possession for sign-in: HKDF(ss, "auth") of the shared secret
 * the client decapsulates from the server's challenge. The secret itself is
 * never sent, so the exchange is not a decryption oracle.
 */
export function authProof(ss: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", ss, Buffer.from("salt", "utf8"), Buffer.from("auth", "utf8"), 32));
}
