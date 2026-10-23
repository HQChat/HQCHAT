import * as crypto from "node:crypto";

/**
 * AES-256-GCM for message payloads, laid out `[IV 12][tag 16][ciphertext]` as
 * in the Swift AESService. The frame header is always bound as AAD, and a tag
 * shorter than 16 bytes is refused rather than verified.
 */

const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Encrypts `plaintext` under `key`, binding `aad`. */
export function sealPayload(plaintext: string, key: Buffer, aad: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

/** Decrypts a sealed payload; throws when it does not authenticate. */
export function openPayload(data: Buffer, key: Buffer, aad: Buffer, padded = false): string {
  if (data.length < IV_BYTES + TAG_BYTES) throw new Error("payload shorter than IV and tag");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, data.subarray(0, IV_BYTES), {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(data.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
  const plain = Buffer.concat([decipher.update(data.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]);
  return (padded ? unpad(plain) : plain).toString("utf8");
}

/** Undoes the core's padding (ISO/IEC 7816-4 to 256-byte classes); throws on anything it could not produce. */
export function unpad(p: Buffer): Buffer {
  let end = p.length - 1;
  while (end >= 0 && p[end] === 0) end--;
  if (p.length === 0 || p.length % 256 !== 0 || end < 0 || p[end] !== 0x80 || p.length - end > 256) {
    throw new Error("bad padding");
  }
  return p.subarray(0, end);
}
