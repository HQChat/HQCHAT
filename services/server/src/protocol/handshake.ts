/**
 * Proof that an `init` came from the peer it names. An `init` is derived only
 * from the responder's public keys, so on its own it authenticates nobody to
 * the responder. The responder answers with a challenge: an HQC encapsulation
 * to the initiator's identity key. The initiator proves possession with
 *
 *     info  = "hqchat/handshake/v1" ‖ nonce(32) ‖ challenger(32) ‖ prover(32)
 *     proof = HKDF-SHA256(ikm = ss, salt = "salt", info, 32)
 *
 * The nonce gives freshness and the ordered ids bind the proof to one pair. The
 * exchange runs on the friendship's `hs/` topic, which only its two members
 * may use, and a prover answers only challenges for handshakes it started.
 */

import * as crypto from "node:crypto";

/** Bytes of freshness in a challenge. */
export const HANDSHAKE_NONCE_BYTES = 32;
/** Bytes of proof. */
export const HANDSHAKE_PROOF_BYTES = 32;

const INFO_PREFIX = Buffer.from("hqchat/handshake/v1", "utf8");
const SALT = Buffer.from("salt", "utf8");
const ID_BYTES = 32;

/** A fresh challenge nonce. */
export function handshakeNonce(): Buffer {
  return crypto.randomBytes(HANDSHAKE_NONCE_BYTES);
}

/**
 * The proof for one challenge. `challenger` and `prover` are 64-char hex
 * client ids, bound in that order so the roles cannot be swapped.
 */
export function handshakeProof(ss: Buffer, nonce: Buffer, challenger: string, prover: string): Buffer {
  if (nonce.length !== HANDSHAKE_NONCE_BYTES) {
    throw new Error(`handshakeProof: nonce must be ${HANDSHAKE_NONCE_BYTES} bytes`);
  }
  const challengerRaw = Buffer.from(challenger, "hex");
  const proverRaw = Buffer.from(prover, "hex");
  if (challengerRaw.length !== ID_BYTES || proverRaw.length !== ID_BYTES) {
    throw new Error("handshakeProof: ids must be 64 lowercase hex characters");
  }
  const info = Buffer.concat([INFO_PREFIX, nonce, challengerRaw, proverRaw]);
  return Buffer.from(crypto.hkdfSync("sha256", ss, SALT, info, HANDSHAKE_PROOF_BYTES));
}

/** Constant-time comparison of a returned proof with the expected one. */
export function handshakeProofMatches(expected: Buffer, offered: Buffer): boolean {
  if (offered.length !== expected.length) return false;
  return crypto.timingSafeEqual(expected, offered);
}

// Wire format (fixed offsets, integers big-endian):
//
//   0   magic   4 bytes  "HQCH"
//   4   version u8       1
//   5   kind    u8       0 = challenge, 1 = proof
//   6   from    32 bytes raw client id
//   38  to      32 bytes raw client id
//   70  nonce   32 bytes
//   [challenge] u32 len + HQC ciphertext, encapsulated to `to`'s identity key
//   [proof]     32 bytes

const HS_MAGIC = Buffer.from("HQCH", "ascii");
export const HANDSHAKE_VERSION = 1;
const KIND_CHALLENGE = 0;
const KIND_PROOF = 1;

const HS_OFF_VERSION = 4;
const HS_OFF_KIND = 5;
const HS_OFF_FROM = 6;
const HS_OFF_TO = 38;
const HS_OFF_NONCE = 70;
const HS_OFF_BODY = 102;

/** Upper bound on the challenge ciphertext length prefix. */
const HS_MAX_CT_BYTES = 1 << 20;

export type HandshakeKind = "chal" | "proof";

export interface HandshakeFrame {
  kind: HandshakeKind;
  /** Lowercase hex client ids. */
  from: string;
  to: string;
  nonce: Buffer;
  /** Challenge only: HQC ciphertext encapsulated to `to`'s identity key. */
  ct?: Buffer;
  /** Proof only. */
  proof?: Buffer;
}

export function encodeHandshake(f: HandshakeFrame): Buffer {
  const from = Buffer.from(f.from, "hex");
  const to = Buffer.from(f.to, "hex");
  if (from.length !== ID_BYTES || to.length !== ID_BYTES) {
    throw new Error("encodeHandshake: ids must be 64 lowercase hex characters");
  }
  if (f.nonce.length !== HANDSHAKE_NONCE_BYTES) {
    throw new Error("encodeHandshake: wrong nonce width");
  }
  const head = Buffer.alloc(HS_OFF_BODY);
  HS_MAGIC.copy(head, 0);
  head.writeUInt8(HANDSHAKE_VERSION, HS_OFF_VERSION);
  head.writeUInt8(f.kind === "chal" ? KIND_CHALLENGE : KIND_PROOF, HS_OFF_KIND);
  from.copy(head, HS_OFF_FROM);
  to.copy(head, HS_OFF_TO);
  f.nonce.copy(head, HS_OFF_NONCE);

  if (f.kind === "chal") {
    if (!f.ct || f.ct.length === 0) throw new Error("encodeHandshake: a challenge needs a ciphertext");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(f.ct.length, 0);
    return Buffer.concat([head, len, f.ct]);
  }
  if (!f.proof || f.proof.length !== HANDSHAKE_PROOF_BYTES) {
    throw new Error("encodeHandshake: a proof must be exactly 32 bytes");
  }
  return Buffer.concat([head, f.proof]);
}

/** Decode, or null. Never throws: this reads bytes off the network. */
export function decodeHandshake(raw: Buffer): HandshakeFrame | null {
  if (raw.length < HS_OFF_BODY) return null;
  if (!raw.subarray(0, 4).equals(HS_MAGIC)) return null;
  if (raw.readUInt8(HS_OFF_VERSION) !== HANDSHAKE_VERSION) return null;

  const kindByte = raw.readUInt8(HS_OFF_KIND);
  if (kindByte !== KIND_CHALLENGE && kindByte !== KIND_PROOF) return null;

  const from = raw.subarray(HS_OFF_FROM, HS_OFF_FROM + ID_BYTES).toString("hex");
  const to = raw.subarray(HS_OFF_TO, HS_OFF_TO + ID_BYTES).toString("hex");
  const nonce = Buffer.from(raw.subarray(HS_OFF_NONCE, HS_OFF_NONCE + HANDSHAKE_NONCE_BYTES));

  if (kindByte === KIND_CHALLENGE) {
    if (raw.length < HS_OFF_BODY + 4) return null;
    const len = raw.readUInt32BE(HS_OFF_BODY);
    if (len === 0 || len > HS_MAX_CT_BYTES) return null;
    if (raw.length !== HS_OFF_BODY + 4 + len) return null;
    return {
      kind: "chal",
      from,
      to,
      nonce,
      ct: Buffer.from(raw.subarray(HS_OFF_BODY + 4, HS_OFF_BODY + 4 + len)),
    };
  }
  if (raw.length !== HS_OFF_BODY + HANDSHAKE_PROOF_BYTES) return null;
  return {
    kind: "proof",
    from,
    to,
    nonce,
    proof: Buffer.from(raw.subarray(HS_OFF_BODY, HS_OFF_BODY + HANDSHAKE_PROOF_BYTES)),
  };
}
