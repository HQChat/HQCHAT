import * as crypto from "node:crypto";
import { core, corePath } from "../../../src/common/core";
import type { Kem } from "./ratchet";

/** HQC-256 sizes, in bytes. */
export const HQC_CONSTANTS = {
  SEED_BYTES: 32,
  PUBLIC_KEY_BYTES: 7237,
  SECRET_KEY_BYTES: 7333,
  CIPHERTEXT_BYTES: 14421,
  SHARED_SECRET_BYTES: 32,
};

/** The library HQC runs in: the core's addon, which compiles the pinned C reference. */
export function loadedLibrary(): string {
  return corePath();
}

/** HQC-256 KEM over the core (the same C reference every client runs). */
export const HqcWrapper = {
  /** Deterministic keypair from a 32-byte seed. */
  keypairFromSeed(seed: Buffer | Uint8Array | number[]): { pk: Buffer; sk: Buffer } {
    const seedBuf = Buffer.from(seed);
    if (seedBuf.length !== HQC_CONSTANTS.SEED_BYTES) {
      throw new Error(`Seed must be ${HQC_CONSTANTS.SEED_BYTES} bytes`);
    }
    return core.hqcKeypairFromSeed(seedBuf);
  },

  /** A fresh ciphertext and 32-byte shared secret for `pk`. */
  encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer } {
    if (pk.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES) throw new Error("Invalid PK length");
    return core.hqcEncapsulate(pk);
  },

  /**
   * The 32-byte shared secret for `ct`. Implicit rejection: a forged ciphertext
   * of the right length yields a pseudo-random secret, never an error.
   */
  decapsulate(sk: Buffer, ct: Buffer): Buffer {
    if (sk.length !== HQC_CONSTANTS.SECRET_KEY_BYTES) throw new Error("Invalid SK length");
    if (ct.length !== HQC_CONSTANTS.CIPHERTEXT_BYTES) throw new Error("Invalid Ciphertext length");
    return core.hqcDecapsulate(sk, ct);
  },
};

/** HQC-256 as the ratchet's KEM, with a fresh random keypair per step. */
export const hqcKem: Kem = {
  generateKeypair: () => HqcWrapper.keypairFromSeed(crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES)),
  encapsulate: (pk) => HqcWrapper.encapsulate(pk),
  decapsulate: (sk, ct) => HqcWrapper.decapsulate(sk, ct),
};
