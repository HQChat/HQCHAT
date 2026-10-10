import * as crypto from "node:crypto";
import * as path from "node:path";
import koffi, { type IKoffiLib, load } from "koffi";
import type { Kem } from "./ratchet";

/** HQC-256 sizes, in bytes. */
export const HQC_CONSTANTS = {
  SEED_BYTES: 32,
  PUBLIC_KEY_BYTES: 7237,
  SECRET_KEY_BYTES: 7333,
  CIPHERTEXT_BYTES: 14421,
  SHARED_SECRET_BYTES: 32,
};

/**
 * Where the native HQC wrapper is loaded from: `HQC_LIB` (set by the Nix
 * package), else the `native/hqc/result` out-link of `nix build .#hqc`.
 */
function candidates(): string[] {
  if (process.env.HQC_LIB) return [process.env.HQC_LIB];
  const file = process.platform === "darwin" ? "libhqc_wrap.dylib" : "libhqc_wrap.so";
  return [path.join(__dirname, "..", "..", "..", "..", "native", "hqc", "result", "lib", file)];
}

let libraryPath = "";

/** The path of the native library that was loaded. */
export function loadedLibrary(): string {
  return libraryPath;
}

function loadLibrary(): IKoffiLib {
  const failures: string[] = [];
  for (const candidate of candidates()) {
    try {
      const lib = load(candidate);
      libraryPath = candidate;
      return lib;
    } catch (e) {
      failures.push(`${candidate}: ${(e as Error).message}`);
    }
  }
  throw new Error(`no HQC native library for ${process.platform}/${process.arch}:\n  ${failures.join("\n  ")}`);
}

const libHQC = loadLibrary();

const outU8 = koffi.out(koffi.pointer("uint8"));
const hqc_kem_keypair_wrap = libHQC.func("hqc_kem_keypair_wrap", "int", ["uint8*", outU8, outU8]);
const hqc_kem_enc_wrap = libHQC.func("hqc_kem_enc_wrap", "int", [outU8, outU8, "uint8*"]);
const hqc_kem_dec_wrap = libHQC.func("hqc_kem_dec_wrap", "int", [outU8, "uint8*", "uint8*"]);

/** HQC-256 KEM over the native wrapper. */
export const HqcWrapper = {
  /** Deterministic keypair from a 32-byte seed. */
  keypairFromSeed(seed: Buffer | Uint8Array | number[]): { pk: Buffer; sk: Buffer } {
    const seedBuf = Buffer.from(seed);
    if (seedBuf.length !== HQC_CONSTANTS.SEED_BYTES) {
      throw new Error(`Seed must be ${HQC_CONSTANTS.SEED_BYTES} bytes`);
    }
    const pk = Buffer.alloc(HQC_CONSTANTS.PUBLIC_KEY_BYTES);
    const sk = Buffer.alloc(HQC_CONSTANTS.SECRET_KEY_BYTES);
    const rc = hqc_kem_keypair_wrap(seedBuf, pk, sk);
    if (rc !== 0) throw new Error(`HQC keypair failed (rc=${rc})`);
    return { pk, sk };
  },

  /** A fresh ciphertext and 32-byte shared secret for `pk`. */
  encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer } {
    if (pk.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES) throw new Error("Invalid PK length");
    const ct = Buffer.alloc(HQC_CONSTANTS.CIPHERTEXT_BYTES);
    const ss = Buffer.alloc(HQC_CONSTANTS.SHARED_SECRET_BYTES);
    const rc = hqc_kem_enc_wrap(ct, ss, pk);
    if (rc !== 0) throw new Error(`HQC encapsulate failed (rc=${rc})`);
    return { ct, ss };
  },

  /**
   * The 32-byte shared secret for `ct`. Implicit rejection: a forged ciphertext
   * of the right length yields a pseudo-random secret, never an error.
   */
  decapsulate(sk: Buffer, ct: Buffer): Buffer {
    if (sk.length !== HQC_CONSTANTS.SECRET_KEY_BYTES) throw new Error("Invalid SK length");
    if (ct.length !== HQC_CONSTANTS.CIPHERTEXT_BYTES) throw new Error("Invalid Ciphertext length");
    const ss = Buffer.alloc(HQC_CONSTANTS.SHARED_SECRET_BYTES);
    const rc = hqc_kem_dec_wrap(ss, ct, sk);
    if (rc !== 0) throw new Error(`HQC decapsulate failed (rc=${rc})`);
    return ss;
  },
};

/** HQC-256 as the ratchet's KEM, with a fresh random keypair per step. */
export const hqcKem: Kem = {
  generateKeypair: () => HqcWrapper.keypairFromSeed(crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES)),
  encapsulate: (pk) => HqcWrapper.encapsulate(pk),
  decapsulate: (sk, ct) => HqcWrapper.decapsulate(sk, ct),
};
