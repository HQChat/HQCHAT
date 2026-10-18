import * as crypto from "node:crypto";
import { HQC_CONSTANTS, HqcWrapper } from "../protocol/hqc";
import { peerId } from "../protocol/identity";

/** A client's long-term HQC identity and the id it is known by. */
export interface Identity {
  pk: Buffer;
  sk: Buffer;
  pkHex: string;
  id: string;
}

/** The identity a 32-byte seed derives. */
export function identityFromSeed(seed: Buffer): Identity {
  const { pk, sk } = HqcWrapper.keypairFromSeed(seed);
  const pkHex = pk.toString("hex");
  return { pk, sk, pkHex, id: peerId(pkHex) };
}

/** A fresh random seed. */
export function newSeed(): Buffer {
  return crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
}
