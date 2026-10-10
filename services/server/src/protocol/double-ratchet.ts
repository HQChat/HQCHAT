import * as crypto from "node:crypto";

/**
 * The KEM double ratchet's key schedule: pure derivations from shared secrets
 * to root, chain and message keys. The KEM calls live in `ratchet.ts`; these
 * functions are pinned byte-for-byte against the Swift implementation by
 * `double-ratchet-vectors.json`.
 *
 * A KEM step differs from a DH step in that the encapsulator chooses the
 * secret, so a stepping header carries the sender's fresh public key and a
 * ciphertext encapsulated to the key the peer last advertised:
 *
 *   sender:   (ct, ss) = Encap(peerRkPub);  (root', ck) = rootStep(root, ss)
 *             header = { rk: myNewRkPub, kemCt: ct }
 *   receiver: ss = Decap(myRkSec, ct);      (root', ck) = rootStep(root, ss)
 *             adopt peerRkPub = rk, and encapsulate to it on the next step
 */

const SALT = Buffer.from("salt", "utf8");

/** Cached skipped message keys, across all chains. Bounds memory and the walk. */
export const MAX_SKIPPED = 2000;

/**
 * Step policy, shared with Swift through `double-ratchet-policy.json`. A step
 * costs ~29 kB (public key + ciphertext), so a sending chain steps only after
 * it has been used and has either carried this many messages or lived this
 * long. These bounds are also the post-compromise-security window.
 */
export const RATCHET_MIN_STEP_INTERVAL_MS = 900_000;
export const RATCHET_MAX_MESSAGES_PER_CHAIN = 32;

function hkdf(ikm: Buffer, info: string): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, SALT, Buffer.from(info, "utf8"), 32));
}

export interface RootAndChain {
  root: Buffer;
  chain: Buffer;
}

/**
 * The initial root and the initiator's first sending chain. `ssId` is
 * encapsulated to the peer's pinned identity key and authenticates them;
 * `ssMt` and the optional `ssOt` (absent when the one-time pool is exhausted)
 * come from prekeys and provide forward secrecy.
 */
export function initRoot(ssId: Buffer, ssMt: Buffer, ssOt?: Buffer): RootAndChain {
  const ikm = Buffer.concat(ssOt ? [ssId, ssMt, ssOt] : [ssId, ssMt]);
  return {
    root: hkdf(ikm, "hqchat/v2/init/root"),
    chain: hkdf(ikm, "hqchat/v2/init/chain"),
  };
}

/** One asymmetric step: the next root and the chain key for the stepping direction. */
export function rootStep(root: Buffer, ss: Buffer): RootAndChain {
  const ikm = Buffer.concat([root, ss]);
  return {
    root: hkdf(ikm, "hqchat/v2/root"),
    chain: hkdf(ikm, "hqchat/v2/chain"),
  };
}

/** Message key at the current chain position. */
export function messageKey(ck: Buffer): Buffer {
  return hkdf(ck, "hqchat/v2/msg");
}

/** The next chain key. */
export function chainNext(ck: Buffer): Buffer {
  return hkdf(ck, "hqchat/v2/ck");
}

export interface ChainWalk {
  messageKey: Buffer;
  ck: Buffer;
  nextN: number;
  skipped: { n: number; key: Buffer }[];
}

/**
 * Walks a receiving chain from `fromN` to `targetN` inclusive, returning the
 * target's key, the advanced chain and the keys skipped on the way. Throws when
 * the gap exceeds MAX_SKIPPED, before doing any work: `targetN` comes from an
 * unauthenticated header.
 */
export function walkChain(ck: Buffer, fromN: number, targetN: number): ChainWalk {
  if (!Number.isInteger(targetN) || !Number.isInteger(fromN)) {
    throw new Error("walkChain: indices must be integers");
  }
  if (targetN < fromN) throw new Error("walkChain: targetN < fromN");
  if (targetN - fromN > MAX_SKIPPED) {
    throw new Error(`walkChain: gap ${targetN - fromN} exceeds MAX_SKIPPED (${MAX_SKIPPED})`);
  }
  const skipped: { n: number; key: Buffer }[] = [];
  let cur = ck;
  for (let i = fromN; i < targetN; i++) {
    skipped.push({ n: i, key: messageKey(cur) });
    cur = chainNext(cur);
  }
  return {
    messageKey: messageKey(cur),
    ck: chainNext(cur),
    nextN: targetN + 1,
    skipped,
  };
}

/** A 16-byte hex digest naming a ratchet public key, and so the chain it produced. */
export function chainId(rkPub: Buffer): string {
  return crypto.createHash("sha256").update(rkPub).digest("hex").slice(0, 32);
}
