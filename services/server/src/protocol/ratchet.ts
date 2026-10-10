import {
  chainId,
  chainNext,
  initRoot,
  MAX_SKIPPED,
  messageKey,
  RATCHET_MAX_MESSAGES_PER_CHAIN,
  RATCHET_MIN_STEP_INTERVAL_MS,
  rootStep,
  walkChain,
} from "./double-ratchet";

/**
 * The double-ratchet state machine over an injected KEM (HQC in production, a
 * stub in tests). The initiator claims the responder's prekeys and sends
 * `init`; the responder takes the first real step when it replies; after that
 * the roles are symmetric. Peer authentication comes from the caller pinning
 * the identity key `ssId` is encapsulated to.
 */

/** The KEM this ratchet rides on. HQC in production, a stub in tests. */
export interface Kem {
  generateKeypair(): { pk: Buffer; sk: Buffer };
  encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer };
  decapsulate(sk: Buffer, ct: Buffer): Buffer;
}

/** One direction's symmetric chain. */
export interface Chain {
  ck: Buffer;
  /** Next index this chain will produce or expect. */
  n: number;
}

export interface SkippedKey {
  /** `chainId` of the ratchet key whose chain produced it. */
  chain: string;
  n: number;
  key: Buffer;
}

export interface SessionState {
  root: Buffer;
  /** My ratchet keypair. Peers encapsulate to `rkPub`; `rkSec` opens their step. */
  rkPub: Buffer;
  rkSec: Buffer;
  /** The peer's advertised ratchet key. Null until the initiator hears back. */
  peerRkPub: Buffer | null;
  send: Chain | null;
  recv: Chain | null;
  /** Length of the previous sending chain — the `pn` header field. */
  prevSendN: number;
  skipped: SkippedKey[];
  /**
   * The handshake header, repeated on every outbound frame until the first
   * successful `open`, so a failed or retried first send still reaches a peer
   * that has never seen the session.
   */
  pendingInit?: InitHeader;
  /**
   * Chains already stepped into, newest last. A replayed stepping frame still
   * decapsulates, so without this it would re-derive the root and desync both
   * sides.
   */
  seenChains: string[];
  /** Messages sent on the current sending chain, for the step policy. */
  sentOnChain: number;
  /** When the current sending chain started, for the step policy. */
  chainStartedAt: number;
}

/** The per-message header. Every field is bound as AEAD additional data. */
export interface MessageHeader {
  /**
   * `chainId` of the sender's current ratchet key, on every message, so `n` is
   * always read against the chain that produced it.
   */
  cid: string;
  /** Present only on a step: the sender's new ratchet public key. */
  rk?: Buffer;
  /** Present only on a step: encapsulated to the receiver's previous `rk`. */
  kemCt?: Buffer;
  n: number;
  pn: number;
}

/** What an `init` frame carries besides the message header. Mirrors Swift's `RatchetInitHeader`. */
export interface InitHeader {
  ctId: Buffer;
  ctMt: Buffer;
  ctOt: Buffer | null;
  otId: number | null;
  rk: Buffer;
  /** `chainId(rk)`, so an init frame carries the same chain selector as a msg. */
  cid: string;
}

/** The peer's published bundle, as claimed from the directory. */
export interface PrekeyBundle {
  identityPk: Buffer;
  mediumPk: Buffer;
  /** Null when the peer's one-time pool was exhausted. */
  oneTimePk: Buffer | null;
  oneTimeId: number | null;
}

/** My own prekey secrets, needed to answer an `init`. */
export interface PrekeySecrets {
  identitySk: Buffer;
  mediumSk: Buffer;
  /** Looked up by the `otId` the initiator echoed back. */
  oneTimeSk(id: number): Buffer | null;
}

/**
 * Initiator side: derives `root_0` from the peer's bundle and opens a sending
 * chain, so the first message can be sent while the peer is offline.
 */
export function startAsInitiator(
  kem: Kem,
  bundle: PrekeyBundle,
  now = Date.now(),
): {
  state: SessionState;
  header: InitHeader;
} {
  const id = kem.encapsulate(bundle.identityPk);
  const mt = kem.encapsulate(bundle.mediumPk);
  const ot = bundle.oneTimePk ? kem.encapsulate(bundle.oneTimePk) : null;

  const { root, chain } = initRoot(id.ss, mt.ss, ot?.ss);
  const mine = kem.generateKeypair();
  const header: InitHeader = {
    ctId: id.ct,
    ctMt: mt.ct,
    ctOt: ot?.ct ?? null,
    otId: bundle.oneTimeId,
    rk: mine.pk,
    cid: chainId(mine.pk),
  };

  return {
    state: {
      root,
      rkPub: mine.pk,
      rkSec: mine.sk,
      peerRkPub: null,
      send: { ck: chain, n: 0 },
      recv: null,
      prevSendN: 0,
      skipped: [],
      seenChains: [],
      pendingInit: header,
      sentOnChain: 0,
      chainStartedAt: now,
    },
    header,
  };
}

/**
 * Responder side: rebuilds the root from an `init` and opens the matching
 * receiving chain. Null when a ciphertext does not decapsulate or the one-time
 * secret is gone; callers must keep any existing session in that case, so a
 * replayed `init` cannot reset a conversation.
 */
export function startAsResponder(
  kem: Kem,
  secrets: PrekeySecrets,
  header: InitHeader,
  now = Date.now(),
): SessionState | null {
  try {
    const ssId = kem.decapsulate(secrets.identitySk, header.ctId);
    const ssMt = kem.decapsulate(secrets.mediumSk, header.ctMt);

    let ssOt: Buffer | undefined;
    if (header.ctOt) {
      if (header.otId === null) return null;
      const sk = secrets.oneTimeSk(header.otId);
      if (!sk) return null;
      ssOt = kem.decapsulate(sk, header.ctOt);
    }

    const { root, chain } = initRoot(ssId, ssMt, ssOt);
    const mine = kem.generateKeypair();

    return {
      root,
      rkPub: mine.pk,
      rkSec: mine.sk,
      peerRkPub: header.rk,
      send: null,
      recv: { ck: chain, n: 0 },
      prevSendN: 0,
      skipped: [],
      seenChains: [chainId(header.rk)],
      sentOnChain: 0,
      chainStartedAt: now,
    };
  } catch {
    return null;
  }
}

/**
 * Whether the next send steps: always when there is no sending chain yet,
 * never before the peer has advertised a key or on an unused chain, otherwise
 * per the RATCHET_* policy.
 */
export function shouldStep(state: SessionState, now = Date.now()): boolean {
  if (!state.peerRkPub) return false;
  if (!state.send) return true;
  if (state.sentOnChain === 0) return false;
  if (state.sentOnChain >= RATCHET_MAX_MESSAGES_PER_CHAIN) return true;
  return now - state.chainStartedAt >= RATCHET_MIN_STEP_INTERVAL_MS;
}

/**
 * Takes the next sending key, stepping first when `shouldStep` says so.
 * Mutates `state`; the header must be bound as the payload's AAD.
 */
export function seal(
  kem: Kem,
  state: SessionState,
  now = Date.now(),
): {
  key: Buffer;
  header: MessageHeader;
  /** Present until the peer answers; see `SessionState.pendingInit`. */
  initHeader?: InitHeader;
} {
  let stepped: { rk: Buffer; kemCt: Buffer } | undefined;

  if (shouldStep(state, now)) {
    const peerRk = state.peerRkPub!;
    const { ct, ss } = kem.encapsulate(peerRk);
    const next = rootStep(state.root, ss);

    const mine = kem.generateKeypair();
    state.root = next.root;
    state.prevSendN = state.send?.n ?? 0;
    state.send = { ck: next.chain, n: 0 };
    state.rkPub = mine.pk;
    state.rkSec = mine.sk;
    state.sentOnChain = 0;
    state.chainStartedAt = now;
    stepped = { rk: mine.pk, kemCt: ct };
  }

  if (!state.send) {
    throw new Error("seal: no sending chain and no peer ratchet key to step against");
  }

  const key = messageKey(state.send.ck);
  const header: MessageHeader = {
    cid: chainId(state.rkPub),
    n: state.send.n,
    pn: state.prevSendN,
    ...(stepped ?? {}),
  };
  state.send.ck = chainNext(state.send.ck);
  state.send.n += 1;
  state.sentOnChain += 1;
  return { key, header, ...(state.pendingInit ? { initHeader: state.pendingInit } : {}) };
}

/** Index of a cached key, or -1. Removal waits until the payload authenticates. */
function findSkipped(state: SessionState, chain: string, n: number): number {
  return state.skipped.findIndex((s) => s.chain === chain && s.n === n);
}

/**
 * Retired chains remembered for replay rejection. Older replays fail to
 * decapsulate because our ratchet secret rotates on every step we send.
 */
const MAX_SEEN_CHAINS = 64;

function rememberChain(state: SessionState, cid: string) {
  state.seenChains.push(cid);
  if (state.seenChains.length > MAX_SEEN_CHAINS) {
    state.seenChains.splice(0, state.seenChains.length - MAX_SEEN_CHAINS);
  }
}

/** Caches skipped keys, evicting the oldest beyond MAX_SKIPPED. The array shape is persisted. */
function cacheSkipped(state: SessionState, chain: string, keys: { n: number; key: Buffer }[]) {
  for (const k of keys) state.skipped.push({ chain, n: k.n, key: k.key });
  if (state.skipped.length > MAX_SKIPPED) {
    state.skipped.splice(0, state.skipped.length - MAX_SKIPPED);
  }
}

/** A receiving chain step computed from a header, not yet committed to the session. */
interface PendingStep {
  root: Buffer;
  peerRkPub: Buffer;
  recv: { ck: Buffer; n: number };
  /** The chain entered, to remember once committed. */
  enteredCid: string;
  /** Keys left on the retiring chain (up to `pn`), cached only once committed. */
  tail: { cid: string; keys: { n: number; key: Buffer }[] } | null;
}

/** A message key cached for a skipped position, consumed only if it verifies. */
function openSkipped(state: SessionState, header: MessageHeader, verify: (key: Buffer) => boolean): Buffer | null {
  const idx = findSkipped(state, header.cid, header.n);
  if (idx === -1) return null;
  const key = state.skipped[idx]!.key;
  if (!verify(key)) return null;
  state.skipped.splice(idx, 1);
  return key;
}

/**
 * The step a header asks for into a new chain, or null unless it is a
 * well-formed step to an unseen chain whose ciphertext decapsulates.
 */
function computeStep(
  kem: Kem,
  state: SessionState,
  header: MessageHeader,
  currentCid: string | null,
): PendingStep | null {
  if (!header.rk || !header.kemCt) return null;
  if (chainId(header.rk) !== header.cid) return null;
  if (state.seenChains.includes(header.cid)) return null;

  let ss: Buffer;
  try {
    ss = kem.decapsulate(state.rkSec, header.kemCt);
  } catch {
    return null;
  }

  // `pn` is attacker-chosen and caching evicts, so the tail is only computed here.
  let tail: PendingStep["tail"] = null;
  const recv = state.recv;
  if (recv && currentCid) {
    const remaining = header.pn - recv.n;
    if (remaining > 0 && remaining <= MAX_SKIPPED) {
      const walked = walkChain(recv.ck, recv.n, header.pn - 1);
      tail = { cid: currentCid, keys: [...walked.skipped, { n: header.pn - 1, key: walked.messageKey }] };
    }
  }

  const next = rootStep(state.root, ss);
  return {
    root: next.root,
    peerRkPub: header.rk,
    recv: { ck: next.chain, n: 0 },
    enteredCid: header.cid,
    tail,
  };
}

/**
 * The message key for an inbound header, or null (replay, retired chain, gap
 * too large, or a payload that does not authenticate; none is an error).
 *
 * `verify` is the AEAD open and the only authenticator: HQC uses implicit
 * rejection, so a forged step decapsulates to a pseudo-random secret without
 * error. Everything is therefore computed into locals and `state` is written
 * only after `verify` passes.
 */
export function open(
  kem: Kem,
  state: SessionState,
  header: MessageHeader,
  verify: (key: Buffer) => boolean,
): Buffer | null {
  if (!Number.isInteger(header.n) || header.n < 0) return null;
  if (!Number.isInteger(header.pn) || header.pn < 0) return null;
  if (typeof header.cid !== "string" || !/^[0-9a-f]{32}$/.test(header.cid)) return null;

  // Skipped keys first, so a late message resolves without touching live state.
  if (findSkipped(state, header.cid, header.n) !== -1) return openSkipped(state, header, verify);

  const currentCid = state.peerRkPub ? chainId(state.peerRkPub) : null;
  const step = header.cid === currentCid ? null : computeStep(kem, state, header, currentCid);
  if (header.cid !== currentCid && !step) return null;

  const recv = step ? step.recv : state.recv;
  if (!recv || header.n < recv.n) return null;

  let walk: ChainWalkResult;
  try {
    walk = walkChain(recv.ck, recv.n, header.n);
  } catch {
    return null;
  }
  if (!verify(walk.messageKey)) return null;

  if (step) {
    state.root = step.root;
    state.peerRkPub = step.peerRkPub;
    if (step.tail) cacheSkipped(state, step.tail.cid, step.tail.keys);
    rememberChain(state, step.enteredCid);
  }
  cacheSkipped(state, header.cid, walk.skipped);
  state.recv = { ck: walk.ck, n: walk.nextN };
  delete state.pendingInit;
  return walk.messageKey;
}

type ChainWalkResult = ReturnType<typeof walkChain>;

export { chainId, MAX_SKIPPED, RATCHET_MAX_MESSAGES_PER_CHAIN, RATCHET_MIN_STEP_INTERVAL_MS };
