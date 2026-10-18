import * as crypto from "node:crypto";
import { openPayload, sealPayload } from "../protocol/aead";
import { decodeFrame, encodeFrame, type Frame, frameHeader, validateFrame } from "../protocol/envelope";
import {
  decodeHandshake,
  encodeHandshake,
  handshakeNonce,
  handshakeProof,
  handshakeProofMatches,
  initTranscript,
} from "../protocol/handshake";
import {
  type InitHeader,
  type Kem,
  type MessageHeader,
  open,
  type PrekeySecrets,
  seal,
  startAsInitiator,
  startAsResponder,
} from "../protocol/ratchet";
import { conversationTopic, handshakeTopic, inboxTopic } from "../protocol/topics";
import type { Api, Friend } from "./api";
import type { Identity } from "./identity";
import type { ClientState, Peer, Store } from "./store";

/** A frame to publish. */
export interface Outbound {
  topic: string;
  payload: Buffer;
}

/** A decrypted message. */
export interface Message {
  from: string;
  text: string;
  msgId: string;
}

/** The result of one inbound publish: messages to deliver, frames to publish, or why it was dropped. */
export interface Received {
  messages: Message[];
  outbound: Outbound[];
  /** Ids of our own messages the peer acknowledged. */
  delivered?: string[];
  dropped?: string;
}

const PREKEY_POOL = 8;
const PREKEY_REPLENISH_AT = 4;
/** Lifetime of the medium-term prekey, and so the forward-secrecy window of sessions that miss the one-time pool. */
const MEDIUM_TERM_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
/** How long an issued handshake challenge stands. */
const CHALLENGE_TTL_MS = 60_000;
/** Open challenges per peer (one per distinct init): bounds the encapsulations and held frames forged inits cost. */
const MAX_CHALLENGES_PER_PEER = 4;

/** An open challenge, about ONE init (keyed by its transcript). */
interface Challenge {
  peer: string;
  nonce: Buffer;
  expected: Buffer;
  /** `init` frames held until the proof arrives, in arrival order. */
  held: Array<{ frame: Frame; aad: Buffer }>;
  expiresAt: number;
}

const nothing = (dropped: string): Received => ({ messages: [], outbound: [], dropped });

/** The ratchet header a frame carries. */
export function messageHeaderOf(f: Frame): MessageHeader {
  return {
    cid: f.cid,
    n: f.n,
    pn: f.pn,
    ...(f.rk ? { rk: f.rk } : {}),
    ...(f.kemCt ? { kemCt: f.kemCt } : {}),
  };
}

/** The handshake an `init` frame carries, or null when a required part is missing. */
export function initHeaderOf(f: Frame): InitHeader | null {
  if (!f.ctId || !f.ctMt || !f.rk) return null;
  const ctOt = f.ctOt ?? null;
  return { ctId: f.ctId, ctMt: f.ctMt, ctOt, otId: ctOt ? (f.otId ?? null) : null, rk: f.rk, cid: f.cid };
}

/**
 * End-to-end conversations with friends, independent of the transport.
 *
 * Sending opens a session on demand from the peer's published prekeys; the
 * first frames are `init`s, published to the peer's inbox so the broker
 * queues them. Receiving an `init` from a peer that has not yet proven its
 * identity key holds the frame and challenges the peer on the friendship's
 * handshake topic; the frames are opened once the proof arrives. Every frame
 * must be addressed to this client and arrive on the topic its kind belongs to.
 */
export class Conversations {
  readonly state: ClientState;
  /** Open challenges, keyed by the hex transcript of the init they are about. */
  private readonly challenges = new Map<string, Challenge>();
  /** Transcripts (hex) of inits whose sender proved possession of its key. */
  private readonly proven = new Set<string>();
  private readonly now: () => number;

  constructor(private readonly o: { identity: Identity; kem: Kem; api: Api; store: Store; now?: () => number }) {
    this.state = o.store.load();
    this.now = o.now ?? Date.now;
  }

  private get me(): string {
    return this.o.identity.id;
  }

  private save(): void {
    this.o.store.save(this.state);
  }

  peer(id: string): Peer | undefined {
    return this.state.peers[id];
  }

  /** A friend's conversation and handshake topics; empty before `applyFriends` named them. */
  topicsOf(id: string): string[] {
    const p = this.state.peers[id];
    return p?.convoId && p.handshakeId ? [conversationTopic(p.convoId), handshakeTopic(p.handshakeId)] : [];
  }

  /** Every topic this client must be subscribed to: its inbox and each friendship's topics. */
  subscriptions(): string[] {
    return [inboxTopic(this.me), ...Object.keys(this.state.peers).flatMap((id) => this.topicsOf(id))];
  }

  /**
   * Makes the tracked friends match `/friends`: new friends are added, names
   * and topic ids updated, and removed friends forgotten with their sessions.
   * Returns the topics to subscribe to and to drop.
   */
  applyFriends(friends: Friend[]): { subscribe: string[]; unsubscribe: string[] } {
    const subscribe: string[] = [];
    const unsubscribe: string[] = [];
    let changed = false;
    const live = new Set<string>();
    for (const f of friends) {
      if (f.id === this.me) continue;
      live.add(f.id);
      const known = this.state.peers[f.id];
      const p: Peer = known ?? { id: f.id };
      if (f.username && p.username !== f.username) {
        p.username = f.username;
        changed = true;
      }
      if (p.convoId !== f.convoId || p.handshakeId !== f.handshakeId) {
        unsubscribe.push(...this.topicsOf(f.id));
        p.convoId = f.convoId;
        p.handshakeId = f.handshakeId;
        this.state.peers[f.id] = p;
        subscribe.push(...this.topicsOf(f.id));
        changed = true;
      }
    }
    for (const id of Object.keys(this.state.peers)) {
      if (live.has(id)) continue;
      unsubscribe.push(...this.topicsOf(id));
      delete this.state.peers[id];
      this.dropChallenges(id);
      changed = true;
    }
    if (changed) this.save();
    return { subscribe, unsubscribe };
  }

  /**
   * Keeps a prekey bundle published: rotates the medium-term key when it is
   * due and tops the one-time pool up. Secrets are saved before the public
   * halves are uploaded. Returns how many one-time keys were published.
   */
  async ensurePrekeys(): Promise<number> {
    const { kem, api } = this.o;
    let k = this.state.prekeys;
    const rotate = !k || this.now() - k.rotatedAt > MEDIUM_TERM_LIFETIME_MS;
    let want = PREKEY_POOL;
    if (!rotate) {
      const remaining = await api.prekeyCount();
      if (remaining > PREKEY_REPLENISH_AT) return 0;
      want = PREKEY_POOL - remaining;
    }
    if (rotate || !k) {
      const medium = kem.generateKeypair();
      k = {
        mediumPk: medium.pk,
        mediumSk: medium.sk,
        oneTime: k?.oneTime ?? new Map(),
        nextId: k?.nextId ?? 0,
        rotatedAt: this.now(),
      };
      this.state.prekeys = k;
    }
    const minted: Array<{ id: number; pk: Buffer }> = [];
    for (let i = 0; i < want; i++) {
      const pair = kem.generateKeypair();
      const id = k.nextId++;
      k.oneTime.set(id, pair.sk);
      minted.push({ id, pk: pair.pk });
    }
    this.save();
    await api.publishPrekeys(k.mediumPk, minted);
    return minted.length;
  }

  /**
   * Seals `text` for a friend, opening a session first when there is none
   * (which claims one of their one-time prekeys). Throws ApiError 404
   * NO_PREKEYS when the friend has published none yet.
   */
  async seal(peerId: string, text: string): Promise<{ frame: Frame; outbound: Outbound }> {
    const p = this.state.peers[peerId];
    if (!p?.convoId) throw new Error(`${peerId.slice(0, 12)}… is not a synced friend`);
    if (!p.session) await this.openSession(p);
    return this.sealFrame(p, "msg", crypto.randomUUID(), text);
  }

  /**
   * A receipt for the peer's message `msgId`: an empty sealed frame inside an
   * answered session, or nothing (a receipt never opens one).
   */
  private receiptFor(p: Peer, msgId: string): Outbound[] {
    if (!p.session || p.session.pendingInit) return [];
    return [this.sealFrame(p, "receipt", msgId, "").outbound];
  }

  private sealFrame(
    p: Peer,
    kind: "msg" | "receipt",
    msgId: string,
    text: string,
  ): { frame: Frame; outbound: Outbound } {
    const sealed = seal(this.o.kem, p.session!, this.now());
    const init = sealed.initHeader;
    const fields: Omit<Frame, "payload"> = {
      v: 3,
      t: init ? "init" : kind,
      sender: this.me,
      to: p.id,
      msgId,
      cid: sealed.header.cid,
      n: sealed.header.n,
      pn: sealed.header.pn,
      ...(init
        ? {
            senderPk: this.o.identity.pk,
            rk: init.rk,
            ctId: init.ctId,
            ctMt: init.ctMt,
            ...(init.ctOt && init.otId !== null ? { ctOt: init.ctOt, otId: init.otId } : {}),
          }
        : {
            ...(sealed.header.rk ? { rk: sealed.header.rk } : {}),
            ...(sealed.header.kemCt ? { kemCt: sealed.header.kemCt } : {}),
          }),
    };
    const aad = frameHeader(fields);
    if (!aad) throw new Error(`cannot frame a message: ${validateFrame(fields)}`);
    const frame: Frame = { ...fields, payload: sealPayload(text, sealed.key, aad) };
    const bytes = encodeFrame(frame);
    if (!bytes) throw new Error("cannot encode the sealed frame");
    this.save();
    return { frame, outbound: { topic: this.topicFor(frame), payload: bytes } };
  }

  /** Where a frame to a friend is published: an `init` to their inbox, anything else to the conversation. */
  topicFor(frame: Frame): string {
    if (frame.t === "init") return inboxTopic(frame.to);
    const convoId = this.state.peers[frame.to]?.convoId;
    if (!convoId) throw new Error(`no conversation topic for ${frame.to.slice(0, 12)}…`);
    return conversationTopic(convoId);
  }

  /** Handles one inbound publish on a conversation, handshake or inbox topic. */
  receive(topic: string, payload: Buffer): Received {
    if (topic.startsWith("hs/")) return this.onHandshake(topic, payload);
    const decoded = decodeFrame(payload);
    if (!decoded) return nothing(`not a frame on ${topic}`);
    const { frame, aad } = decoded;
    if (frame.sender === this.me) return nothing("own frame");
    const p = this.state.peers[frame.sender];
    if (!p) return nothing(`frame from ${frame.sender.slice(0, 12)}…, not a friend`);
    if (frame.to !== this.me) return nothing(`frame addressed to ${frame.to.slice(0, 12)}…`);
    const expected = frame.t === "init" ? inboxTopic(this.me) : p.convoId && conversationTopic(p.convoId);
    if (topic !== expected) return nothing(`${frame.t} on ${topic}, expected ${expected}`);

    if (frame.t === "init" && !p.session) {
      const header = initHeaderOf(frame);
      if (!header) return nothing("init missing handshake fields");
      const transcript = initTranscript(frame.sender, frame.to, header).toString("hex");
      return this.proven.has(transcript) ? this.openInit(p, frame, aad) : this.challenge(p, frame, aad, transcript);
    }
    return this.openMessage(p, frame, aad);
  }

  private async openSession(p: Peer): Promise<void> {
    const { api, kem } = this.o;
    const identityPk = p.pk ? Buffer.from(p.pk, "hex") : await api.peerKey(p.id);
    p.pk = identityPk.toString("hex");
    const claim = await api.claimPrekeys(p.id);
    p.session = startAsInitiator(
      kem,
      {
        identityPk,
        mediumPk: Buffer.from(claim.medium, "hex"),
        oneTimePk: claim.oneTime ? Buffer.from(claim.oneTime.prekey, "hex") : null,
        oneTimeId: claim.oneTime ? claim.oneTime.id : null,
      },
      this.now(),
    ).state;
    this.save();
  }

  private sweepChallenges(): void {
    const now = this.now();
    for (const [id, c] of this.challenges) if (c.expiresAt <= now) this.challenges.delete(id);
  }

  /** Drops every open challenge for one peer. */
  private dropChallenges(peer: string): void {
    for (const [t, c] of this.challenges) if (c.peer === peer) this.challenges.delete(t);
  }

  /**
   * Holds an unproven init and challenges its sender, one challenge per
   * distinct init: the proof is bound to the transcript, so it releases only
   * the frames of the init the sender actually built.
   */
  private challenge(p: Peer, frame: Frame, aad: Buffer, transcript: string): Received {
    this.sweepChallenges();
    const open = this.challenges.get(transcript);
    if (open) {
      open.held.push({ frame, aad });
      return { messages: [], outbound: [] };
    }
    if (!p.handshakeId || !frame.senderPk) return nothing("init without a handshake topic or sender key");
    const openForPeer = [...this.challenges].filter(([, c]) => c.peer === p.id);
    // At the cap the oldest goes: the real initiator re-sends its init, so its newest one always gets a challenge.
    if (openForPeer.length >= MAX_CHALLENGES_PER_PEER) this.challenges.delete(openForPeer[0]![0]);
    const nonce = handshakeNonce();
    const { ct, ss } = this.o.kem.encapsulate(frame.senderPk);
    this.challenges.set(transcript, {
      peer: p.id,
      nonce,
      expected: handshakeProof(ss, nonce, this.me, p.id, Buffer.from(transcript, "hex")),
      held: [{ frame, aad }],
      expiresAt: this.now() + CHALLENGE_TTL_MS,
    });
    const chal = encodeHandshake({ kind: "chal", from: this.me, to: p.id, nonce, ct });
    return { messages: [], outbound: [{ topic: handshakeTopic(p.handshakeId), payload: chal }] };
  }

  private onHandshake(topic: string, raw: Buffer): Received {
    const h = decodeHandshake(raw);
    if (!h) return nothing("not a handshake frame");
    if (h.from === this.me) return nothing("own handshake frame");
    if (h.to !== this.me) return nothing("handshake frame for another client");
    const p = this.state.peers[h.from];
    if (!p?.handshakeId || topic !== handshakeTopic(p.handshakeId)) return nothing(`handshake frame on ${topic}`);

    if (h.kind === "chal") {
      const pendingInit = p.session?.pendingInit;
      if (!pendingInit || !h.ct) return nothing("challenge for a handshake this client did not start");
      let ss: Buffer;
      try {
        ss = this.o.kem.decapsulate(this.o.identity.sk, h.ct);
      } catch {
        return nothing("challenge did not decapsulate");
      }
      const proof = encodeHandshake({
        kind: "proof",
        from: this.me,
        to: p.id,
        nonce: h.nonce,
        // Bound to the init WE sent: a challenge about a forged init gets a proof that does not match it.
        proof: handshakeProof(ss, h.nonce, p.id, this.me, initTranscript(this.me, p.id, pendingInit)),
      });
      return { messages: [], outbound: [{ topic, payload: proof }] };
    }

    this.sweepChallenges();
    const found = [...this.challenges].find(([, c]) => c.peer === p.id && c.nonce.equals(h.nonce));
    if (!found || !h.proof) return nothing("proof for no open challenge");
    const [transcript, pending] = found;
    this.challenges.delete(transcript);
    if (!handshakeProofMatches(pending.expected, h.proof)) return nothing("handshake proof did not match");
    // The peer proved THIS init. Its other open challenges are about inits it did not build.
    this.proven.add(transcript);
    this.dropChallenges(p.id);
    const out: Received = { messages: [], outbound: [] };
    for (const { frame, aad } of pending.held) {
      const r = p.session ? this.openMessage(p, frame, aad) : this.openInit(p, frame, aad);
      out.messages.push(...r.messages);
      out.outbound.push(...r.outbound);
      if (r.dropped) out.dropped = r.dropped;
    }
    return out;
  }

  private prekeySecrets(): PrekeySecrets | null {
    const k = this.state.prekeys;
    if (!k) return null;
    return { identitySk: this.o.identity.sk, mediumSk: k.mediumSk, oneTimeSk: (id) => k.oneTime.get(id) ?? null };
  }

  private openInit(p: Peer, frame: Frame, aad: Buffer): Received {
    const header = initHeaderOf(frame);
    if (!header) return nothing("init missing handshake fields");
    const secrets = this.prekeySecrets();
    if (!secrets) return nothing("init before this client published prekeys");
    const session = startAsResponder(this.o.kem, secrets, header, this.now());
    if (!session) return nothing("init did not open a session");
    const text = this.openWith(session, frame, aad);
    if (text === null) return nothing("init payload did not authenticate");
    if (!p.pk && frame.senderPk) p.pk = frame.senderPk.toString("hex");
    p.session = session;
    if (frame.otId !== undefined) this.state.prekeys?.oneTime.delete(frame.otId);
    this.save();
    return { messages: [{ from: p.id, text, msgId: frame.msgId }], outbound: this.receiptFor(p, frame.msgId) };
  }

  private openMessage(p: Peer, frame: Frame, aad: Buffer): Received {
    if (!p.session) return nothing(`${frame.t} from ${p.id.slice(0, 12)}… with no session`);
    const text = this.openWith(p.session, frame, aad);
    if (text === null) return nothing(`${frame.t} n=${frame.n} did not authenticate`);
    this.save();
    if (frame.t === "receipt") return { messages: [], outbound: [], delivered: [frame.msgId] };
    return { messages: [{ from: p.id, text, msgId: frame.msgId }], outbound: this.receiptFor(p, frame.msgId) };
  }

  /** Opens a frame's payload; the AEAD tag decides whether the ratchet commits. */
  private openWith(session: NonNullable<Peer["session"]>, frame: Frame, aad: Buffer): string | null {
    let text: string | null = null;
    const key = open(this.o.kem, session, messageHeaderOf(frame), (mk) => {
      try {
        text = openPayload(frame.payload, mk, aad);
        return true;
      } catch {
        return false;
      }
    });
    return key === null ? null : text;
  }
}
