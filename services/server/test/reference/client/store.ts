import * as fs from "node:fs";
import * as path from "node:path";
import type { InitHeader, SessionState } from "../protocol/ratchet";

/** What a client knows about one friend. */
export interface Peer {
  id: string;
  username?: string;
  /** Identity public key, hex; present only once verified against `id`. */
  pk?: string;
  session?: SessionState;
  convoId?: string;
  handshakeId?: string;
}

/** This client's prekey secrets. */
export interface Prekeys {
  mediumPk: Buffer;
  mediumSk: Buffer;
  oneTime: Map<number, Buffer>;
  nextId: number;
  rotatedAt: number;
}

/** Everything a client persists between runs. */
export interface ClientState {
  peers: Record<string, Peer>;
  prekeys: Prekeys | null;
}

/** Where a client's state lives. */
export interface Store {
  load(): ClientState;
  save(state: ClientState): void;
}

export function emptyState(): ClientState {
  return { peers: {}, prekeys: null };
}

/** Keeps state in memory only. */
export class MemoryStore implements Store {
  private state = emptyState();
  load(): ClientState {
    return this.state;
  }
  save(state: ClientState): void {
    this.state = state;
  }
}

/** Keeps state in a JSON file (mode 0600), written atomically. */
export class FileStore implements Store {
  constructor(private readonly file: string) {}

  load(): ClientState {
    if (!fs.existsSync(this.file)) return emptyState();
    return decodeState(JSON.parse(fs.readFileSync(this.file, "utf8")));
  }

  save(state: ClientState): void {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(encodeState(state)), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

const b64 = (b: Buffer) => b.toString("base64");
const buf = (v: unknown) => Buffer.from(String(v ?? ""), "base64");

type Base64 = string;

/** `SessionState` as JSON, every Buffer as base64. */
export interface EncodedSession {
  root: Base64;
  rkPub: Base64;
  rkSec: Base64;
  peerRkPub: Base64 | null;
  send: { ck: Base64; n: number } | null;
  recv: { ck: Base64; n: number } | null;
  prevSendN: number;
  skipped: Array<{ chain: string; n: number; key: Base64 }>;
  seenChains: string[];
  sentOnChain: number;
  chainStartedAt: number;
  pendingInit?: { ctId: Base64; ctMt: Base64; ctOt: Base64 | null; otId: number | null; rk: Base64; cid: string };
}

interface EncodedState {
  peers: Record<string, Omit<Peer, "session"> & { session?: EncodedSession }>;
  prekeys: {
    mediumPk: Base64;
    mediumSk: Base64;
    oneTime: Record<string, Base64>;
    nextId: number;
    rotatedAt: number;
  } | null;
}

/** A session as JSON, every Buffer as base64. */
export function encodeSession(s: SessionState): EncodedSession {
  return {
    root: b64(s.root),
    rkPub: b64(s.rkPub),
    rkSec: b64(s.rkSec),
    peerRkPub: s.peerRkPub ? b64(s.peerRkPub) : null,
    send: s.send ? { ck: b64(s.send.ck), n: s.send.n } : null,
    recv: s.recv ? { ck: b64(s.recv.ck), n: s.recv.n } : null,
    prevSendN: s.prevSendN,
    skipped: s.skipped.map((k) => ({ chain: k.chain, n: k.n, key: b64(k.key) })),
    seenChains: s.seenChains,
    sentOnChain: s.sentOnChain,
    chainStartedAt: s.chainStartedAt,
    ...(s.pendingInit
      ? {
          pendingInit: {
            ctId: b64(s.pendingInit.ctId),
            ctMt: b64(s.pendingInit.ctMt),
            ctOt: s.pendingInit.ctOt ? b64(s.pendingInit.ctOt) : null,
            otId: s.pendingInit.otId,
            rk: b64(s.pendingInit.rk),
            cid: s.pendingInit.cid,
          },
        }
      : {}),
  };
}

/** The session `encodeSession` wrote, or null for anything else. */
export function decodeSession(raw: unknown): SessionState | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Partial<EncodedSession>;
  if (typeof r.root !== "string" || typeof r.rkPub !== "string" || typeof r.rkSec !== "string") return null;
  const pending = r.pendingInit;
  return {
    root: buf(r.root),
    rkPub: buf(r.rkPub),
    rkSec: buf(r.rkSec),
    peerRkPub: r.peerRkPub ? buf(r.peerRkPub) : null,
    send: r.send ? { ck: buf(r.send.ck), n: Number(r.send.n) } : null,
    recv: r.recv ? { ck: buf(r.recv.ck), n: Number(r.recv.n) } : null,
    prevSendN: Number(r.prevSendN ?? 0),
    skipped: Array.isArray(r.skipped)
      ? r.skipped.map((k) => ({ chain: String(k.chain), n: Number(k.n), key: buf(k.key) }))
      : [],
    seenChains: Array.isArray(r.seenChains) ? r.seenChains.map(String) : [],
    sentOnChain: Number(r.sentOnChain ?? 0),
    chainStartedAt: Number(r.chainStartedAt ?? 0),
    ...(pending
      ? {
          pendingInit: {
            ctId: buf(pending.ctId),
            ctMt: buf(pending.ctMt),
            ctOt: pending.ctOt ? buf(pending.ctOt) : null,
            otId: pending.otId ?? null,
            rk: buf(pending.rk),
            cid: String(pending.cid),
          } satisfies InitHeader,
        }
      : {}),
  };
}

function encodeState(s: ClientState): EncodedState {
  return {
    peers: Object.fromEntries(
      Object.entries(s.peers).map(([id, { session, ...peer }]) => [
        id,
        { ...peer, ...(session ? { session: encodeSession(session) } : {}) },
      ]),
    ),
    prekeys: s.prekeys
      ? {
          mediumPk: b64(s.prekeys.mediumPk),
          mediumSk: b64(s.prekeys.mediumSk),
          oneTime: Object.fromEntries([...s.prekeys.oneTime].map(([id, sk]) => [id, b64(sk)])),
          nextId: s.prekeys.nextId,
          rotatedAt: s.prekeys.rotatedAt,
        }
      : null,
  };
}

function decodeState(raw: unknown): ClientState {
  const r = (raw ?? {}) as Partial<EncodedState>;
  const peers: Record<string, Peer> = {};
  for (const [id, p] of Object.entries(r.peers ?? {})) {
    const session = decodeSession(p?.session);
    peers[id] = {
      id,
      ...(p.username ? { username: String(p.username) } : {}),
      ...(p.pk ? { pk: String(p.pk) } : {}),
      ...(p.convoId ? { convoId: String(p.convoId) } : {}),
      ...(p.handshakeId ? { handshakeId: String(p.handshakeId) } : {}),
      ...(session ? { session } : {}),
    };
  }
  const k = r.prekeys;
  return {
    peers,
    prekeys: k
      ? {
          mediumPk: buf(k.mediumPk),
          mediumSk: buf(k.mediumSk),
          oneTime: new Map(Object.entries(k.oneTime ?? {}).map(([id, sk]) => [Number(id), buf(sk)])),
          nextId: Number(k.nextId ?? 0),
          rotatedAt: Number(k.rotatedAt ?? 0),
        }
      : null,
  };
}
