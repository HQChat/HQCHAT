import { createRequire } from "node:module";
import * as path from "node:path";

/**
 * The Rust core's Node addon (core/hqchat-node): the protocol, the hqn/1
 * gateway and the client Engine, one implementation shared with the apps.
 * Loaded from `HQCHAT_NODE` (set by the Nix package), else from the build
 * that `core/hqchat-node/build.sh` leaves in the source tree.
 *
 * The types below mirror the Rust exports; test/unit/core-addon.test.ts
 * fails when either side has a name the other lacks.
 */

export interface HqcKeyPair {
  pk: Buffer;
  sk: Buffer;
}

export interface Encapsulation {
  ct: Buffer;
  ss: Buffer;
}

export interface ConnectProof {
  keyId: string;
  ts: number;
  nonce: Buffer;
  signature: Buffer;
}

/** The gateway's static keys, as its key file holds them. */
export interface GatewayKey {
  keyId: number;
  x25519: Buffer;
  hqcSeed: Buffer;
}

export interface GatewayPublicKey {
  keyId: number;
  x25519: Buffer;
  hqc: Buffer;
}

export interface HqnTransport {
  seal(data: Buffer): Buffer;
  /** Opens a chunk of the inbound stream; returns whatever whole frames held. */
  open(chunk: Buffer): Buffer;
  readonly handshakeHash: Buffer;
}

export interface HqnMessage2 {
  takeMessage(): Buffer;
  takeTransport(): HqnTransport;
}

export interface HqnGatewayHandshake {
  openMessage1(msg1: Buffer): Buffer;
  finishMessage1(secret: HqnSecret): Buffer;
  writeMessage2(payload: Buffer): HqnMessage2;
}

/** A gateway key pair, derived once from its seeds (HQC keygen takes milliseconds). */
export interface GatewayKeyPair {
  readonly keyId: number;
  publicKey(): GatewayPublicKey;
  /** The key's fingerprint, as the apps' `hqnKeyPins` list it. */
  fingerprint(): string;
  /** Decapsulates on libuv's thread pool; the secret stays in the core. */
  decapsulate(ct: Buffer): Promise<HqnSecret>;
}

/** A decapsulated secret held by the core: a handle, never bytes. */
export interface HqnSecret {
  readonly __hqnSecret?: never;
}

export interface HqnGatewayHandshakeClass {
  new (key: GatewayKeyPair): HqnGatewayHandshake;
  /** The client's ephemeral key, for the replay cache, before any work. */
  ephemeralOf(msg1: Buffer): Buffer;
}

export interface EngineOptions {
  serverUrl: string;
  profileId: string;
  /** Directory the engine's sealed blobs live in. */
  dir: string;
  /** The device key from a previous run, 32 bytes. */
  deviceKey?: Buffer;
  /** Reach the broker over hqn/1 when the server offers it (default true); false keeps to WSS. */
  hqn?: boolean;
}

/** What `importLegacy` did. */
export interface CoreImport {
  effects: CoreEffect[];
  /** Friends whose session could not be read: imported without one. */
  unreadable: string[];
}

export interface CoreMessage {
  msgId: string;
  peer: string;
  outgoing: boolean;
  text: string;
  at: number;
  delivery?: string;
}

/** One effect; `kind` says which fields are set. */
export interface CoreEffect {
  kind:
    | "http"
    | "open"
    | "write"
    | "close"
    | "timer"
    | "needUnlock"
    | "messageAdded"
    | "messageStatus"
    | "friendsChanged"
    | "invitesChanged"
    | "actionDone"
    | "presenceChanged"
    | "connection"
    | "tierChanged"
    | "notify"
    | "actionFailed"
    | "accountDeleted"
    | "dropped"
    | "storageFailed";
  req?: number;
  method?: string;
  path?: string;
  authorization?: string;
  body?: Buffer;
  conn?: number;
  transport?: "tcp" | "wss";
  host?: string;
  port?: number;
  url?: string;
  at?: number;
  reason?: string;
  message?: CoreMessage;
  msgId?: string;
  state?: string;
  peer?: string;
  online?: boolean;
  action?: string;
  status?: number;
  code?: string;
}

export interface CoreFriend {
  id: string;
  username?: string;
  online: boolean;
  hasSession: boolean;
  unread: number;
  /** Unix ms; a blocked friend is kept, read-only. */
  blockedAt?: number;
  /** Unix ms; their username now belongs to another identity. */
  vanishedAt?: number;
  hasKey: boolean;
  verified: boolean;
}

export interface CoreSentInvite {
  to: string;
  at: number;
}

export interface CoreInvite {
  id: string;
  username: string;
}

export interface Engine {
  /** The device key to keep for the next run; null before `createIdentity`. */
  readonly deviceKey: Buffer | null;
  createIdentity(): CoreEffect[];
  /** The bot's seed and the TS reference client's state file, into a profile with no identity. */
  importLegacy(seed: Buffer, stateJson: string | null, now: number): CoreImport;
  start(now: number, network: string): CoreEffect[];
  unlock(now: number): CoreEffect[];
  lock(): CoreEffect[];
  tick(now: number): CoreEffect[];
  sendText(peer: string, text: string, now: number): CoreEffect[];
  retry(msgId: string, now: number): CoreEffect[];
  invite(username: string): CoreEffect[];
  accept(peer: string): CoreEffect[];
  remove(peer: string): CoreEffect[];
  block(peer: string): CoreEffect[];
  unblock(peer: string): CoreEffect[];
  cancel(peer: string): CoreEffect[];
  setPresence(online: boolean, now: number): CoreEffect[];
  myId(): string | null;
  setVerified(peer: string, verified: boolean): CoreEffect[];
  sentInvites(): CoreSentInvite[];
  forget(peer: string): CoreEffect[];
  markRead(peer: string): CoreEffect[];
  rotateKeys(peer: string): CoreEffect[];
  report(peer: string, reason: string, msgId: string | null, block: boolean, note?: string | null): CoreEffect[];
  setUsername(username: string): CoreEffect[];
  deleteAccount(): CoreEffect[];
  registerApns(token: string, sandbox: boolean): CoreEffect[];
  history(peer: string, before: number | null, limit: number): CoreMessage[];
  friends(): CoreFriend[];
  invites(): CoreInvite[];
  fingerprint(peer: string): string | null;
  onHttp(req: number, status: number, body: Buffer, now: number): CoreEffect[];
  onOpened(conn: number, now: number): CoreEffect[];
  onBytes(conn: number, bytes: Buffer, now: number): CoreEffect[];
  /** `reason`: `requested`, `remote`, or anything else for a failure. */
  onClosed(conn: number, reason: string, now: number): CoreEffect[];
  onNetworkChanged(network: string, now: number): CoreEffect[];
}

export interface CoreAddon {
  hqcKeypairFromSeed(seed: Buffer): HqcKeyPair;
  hqcEncapsulate(pk: Buffer): Encapsulation;
  hqcDecapsulate(sk: Buffer, ct: Buffer): Buffer;
  /** A sign-in challenge to `pk` at `origin`; the shared secret never reaches JS. */
  authChallenge(pk: Buffer, origin: string): { ct: Buffer; proof: Buffer };
  /** `scheme://host[:port]` of a URL, as the sign-in proof binds it, or null. */
  originOf(url: string): string | null;
  authProofMatches(expected: Buffer, offered: Buffer): boolean;
  parseConnectProof(password: string): ConnectProof | null;
  /** 32 bytes, a canonical Ed25519 point, not of small order. */
  isSigningKey(raw: Buffer): boolean;
  isFreshTimestamp(ts: number, nowSec: number): boolean;
  verifyConnectProof(publicKey: Buffer, clientid: string, proof: ConnectProof): boolean;
  peerId(publicKeyHex: string): string;
  isPeerId(value: string): boolean;
  keyMatchesId(publicKeyHex: string, id: string): boolean;
  conversationTopic(convoId: string): string;
  handshakeTopic(handshakeId: string): string;
  hqnMsg1Length(payloadLen: number): number;
  hqnFrame(body: Buffer): Buffer;
  readonly MQTT_PROOF_NONCE_TTL_SECONDS: number;
  readonly PEER_ID_LENGTH: number;
  readonly HQC_PUBLIC_KEY_BYTES: number;
  readonly HQN_VERSION: number;
  GatewayKeyPair: new (key: GatewayKey) => GatewayKeyPair;
  HqnGatewayHandshake: HqnGatewayHandshakeClass;
  /** `fromBytes` is for tests that drive the handshake with a stand-in KEM. */
  HqnSecret: { fromBytes(ss: Buffer): HqnSecret };
  HqnMessage2: unknown;
  HqnTransport: unknown;
  Engine: new (options: EngineOptions) => Engine;
}

/** Every name the addon exports, for the conformance test. */
export const CORE_EXPORTS: readonly (keyof CoreAddon)[] = [
  "hqcKeypairFromSeed",
  "hqcEncapsulate",
  "hqcDecapsulate",
  "authChallenge",
  "originOf",
  "authProofMatches",
  "parseConnectProof",
  "isSigningKey",
  "isFreshTimestamp",
  "verifyConnectProof",
  "peerId",
  "isPeerId",
  "keyMatchesId",
  "conversationTopic",
  "handshakeTopic",
  "hqnMsg1Length",
  "hqnFrame",
  "MQTT_PROOF_NONCE_TTL_SECONDS",
  "PEER_ID_LENGTH",
  "HQC_PUBLIC_KEY_BYTES",
  "HQN_VERSION",
  "GatewayKeyPair",
  "HqnGatewayHandshake",
  "HqnSecret",
  "HqnMessage2",
  "HqnTransport",
  "Engine",
];

/** Where the addon is loaded from. */
export function corePath(): string {
  return (
    process.env.HQCHAT_NODE ?? path.join(__dirname, "..", "..", "..", "..", "core", "hqchat-node", "hqchat_node.node")
  );
}

function load(): CoreAddon {
  const file = corePath();
  try {
    return createRequire(__filename)(file) as CoreAddon;
  } catch (e) {
    throw new Error(
      `the core addon did not load from ${file} (${process.platform}/${process.arch}): ` +
        `${(e as Error).message}. Set HQCHAT_NODE, or run core/hqchat-node/build.sh.`,
    );
  }
}

export const core: CoreAddon = load();

/** Whether `value` is an id (64 lowercase hex), for values from JSON. */
export function isPeerId(value: unknown): value is string {
  return typeof value === "string" && core.isPeerId(value);
}
