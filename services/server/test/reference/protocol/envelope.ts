/**
 * The client-to-client frame: length-prefixed binary whose header is also the
 * AAD the payload is sealed against. A receiver binds the exact bytes that
 * arrived, so there is no second canonical encoding to keep in step.
 *
 * Layout (integers big-endian; bytes 0 up to the payload length are the AAD):
 *
 *   0   magic     4 bytes   "HQCE"
 *   4   version   u8        3
 *   5   kind      u8        0 = msg, 1 = init, 2 = receipt
 *   6   flags     u8        bit0 rk, bit1 kemCt, bit2 one-time (ctOt + otId)
 *   7   sender    32 bytes  sender client id
 *   39  to        32 bytes  recipient client id
 *   71  cid       16 bytes  chain selector
 *   87  n         u32
 *   91  pn        u32
 *   95  msgIdLen  u8        1..128
 *   96  msgId     UTF-8
 *       [rk]      u32 len + bytes
 *       [kemCt]   u32 len + bytes
 *       [init]    u32 len + senderPk, u32 len + ctId, u32 len + ctMt
 *       [oneTime] u32 len + ctOt, u32 otId
 *       payload   u32 len + bytes
 *
 * Sending: build the header with `frameHeader`, seal the payload against it,
 * then `encodeFrame`, which derives the same header.
 */

import { keyMatchesId, PEER_ID_RE } from "./identity";

/**
 * Whether a frame opens a session, carries a message inside one, or
 * acknowledges the message whose id it carries (laid out as a `msg`).
 */
export type EnvelopeKind = "init" | "msg" | "receipt";

const KIND_BYTE: Record<EnvelopeKind, number> = { msg: 0, init: 1, receipt: 2 };
const KIND_OF_BYTE: readonly EnvelopeKind[] = ["msg", "init", "receipt"];

const MAGIC = Buffer.from("HQCE", "ascii");
export const FRAME_VERSION = 3;

/**
 * `rk` and `kemCt` have independent bits: a `msg` carries both or neither, an
 * `init` carries `rk` alone (there is no peer ratchet key to encapsulate to).
 */
const FLAG_RK = 0x01;
const FLAG_KEMCT = 0x02;
const FLAG_ONE_TIME = 0x04;
const ALL_FLAGS = FLAG_RK | FLAG_KEMCT | FLAG_ONE_TIME;

const OFF_VERSION = 4;
const OFF_KIND = 5;
const OFF_FLAGS = 6;
const OFF_SENDER = 7;
const OFF_TO = 39;
const OFF_CID = 71;
const OFF_N = 87;
const OFF_PN = 91;
const OFF_MSGID_LEN = 95;
const OFF_MSGID = 96;

const ID_BYTES = 32;
const CID_BYTES = 16;
const MAX_MSGID_BYTES = 128;

/** Upper bound on any length prefix, so a hostile prefix is not an allocation request. */
const MAX_FIELD_BYTES = 1 << 20;

/** The largest `n`, `pn` or `otId` a frame can carry. */
export const MAX_COUNTER = 0xffffffff;

/** A decoded frame. Ids are lowercase hex; binary fields are Buffers. */
export interface Frame {
  v: 3;
  t: EnvelopeKind;
  /** 64 hex chars. */
  sender: string;
  /** 64 hex chars. */
  to: string;
  msgId: string;
  /** 32 hex chars. */
  cid: string;
  n: number;
  pn: number;
  rk?: Buffer;
  kemCt?: Buffer;
  ctId?: Buffer;
  ctMt?: Buffer;
  ctOt?: Buffer;
  otId?: number;
  /** The initiator's public key; must hash to `sender`. */
  senderPk?: Buffer;
  payload: Buffer;
}

function u32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value, 0);
  return b;
}

/** A length-prefixed blob. */
function blob(b: Buffer): Buffer {
  return Buffer.concat([u32(b.length), b]);
}

/** Exactly `bytes` bytes of lowercase hex, and nothing else. */
function isHexOfWidth(value: unknown, bytes: number): value is string {
  return typeof value === "string" && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}

function isCounter(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= MAX_COUNTER;
}

/**
 * Why these fields cannot make a well-formed frame, or null when they can.
 * Encoders refuse rather than pad, clip or wrap, so every implementation
 * produces the same bytes or none.
 */
export function validateFrame(f: Omit<Frame, "payload">): string | null {
  if (!isHexOfWidth(f.sender, ID_BYTES)) return "sender is not a client id";
  if (!isHexOfWidth(f.to, ID_BYTES)) return "to is not a client id";
  if (!isHexOfWidth(f.cid, CID_BYTES)) return "cid is not a chain selector";
  if (!isCounter(f.n)) return "n is not a u32";
  if (!isCounter(f.pn)) return "pn is not a u32";

  const msgIdBytes = Buffer.byteLength(f.msgId ?? "", "utf8");
  if (msgIdBytes === 0 || msgIdBytes > MAX_MSGID_BYTES) return "msgId is empty or over 128 bytes";

  for (const [name, value] of Object.entries({
    rk: f.rk,
    kemCt: f.kemCt,
    ctId: f.ctId,
    ctMt: f.ctMt,
    ctOt: f.ctOt,
    senderPk: f.senderPk,
  })) {
    if (value !== undefined && value.length === 0) return `${name} is present but empty`;
    if (value !== undefined && value.length > MAX_FIELD_BYTES) return `${name} is implausibly large`;
  }
  if (f.otId !== undefined && !isCounter(f.otId)) return "otId is not a u32";

  if (f.t !== "init" && (f.rk === undefined) !== (f.kemCt === undefined)) {
    return "a msg carries rk and kemCt together or not at all";
  }
  if (f.t === "init") {
    if (f.rk === undefined) return "an init must advertise rk";
    if (f.kemCt !== undefined) return "an init must not carry a kemCt";
    if (f.senderPk === undefined) return "an init must carry senderPk";
    if (f.ctId === undefined || f.ctMt === undefined) return "an init needs ctId and ctMt";
    if (!keyMatchesId(f.senderPk.toString("hex"), f.sender)) {
      return "senderPk does not hash to sender";
    }
  }
  if ((f.ctOt === undefined) !== (f.otId === undefined)) {
    return "ctOt and otId travel together or not at all";
  }
  return null;
}

/** The header (and AAD) for these fields, or null when `validateFrame` refuses them. */
export function frameHeader(f: Omit<Frame, "payload">): Buffer | null {
  if (validateFrame(f) !== null) return null;

  const sender = Buffer.from(f.sender, "hex");
  const to = Buffer.from(f.to, "hex");
  const cid = Buffer.from(f.cid, "hex");
  const msgId = Buffer.from(f.msgId, "utf8");

  const hasRk = f.rk !== undefined;
  const hasKemCt = f.kemCt !== undefined;
  const hasOneTime = f.ctOt !== undefined && f.otId !== undefined;

  const fixed = Buffer.alloc(OFF_MSGID);
  MAGIC.copy(fixed, 0);
  fixed.writeUInt8(FRAME_VERSION, OFF_VERSION);
  fixed.writeUInt8(KIND_BYTE[f.t], OFF_KIND);
  fixed.writeUInt8((hasRk ? FLAG_RK : 0) | (hasKemCt ? FLAG_KEMCT : 0) | (hasOneTime ? FLAG_ONE_TIME : 0), OFF_FLAGS);
  sender.copy(fixed, OFF_SENDER);
  to.copy(fixed, OFF_TO);
  cid.copy(fixed, OFF_CID);
  fixed.writeUInt32BE(f.n, OFF_N);
  fixed.writeUInt32BE(f.pn, OFF_PN);
  fixed.writeUInt8(msgId.length, OFF_MSGID_LEN);

  const parts: Buffer[] = [fixed, msgId];
  if (hasRk) parts.push(blob(f.rk!));
  if (hasKemCt) parts.push(blob(f.kemCt!));
  if (f.t === "init") parts.push(blob(f.senderPk!), blob(f.ctId!), blob(f.ctMt!));
  if (hasOneTime) parts.push(blob(f.ctOt!), u32(f.otId!));
  return Buffer.concat(parts);
}

/** Header + payload. The complete frame, or null when it would not be one. */
export function encodeFrame(f: Frame): Buffer | null {
  if (f.payload === undefined || f.payload.length === 0) return null;
  if (f.payload.length > MAX_FIELD_BYTES) return null;
  const header = frameHeader(f);
  return header === null ? null : Buffer.concat([header, blob(f.payload)]);
}

/** Whether these bytes start with the frame magic and version. */
export function looksLikeFrame(raw: Buffer): boolean {
  return raw.length >= OFF_MSGID && raw.subarray(0, 4).equals(MAGIC) && raw.readUInt8(OFF_VERSION) === FRAME_VERSION;
}

/** Thrown inside `decodeFrame` by `FrameReader`; never escapes it. */
const MALFORMED = Symbol("malformed frame");

/** Reads length-prefixed fields from `raw`, throwing MALFORMED on anything short, oversized or empty. */
class FrameReader {
  constructor(
    private readonly raw: Buffer,
    public cursor: number,
  ) {}

  /** A non-empty `u32 len + bytes` field. */
  blob(): Buffer {
    const len = this.u32();
    if (len === 0 || len > MAX_FIELD_BYTES || this.raw.length < this.cursor + len) throw MALFORMED;
    const out = this.raw.subarray(this.cursor, this.cursor + len);
    this.cursor += len;
    return out;
  }

  u32(): number {
    if (this.raw.length < this.cursor + 4) throw MALFORMED;
    const value = this.raw.readUInt32BE(this.cursor);
    this.cursor += 4;
    return value;
  }
}

/**
 * Decodes a frame and returns the AAD as the exact header bytes received, or
 * null for anything malformed: unknown flags, broken pairing rules, empty or
 * oversized fields, invalid UTF-8, trailing bytes, or an init whose `senderPk`
 * does not hash to `sender`.
 */
export function decodeFrame(raw: Buffer): { frame: Frame; aad: Buffer } | null {
  try {
    return readFrame(raw);
  } catch (e) {
    if (e === MALFORMED) return null;
    throw e;
  }
}

function readFrame(raw: Buffer): { frame: Frame; aad: Buffer } | null {
  if (!looksLikeFrame(raw)) return null;

  const t = KIND_OF_BYTE[raw.readUInt8(OFF_KIND)];
  if (t === undefined) return null;

  const flags = raw.readUInt8(OFF_FLAGS);
  if (flags & ~ALL_FLAGS) return null;
  const hasRk = (flags & FLAG_RK) !== 0;
  const hasKemCt = (flags & FLAG_KEMCT) !== 0;
  const hasOneTime = (flags & FLAG_ONE_TIME) !== 0;
  if (t !== "init" && hasRk !== hasKemCt) return null;
  if (t === "init" && (!hasRk || hasKemCt)) return null;

  const msgIdLen = raw.readUInt8(OFF_MSGID_LEN);
  if (msgIdLen === 0 || msgIdLen > MAX_MSGID_BYTES || raw.length < OFF_MSGID + msgIdLen) return null;
  const msgIdBytes = raw.subarray(OFF_MSGID, OFF_MSGID + msgIdLen);
  // Round-trip check: toString would silently substitute U+FFFD for invalid UTF-8.
  const msgId = msgIdBytes.toString("utf8");
  if (!Buffer.from(msgId, "utf8").equals(msgIdBytes)) return null;

  const r = new FrameReader(raw, OFF_MSGID + msgIdLen);
  const rk = hasRk ? r.blob() : undefined;
  const kemCt = hasKemCt ? r.blob() : undefined;
  const init = t === "init" ? { senderPk: r.blob(), ctId: r.blob(), ctMt: r.blob() } : undefined;
  const oneTime = hasOneTime ? { ctOt: r.blob(), otId: r.u32() } : undefined;
  const headerEnd = r.cursor;
  const payload = r.blob();
  if (r.cursor !== raw.length) return null;

  const sender = raw.subarray(OFF_SENDER, OFF_SENDER + ID_BYTES).toString("hex");
  const to = raw.subarray(OFF_TO, OFF_TO + ID_BYTES).toString("hex");
  const cid = raw.subarray(OFF_CID, OFF_CID + CID_BYTES).toString("hex");
  if (!PEER_ID_RE.test(sender) || !PEER_ID_RE.test(to)) return null;
  if (init && !keyMatchesId(init.senderPk.toString("hex"), sender)) return null;

  const copy = (b: Buffer) => Buffer.from(b);
  const frame: Frame = {
    v: 3,
    t,
    sender,
    to,
    msgId,
    cid,
    n: raw.readUInt32BE(OFF_N),
    pn: raw.readUInt32BE(OFF_PN),
    payload: copy(payload),
    ...(rk ? { rk: copy(rk) } : {}),
    ...(kemCt ? { kemCt: copy(kemCt) } : {}),
    ...(init ? { senderPk: copy(init.senderPk), ctId: copy(init.ctId), ctMt: copy(init.ctMt) } : {}),
    ...(oneTime ? { ctOt: copy(oneTime.ctOt), otId: oneTime.otId } : {}),
  };
  return { frame, aad: Buffer.from(raw.subarray(0, headerEnd)) };
}
