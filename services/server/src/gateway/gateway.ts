import * as net from "node:net";
import {
  FrameReader,
  frame,
  HQN_VERSION,
  HqnResponder,
  msg1Length,
  NoiseError,
  type ServerStatic,
  sealFrames,
  type Transport,
} from "../protocol/noise";
import { Admission } from "./admission";
import { connectClientId } from "./mqtt-connect";

/**
 * noise-gw: terminates hqn/1 (protocol/noise.ts) and pipes the decrypted MQTT byte
 * stream to EMQX's internal plain-TCP listener.
 *
 * This process is the first thing on the public internet that reads a raw-TCP
 * client's bytes, before any authentication, so everything here is shaped by
 * what an attacker can make it do:
 *
 *   - Nothing is buffered beyond one message. The opening is two header bytes,
 *     then ONE length-prefixed msg1 whose length must fall in the window a real
 *     CONNECT can produce; anything else is closed before any cryptography.
 *   - The expensive step — HQC-256 decapsulation — is reached only by a msg1
 *     whose encrypted KEM ciphertext already OPENED under the X25519 key. Random
 *     bytes fail that AEAD tag for the price of one X25519 and never cost a
 *     decapsulation. (A real Noise client can still spend one decapsulation per
 *     handshake; that is what the per-IP handshake rate is for.)
 *   - Decapsulation runs off the event loop (`decapsulate` is async; main.ts
 *     backs it with a worker pool) behind a bounded queue, so a burst of
 *     well-formed handshakes sheds load instead of stalling every established
 *     stream on this process.
 *   - Every failure is a silent close. No error frame, no timing difference
 *     worth measuring, nothing that tells a prober which check it failed.
 *   - A msg1 whose ephemeral key was seen within the replay window is refused.
 *     It cannot yield a session (msg2 is keyed by ee), but it would forward a
 *     CONNECT, which the proof's single-use nonce also refuses.
 */

export interface GatewayOptions {
  /** Loaded server key pairs, by key id. */
  keys: Map<number, ServerStatic>;
  /** HQC-256 decapsulation, off the event loop. Rejects when overloaded. */
  decapsulate: (keyId: number, ct: Buffer) => Promise<Buffer>;
  /** Where the decrypted stream goes: EMQX's internal plain-TCP listener. */
  upstream: { host: string; port: number };
  limits?: Partial<GatewayLimits>;
  /** Clock, for the rate windows. */
  now?: () => number;
  /** Observability hook; never passed secrets. */
  onEvent?: (e: GatewayEvent) => void;
}

export interface GatewayLimits {
  /** Largest CONNECT accepted inside msg1. A real one is well under 1 kB. */
  maxConnectBytes: number;
  /** Time from accept to a complete msg1. */
  handshakeTimeoutMs: number;
  /** Handshakes in progress from one address. */
  perIpHandshakes: number;
  /** Established streams from one address — high, because carrier NAT puts
   *  thousands of phones behind one IPv4 address. */
  perIpConnections: number;
  /** Handshakes STARTED per address per minute (each may cost a decapsulation). */
  perIpHandshakesPerMinute: number;
  /** Handshakes in progress across the whole process. */
  maxHalfOpen: number;
  /** How long a client ephemeral key is remembered for replay refusal. */
  replayWindowMs: number;
  /** Cap on remembered ephemerals, so the cache cannot be grown without bound. */
  replayCacheMax: number;
}

export const DEFAULT_LIMITS: GatewayLimits = {
  maxConnectBytes: 4096,
  handshakeTimeoutMs: 5000,
  perIpHandshakes: 8,
  perIpConnections: 512,
  perIpHandshakesPerMinute: 120,
  maxHalfOpen: 1024,
  replayWindowMs: 120_000,
  replayCacheMax: 200_000,
};

export type GatewayEvent =
  | { t: "refused"; reason: RefusalReason; ip: string }
  | { t: "established"; ip: string; clientId: string | null; handshakeMs: number }
  | { t: "closed"; ip: string; clientId: string | null; bytesUp: number; bytesDown: number };

export type RefusalReason =
  | "header"
  | "length"
  | "timeout"
  | "ip-handshakes"
  | "ip-rate"
  | "ip-connections"
  | "half-open"
  | "replay"
  | "noise"
  | "overloaded"
  | "upstream"
  | "stream";

export interface GatewayStats {
  halfOpen: number;
  established: number;
  refused: Record<RefusalReason, number>;
  replayCacheSize: number;
}

/** One accepted socket, from accept to close. */
interface Connection {
  sock: net.Socket;
  ip: string;
  started: number;
  /** Ends the handshake accounting; idempotent. */
  leaveHandshake: () => void;
  timer: NodeJS.Timeout;
}

/** The hqn/1 front door: admission, the handshake, then the decrypted pipe to EMQX. */
class Gateway {
  private readonly limits: GatewayLimits;
  private readonly now: () => number;
  private readonly admission: Admission;
  private readonly msg1Window: { min: number; max: number };

  constructor(private readonly opts: GatewayOptions) {
    this.limits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
    this.now = opts.now ?? Date.now;
    this.admission = new Admission(this.limits, this.now);
    this.msg1Window = { min: msg1Length(0), max: msg1Length(this.limits.maxConnectBytes) };
  }

  private refuse(sock: net.Socket, ip: string, reason: RefusalReason): void {
    this.admission.countRefusal(reason);
    this.opts.onEvent?.({ t: "refused", reason, ip });
    sock.destroy();
  }

  stats(): GatewayStats {
    return this.admission.stats();
  }

  accept(sock: net.Socket) {
    const ip = sock.remoteAddress ?? "?";
    const refusal = this.admission.refusalFor(ip);
    if (refusal) return this.refuse(sock, ip, refusal);

    const leaveHandshake = this.admission.startHandshake(ip);
    sock.once("close", leaveHandshake);
    sock.on("error", () => {
      /* a reset client is not an event worth logging */
    });
    const timer = setTimeout(() => this.refuse(sock, ip, "timeout"), this.limits.handshakeTimeoutMs);
    sock.once("close", () => clearTimeout(timer));

    const conn: Connection = { sock, ip, started: this.now(), leaveHandshake, timer };
    this.readMessage1(conn, (keyId, msg1) => void this.handshake(conn, keyId, msg1));
  }

  /** Buffers the two header bytes and exactly one length-prefixed msg1, refusing anything else. */
  private readMessage1(conn: Connection, done: (keyId: number, msg1: Buffer) => void) {
    const { sock, ip } = conn;
    let buf: Buffer = Buffer.alloc(0);
    let keyId = -1;
    let need = 2;
    const onData = (chunk: Buffer) => {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      if (keyId < 0) {
        if (buf.length < 2) return;
        if (buf[0] !== HQN_VERSION || !this.opts.keys.has(buf[1]!)) return this.refuse(sock, ip, "header");
        keyId = buf[1]!;
        buf = buf.subarray(2);
      }
      if (need === 2) {
        if (buf.length < 2) return;
        const len = buf.readUInt16BE(0);
        if (len < this.msg1Window.min || len > this.msg1Window.max) return this.refuse(sock, ip, "length");
        need = 2 + len;
      }
      if (buf.length > need) return this.refuse(sock, ip, "length"); // nothing may follow msg1 before msg2
      if (buf.length < need) return;
      sock.off("data", onData);
      sock.pause();
      done(keyId, buf.subarray(2));
    };
    sock.on("data", onData);
  }

  /** Opens the KEM ciphertext, decapsulates off the event loop and answers with msg2. */
  private async handshake(conn: Connection, keyId: number, msg1: Buffer): Promise<void> {
    const { sock, ip } = conn;
    if (!this.admission.freshEphemeral(HqnResponder.ephemeralOf(msg1))) return this.refuse(sock, ip, "replay");
    const responder = new HqnResponder(this.opts.keys.get(keyId)!);
    let ct: Buffer;
    try {
      ct = responder.openMessage1(msg1);
    } catch {
      return this.refuse(sock, ip, "noise");
    }
    let ss: Buffer;
    try {
      ss = await this.opts.decapsulate(keyId, ct);
    } catch {
      return this.refuse(sock, ip, "overloaded");
    }
    if (sock.destroyed) return;
    let connect: Buffer;
    let transport: Transport;
    let msg2: Buffer;
    try {
      connect = responder.finishMessage1(ss);
      ({ message: msg2, transport } = responder.writeMessage2(Buffer.alloc(0)));
    } catch (e) {
      if (!(e instanceof NoiseError)) throw e;
      return this.refuse(sock, ip, "noise");
    }
    clearTimeout(conn.timer);
    this.pipe(conn, connect, msg2, transport);
  }

  /** Pipes the decrypted MQTT stream to EMQX and back. */
  private pipe(conn: Connection, connect: Buffer, msg2: Buffer, t: Transport) {
    const { sock, ip } = conn;
    const clientId = connectClientId(connect);
    const up = net.connect({ host: this.opts.upstream.host, port: this.opts.upstream.port, noDelay: true });
    let bytesUp = 0;
    let bytesDown = 0;
    let open = false;
    const closeBoth = () => {
      sock.destroy();
      up.destroy();
    };

    up.on("error", () => {
      if (!open) return this.refuse(sock, ip, "upstream");
      closeBoth();
    });
    up.once("connect", () => {
      open = true;
      conn.leaveHandshake();
      this.admission.connectionOpened(ip);
      this.opts.onEvent?.({ t: "established", ip, clientId, handshakeMs: this.now() - conn.started });
      // msg2 goes out without waiting for CONNACK, which then follows as the
      // first transport frame: the client's connect costs no extra round trip.
      sock.write(frame(msg2));
      up.write(connect);
      bytesUp += connect.length;
      sock.resume();
    });

    const reader = new FrameReader();
    sock.on("data", (chunk: Buffer) => {
      reader.push(chunk);
      try {
        for (let f = reader.next(); f; f = reader.next()) {
          const pt = t.recv.decryptWithAd(Buffer.alloc(0), f);
          bytesUp += pt.length;
          if (!up.write(pt)) sock.pause();
        }
      } catch {
        this.admission.countRefusal("stream");
        closeBoth();
      }
    });
    up.on("drain", () => sock.resume());

    up.on("data", (chunk: Buffer) => {
      bytesDown += chunk.length;
      if (!sock.write(sealFrames(t.send, chunk))) up.pause();
    });
    sock.on("drain", () => up.resume());

    let counted = false;
    const onClose = () => {
      closeBoth();
      if (!open || counted) return;
      counted = true;
      this.admission.connectionClosed(ip);
      this.opts.onEvent?.({ t: "closed", ip, clientId, bytesUp, bytesDown });
    };
    sock.once("close", onClose);
    up.once("close", onClose);
  }
}

export function createGateway(opts: GatewayOptions): { server: net.Server; stats: () => GatewayStats } {
  const gateway = new Gateway(opts);
  return {
    server: net.createServer({ noDelay: true, pauseOnConnect: false }, (sock) => gateway.accept(sock)),
    stats: () => gateway.stats(),
  };
}
