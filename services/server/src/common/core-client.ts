import * as net from "node:net";
import { type CoreEffect, type CoreMessage, core, type Engine, type EngineOptions } from "./core";

/**
 * A headless HQChat client on the Rust core: the Node shell around the core's
 * Engine (docs/architecture/core-wiring.md). The engine decides everything —
 * sign-in, the friend graph, the broker session, the ratchet — and this class
 * only carries out its effects: HTTP through fetch, the broker connection over
 * a TCP socket (hqn/1) or a WebSocket, one timer, and events for the program
 * on top (the bot, the scenarios).
 */
export interface CoreClientOptions extends EngineOptions {
  /** Where WSS connections go instead of `${serverUrl}/mqtt`: a stack whose
   *  broker listens elsewhere (local runs, the bot's private path). */
  wssUrl?: string;
  /** Named to the engine as the network, so a failed hqn/1 is remembered per network. */
  network?: string;
  /** Bound on each HTTP request. */
  httpTimeoutMs?: number;
  log?: (line: string) => void;
}

type Conn = { write: (b: Buffer) => void; close: () => void };

const NO_BODY = Buffer.alloc(0);

export class CoreClient {
  readonly engine: Engine;
  private readonly conns = new Map<number, Conn>();
  private timer: NodeJS.Timeout | null = null;
  private stopped = false;
  private readonly messageHandlers: ((m: CoreMessage) => void)[] = [];
  private readonly effectHandlers: ((e: CoreEffect) => void)[] = [];

  constructor(private readonly o: CoreClientOptions) {
    this.engine = new core.Engine(o);
  }

  /** The device key to keep for the next run; null before an identity exists. */
  get deviceKey(): Buffer | null {
    return this.engine.deviceKey;
  }

  /** Called for every message from a friend, once it is opened and stored. */
  onMessage(fn: (m: CoreMessage) => void): void {
    this.messageHandlers.push(fn);
  }

  /** Called for every effect after it is carried out (friends, invites, statuses, …). */
  onEffect(fn: (e: CoreEffect) => void): void {
    this.effectHandlers.push(fn);
  }

  /** Signs in and connects, or asks for an unlock first. */
  start(): void {
    this.stopped = false;
    this.run(() => this.engine.start(Date.now(), this.o.network ?? "server"));
  }

  /** Sends `text` to `peer`; returns the message id. */
  send(peer: string, text: string): string {
    const effects = this.engine.sendText(peer, text, Date.now());
    const added = effects.find((e) => e.kind === "messageAdded")?.message?.msgId;
    this.handle(effects);
    if (!added) throw new Error("the core accepted the message without adding it");
    return added;
  }

  /** Runs an engine command and carries out what it returns. */
  run(command: () => CoreEffect[]): void {
    let effects: CoreEffect[];
    try {
      effects = command();
    } catch (e) {
      this.o.log?.(`core: ${(e as Error).message}`);
      return;
    }
    this.handle(effects);
  }

  /** Closes every connection and stops the timer; the engine keeps its state. */
  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    for (const c of this.conns.values()) c.close();
    this.conns.clear();
  }

  private handle(effects: CoreEffect[]): void {
    for (const e of effects) {
      this.carryOut(e);
      if (e.kind === "messageAdded" && e.message && !e.message.outgoing) {
        for (const fn of this.messageHandlers) fn(e.message);
      }
      for (const fn of this.effectHandlers) fn(e);
    }
  }

  private carryOut(e: CoreEffect): void {
    switch (e.kind) {
      case "http":
        void this.http(e);
        return;
      case "open":
        if (!this.stopped) this.open(e);
        return;
      case "write":
        this.conns.get(e.conn!)?.write(e.body ?? NO_BODY);
        return;
      case "close": {
        // The engine closed it itself: no onClosed back.
        const c = this.conns.get(e.conn!);
        this.conns.delete(e.conn!);
        c?.close();
        return;
      }
      case "timer":
        this.schedule(e.at!);
        return;
      case "needUnlock":
        // Headless: the device key is a software key held by this process.
        this.run(() => this.engine.unlock(Date.now()));
        return;
      case "dropped":
        this.o.log?.(`dropped: ${e.reason}`);
        return;
      case "storageFailed":
        this.o.log?.(`storage failed: ${e.reason}`);
        return;
      case "actionFailed":
        this.o.log?.(`${e.action} failed: ${e.status} ${e.code}`);
        return;
      default:
        return;
    }
  }

  private async http(e: CoreEffect): Promise<void> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (e.authorization) headers.authorization = `Bearer ${e.authorization}`;
    let status = 0;
    let body = NO_BODY;
    try {
      const res = await fetch(`${this.o.serverUrl}${e.path}`, {
        method: e.method ?? "GET",
        headers,
        ...(e.method === "GET" ? {} : { body: new Uint8Array(e.body ?? NO_BODY) }),
        signal: AbortSignal.timeout(this.o.httpTimeoutMs ?? 15_000),
      });
      status = res.status;
      body = Buffer.from(await res.arrayBuffer());
    } catch (err) {
      // Unreachable: the engine reads status 0 as "could not reach the server".
      this.o.log?.(`${e.method} ${e.path}: ${(err as Error).message}`);
    }
    this.run(() => this.engine.onHttp(e.req!, status, body, Date.now()));
  }

  private open(e: CoreEffect): void {
    const id = e.conn!;
    const closed = (reason: string) => {
      if (!this.conns.has(id)) return;
      this.conns.delete(id);
      this.run(() => this.engine.onClosed(id, reason, Date.now()));
    };
    if (e.transport === "tcp") {
      const sock = net.connect({ host: e.host!, port: e.port!, noDelay: true });
      let failed = false;
      sock.on("connect", () => this.run(() => this.engine.onOpened(id, Date.now())));
      sock.on("data", (chunk: Buffer) => this.run(() => this.engine.onBytes(id, chunk, Date.now())));
      sock.on("error", (err) => {
        failed = true;
        this.o.log?.(`tcp ${e.host}:${e.port}: ${err.message}`);
      });
      sock.on("close", () => closed(failed ? "failed" : "remote"));
      this.conns.set(id, { write: (b) => sock.write(b), close: () => sock.destroy() });
      return;
    }
    const url = this.o.wssUrl ?? e.url!;
    const ws = new WebSocket(url, ["mqtt"]);
    ws.binaryType = "arraybuffer";
    let failed = false;
    ws.onopen = () => this.run(() => this.engine.onOpened(id, Date.now()));
    ws.onmessage = (m) => {
      const bytes = Buffer.from(m.data as ArrayBuffer);
      this.run(() => this.engine.onBytes(id, bytes, Date.now()));
    };
    ws.onerror = () => {
      failed = true;
    };
    ws.onclose = () => closed(failed ? "failed" : "remote");
    this.conns.set(id, { write: (b) => ws.send(b), close: () => ws.close() });
  }

  private schedule(at: number): void {
    if (this.stopped) return;
    if (this.timer) clearTimeout(this.timer);
    // setTimeout holds at most 2^31 - 1 ms; the engine re-arms when woken early.
    const wait = Math.min(Math.max(0, at - Date.now()), 2 ** 31 - 1);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.run(() => this.engine.tick(Date.now()));
    }, wait);
  }
}
