import type { Frame } from "../protocol/envelope";
import { hqcKem } from "../protocol/hqc";
import type { Kem } from "../protocol/ratchet";
import { graphTopic, presenceTopic } from "../protocol/topics";
import { Api } from "./api";
import { Auth } from "./auth";
import { Conversations, type Message } from "./conversation";
import type { Identity } from "./identity";
import { MemoryStore, type Store } from "./store";
import { type Endpoint, Transport } from "./transport";

export interface ClientOptions {
  /** The server's HTTPS origin, e.g. https://hqchat.app. */
  baseUrl: string;
  /** The broker, over WSS or hqn/1. */
  endpoint: Endpoint;
  identity: Identity;
  store?: Store;
  kem?: Kem;
  /** Reconnect with fresh credentials whenever the connection drops. */
  reconnect?: boolean;
  log?: (line: string) => void;
}

const PRESENCE_ONLINE = Buffer.from(JSON.stringify({ s: "online" }));
const PRESENCE_OFFLINE = Buffer.from(JSON.stringify({ s: "offline" }));
const MAX_RELINK_MS = 30_000;

/**
 * A complete HQChat client over the public API only: REST for sign-in and the
 * friend graph, MQTT for conversations.
 *
 *   const c = new Client({ baseUrl, endpoint: { url: "wss://…/mqtt" }, identity });
 *   await c.signIn();
 *   await c.connect();
 *   c.onMessage((m) => c.send(m.from, `you said ${m.text}`));
 *
 * The friend graph is re-read whenever the server nudges `u/{id}/graph`, and
 * on `sync()`.
 */
export class Client {
  readonly auth: Auth;
  readonly api: Api;
  readonly conversations: Conversations;
  /** Why inbound frames were dropped, oldest first. */
  readonly drops: string[] = [];
  private transport: Transport | null = null;
  private readonly inbox: Message[] = [];
  private readonly messageHandlers: Array<(m: Message) => void> = [];
  private graphHandler: () => Promise<void>;
  private closed = false;
  private relinkDelay = 2_000;

  constructor(private readonly o: ClientOptions) {
    this.auth = new Auth(o.baseUrl, o.identity);
    this.api = new Api(o.baseUrl, this.auth);
    this.conversations = new Conversations({
      identity: o.identity,
      kem: o.kem ?? hqcKem,
      api: this.api,
      store: o.store ?? new MemoryStore(),
    });
    this.graphHandler = () => this.sync();
  }

  get id(): string {
    return this.o.identity.id;
  }

  get connected(): boolean {
    return this.transport?.connected ?? false;
  }

  /** The bytes this client opened its last hqn/1 connection with. */
  get hqnOpening(): Buffer | null {
    return this.transport?.opening() ?? null;
  }

  private log(line: string): void {
    this.o.log?.(line);
  }

  /** Signs in and reads the friend graph. */
  async signIn(): Promise<void> {
    await this.auth.signIn();
    await this.sync();
  }

  /** Re-reads `/friends` and updates subscriptions on a live connection. */
  async sync(): Promise<void> {
    const { subscribe, unsubscribe } = this.conversations.applyFriends(await this.api.friends());
    if (!this.transport) return;
    await this.transport.unsubscribe(unsubscribe);
    const refused = await this.transport.subscribe(subscribe);
    if (refused.length) this.log(`broker refused ${refused.join(", ")}`);
  }

  /** Replaces what happens on a graph nudge (by default, `sync()`). */
  onGraphChanged(handler: () => Promise<void>): void {
    this.graphHandler = handler;
  }

  /** Delivers every decrypted message, in addition to `next()`. */
  onMessage(handler: (m: Message) => void): void {
    this.messageHandlers.push(handler);
  }

  /**
   * Connects to the broker, subscribes to the inbox, the graph nudge and
   * every friendship's topics, announces presence and keeps the prekey bundle
   * published.
   */
  async connect(): Promise<void> {
    this.closed = false;
    const t = await Transport.connect({
      endpoint: this.o.endpoint,
      clientId: this.id,
      password: this.auth.mqttPassword(),
      will: { topic: presenceTopic(this.id), payload: PRESENCE_OFFLINE },
    });
    this.transport = t;
    this.relinkDelay = 2_000;
    t.onMessage((topic, payload) => void this.handle(topic, payload));
    t.onClose((reason) => this.onClosed(t, reason));
    const refused = await t.subscribe([...this.conversations.subscriptions(), graphTopic(this.id)]);
    if (refused.length) throw new Error(`broker refused subscriptions: ${refused.join(", ")}`);
    await t.publish(presenceTopic(this.id), PRESENCE_ONLINE, { retain: true });
    await this.conversations.ensurePrekeys();
  }

  /** Seals and publishes a message to a friend; returns the frame sent. */
  async send(peerId: string, text: string): Promise<Frame> {
    if (!this.transport?.connected) throw new Error("not connected");
    const { frame, outbound } = await this.conversations.seal(peerId, text);
    if (!(await this.transport.publish(outbound.topic, outbound.payload))) {
      throw new Error(`publish to ${outbound.topic} was not acknowledged`);
    }
    return frame;
  }

  /** Publishes raw bytes; true once the broker acknowledged them. */
  publish(topic: string, payload: Buffer | string): Promise<boolean> {
    return this.transport?.publish(topic, payload) ?? Promise.resolve(false);
  }

  /** Subscribes to arbitrary topics; resolves with those the broker refused. */
  subscribe(topics: string[]): Promise<string[]> {
    return this.transport?.subscribe(topics) ?? Promise.resolve(topics);
  }

  /** The next unread message (from `from`, when given), waiting up to `timeoutMs`. */
  async next(from?: string, timeoutMs = 8000): Promise<Message> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const i = this.inbox.findIndex((m) => from === undefined || m.from === from);
      if (i !== -1) return this.inbox.splice(i, 1)[0]!;
      await new Promise((r) => setTimeout(r, 25));
    }
    const why = this.drops.length ? `dropped: ${this.drops.join("; ")}` : "nothing arrived";
    throw new Error(`no message${from ? ` from ${from.slice(0, 12)}…` : ""} within ${timeoutMs}ms (${why})`);
  }

  /** Closes the connection, keeping the broker session so messages queue meanwhile. */
  async close(): Promise<void> {
    this.closed = true;
    const t = this.transport;
    this.transport = null;
    await t?.close();
  }

  private async handle(topic: string, payload: Buffer): Promise<void> {
    if (topic === graphTopic(this.id)) {
      await this.graphHandler().catch((e: Error) => this.log(`graph sync failed: ${e.message}`));
      return;
    }
    // receive() is synchronous, so frames are decided in arrival order. Deliver
    // before awaiting any publish: handlers run concurrently, and a frame that
    // releases held messages (a handshake proof) must not let a later frame's
    // message overtake them while its receipts are in flight.
    const r = this.conversations.receive(topic, payload);
    if (r.dropped) {
      this.drops.push(r.dropped);
      this.log(`dropped: ${r.dropped}`);
    }
    for (const m of r.messages) {
      this.inbox.push(m);
      for (const h of this.messageHandlers) h(m);
    }
    for (const out of r.outbound) await this.transport?.publish(out.topic, out.payload);
  }

  private onClosed(t: Transport, reason: string): void {
    if (this.transport !== t) return;
    this.transport = null;
    if (!this.closed && this.o.reconnect) this.relink(reason);
  }

  /** Reconnects with fresh credentials after an exponential backoff. */
  private relink(reason: string): void {
    const delay = this.relinkDelay;
    this.relinkDelay = Math.min(MAX_RELINK_MS, delay * 2);
    this.log(`connection lost (${reason}); reconnecting in ${delay}ms`);
    setTimeout(() => {
      void (async () => {
        if (this.closed || this.transport) return;
        try {
          await this.auth.renew();
          await this.sync();
          await this.connect();
        } catch (e) {
          this.log(`reconnect failed: ${(e as Error).message}`);
          if (!this.closed && !this.transport) this.relink("reconnect failed");
        }
      })();
    }, delay).unref();
  }
}
