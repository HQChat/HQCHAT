import mqtt, { type IClientOptions, MqttClient } from "mqtt";
import type { ServerStaticPublic } from "../protocol/noise";
import { HqnStream } from "./hqn-stream";

/** Where the broker is: MQTT over WebSocket, or hqn/1 to the gateway with its pinned key. */
export type Endpoint = { url: string } | { hqn: { host: string; port: number; server: ServerStaticPublic } };

export interface TransportOptions {
  endpoint: Endpoint;
  clientId: string;
  password: string;
  /** Retained message the broker publishes if the connection drops. */
  will?: { topic: string; payload: Buffer };
  connectTimeoutMs?: number;
}

/** MQTT 5 DISCONNECT reason codes this deployment can produce. */
const DISCONNECT_REASONS: Record<number, string> = {
  130: "protocol error",
  135: "not authorized",
  137: "server busy",
  139: "server shutting down",
  141: "keepalive timeout",
  142: "session taken over by another connection with this client id",
  149: "packet too large",
};

/**
 * One MQTT 5 connection with a persistent session (an hour's expiry), so the
 * broker queues messages while the client is offline. It does not reconnect
 * on its own: every CONNECT needs a fresh signed password, so the owner opens
 * a new Transport instead. Publishes and subscribes always settle, including
 * when the broker closes the connection instead of answering.
 */
export class Transport {
  private handler: ((topic: string, payload: Buffer) => void) | null = null;
  private readonly early: Array<[string, Buffer]> = [];

  private constructor(
    private readonly client: MqttClient,
    readonly opening: () => Buffer | null,
  ) {
    client.on("message", (topic, payload) => {
      if (this.handler) this.handler(topic, payload);
      else this.early.push([topic, payload]);
    });
  }

  /** Connects and resolves on CONNACK; rejects on refusal, error or timeout. */
  static connect(o: TransportOptions): Promise<Transport> {
    const options: IClientOptions = {
      clientId: o.clientId,
      username: o.clientId,
      password: o.password,
      protocolVersion: 5,
      clean: false,
      properties: { sessionExpiryInterval: 3600 },
      reconnectPeriod: 0,
      keepalive: 30,
      connectTimeout: o.connectTimeoutMs ?? 15_000,
      ...(o.will ? { will: { topic: o.will.topic, payload: o.will.payload, qos: 1, retain: true } } : {}),
    };
    let stream: HqnStream | null = null;
    const client =
      "url" in o.endpoint
        ? mqtt.connect(o.endpoint.url, options)
        : (() => {
            const { host, port, server } = o.endpoint.hqn;
            return new MqttClient(() => {
              stream = new HqnStream(host, port, server);
              return stream as never;
            }, options);
          })();
    const transport = new Transport(client, () => stream?.opening ?? null);
    return new Promise((resolve, reject) => {
      const fail = (e: Error) => {
        client.end(true);
        reject(e);
      };
      client.once("connect", () => {
        client.removeAllListeners("error");
        client.on("error", () => {});
        resolve(transport);
      });
      client.once("error", fail);
      client.once("close", () => fail(new Error("connection closed before CONNACK")));
    });
  }

  get connected(): boolean {
    return this.client.connected;
  }

  /**
   * Delivers every inbound publish, including any the broker sent (from the
   * persistent session's queue) before this was called.
   */
  onMessage(handler: (topic: string, payload: Buffer) => void): void {
    this.handler = handler;
    for (const [topic, payload] of this.early.splice(0)) handler(topic, payload);
  }

  /** Called once when the connection ends, with the broker's reason when it gave one. */
  onClose(handler: (reason: string) => void): void {
    let reason = "connection closed";
    this.client.on("disconnect", (packet: { reasonCode?: number }) => {
      const code = packet?.reasonCode;
      if (code !== undefined) reason = DISCONNECT_REASONS[code] ?? `disconnect reason 0x${code.toString(16)}`;
    });
    this.client.once("close", () => handler(reason));
  }

  /** Subscribes at QoS 1; resolves with the topics the broker refused. */
  subscribe(topics: string[]): Promise<string[]> {
    if (!topics.length) return Promise.resolve([]);
    return this.settle(topics, (done) =>
      this.client.subscribe(topics, { qos: 1 }, (err, granted) => {
        if (err) return done(topics);
        done((granted ?? []).filter((g) => g.qos >= 0x80).map((g) => g.topic));
      }),
    );
  }

  unsubscribe(topics: string[]): Promise<void> {
    if (!topics.length || !this.client.connected) return Promise.resolve();
    return this.settle(undefined, (done) => this.client.unsubscribe(topics, () => done(undefined)));
  }

  /** Publishes at QoS 1; resolves true once the broker acknowledged it. */
  publish(topic: string, payload: Buffer | string, opts: { retain?: boolean } = {}): Promise<boolean> {
    return this.settle(false, (done) =>
      this.client.publish(topic, payload, { qos: 1, retain: opts.retain ?? false }, (err) => done(!err)),
    );
  }

  /** Ends the connection without unsubscribing, so the broker keeps the session. */
  close(): Promise<void> {
    return new Promise((resolve) => this.client.end(true, {}, () => resolve()));
  }

  /** Runs `op`, resolving with `fallback` if the connection closes or 5 s pass first. */
  private settle<T>(fallback: T, op: (done: (v: T) => void) => void): Promise<T> {
    return new Promise((resolve) => {
      if (!this.client.connected) return resolve(fallback);
      let settled = false;
      const done = (v: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.client.removeListener("close", gone);
        resolve(v);
      };
      const gone = () => done(fallback);
      const timer = setTimeout(gone, 5000);
      this.client.once("close", gone);
      op(done);
    });
  }
}
