import type { GatewayKeyPair, HqnSecret } from "../common/core";

/**
 * A BOUNDED queue in front of HQC decapsulation.
 *
 * Bounded is the point: every queued job is a well-formed handshake from
 * somewhere on the internet, and an unbounded queue under a burst is memory
 * growth plus handshakes that time out anyway after waiting. When the queue is
 * full the job is refused at once and the gateway closes that connection —
 * the client's fallback to WSS handles it, and everyone already connected is
 * unaffected.
 *
 * The decapsulation itself is the core's (`GatewayKeyPair.decapsulate`): it
 * runs on libuv's thread pool against the key Rust holds, and hands back a
 * handle, so neither the HQC secret key nor any shared secret is ever in the
 * JS heap. `size` caps how many run at once; libuv's pool (UV_THREADPOOL_SIZE)
 * bounds how many run in parallel.
 */
export class DecapPool {
  private running = 0;
  private queue: { key: GatewayKeyPair; ct: Buffer; resolve: (s: HqnSecret) => void; reject: (e: Error) => void }[] =
    [];

  constructor(
    private readonly keys: Map<number, GatewayKeyPair>,
    readonly size: number,
    readonly queueMax: number,
  ) {}

  decapsulate(keyId: number, ct: Buffer): Promise<HqnSecret> {
    if (this.queue.length >= this.queueMax) return Promise.reject(new Error("decapsulation queue full"));
    const key = this.keys.get(keyId);
    if (!key) return Promise.reject(new Error("unknown key id"));
    return new Promise((resolve, reject) => {
      this.queue.push({ key, ct, resolve, reject });
      this.dispatch();
    });
  }

  private dispatch(): void {
    while (this.running < this.size) {
      const job = this.queue.shift();
      if (!job) return;
      this.running++;
      let started: Promise<HqnSecret>;
      try {
        started = job.key.decapsulate(job.ct);
      } catch (e) {
        started = Promise.reject(e as Error);
      }
      started
        .then(job.resolve, (e: Error) => job.reject(e))
        .finally(() => {
          this.running--;
          this.dispatch();
        });
    }
  }

  get queued(): number {
    return this.queue.length;
  }

  async close(): Promise<void> {
    for (const job of this.queue.splice(0)) job.reject(new Error("closing"));
  }
}
