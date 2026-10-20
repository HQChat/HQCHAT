import * as path from "node:path";
import { Worker } from "node:worker_threads";

/**
 * A fixed pool of decapsulation workers behind a BOUNDED queue.
 *
 * Bounded is the point: every queued job is a well-formed handshake from
 * somewhere on the internet, and an unbounded queue under a burst is memory
 * growth plus handshakes that time out anyway after waiting. When the queue is
 * full the job is refused at once and the gateway closes that connection —
 * the client's fallback to WSS handles it, and everyone already connected is
 * unaffected.
 *
 * A worker that dies fails only the job it was running and is replaced, so the
 * pool keeps its size and no later job is sent to a dead worker.
 */
interface Slot {
  w: Worker;
  /** The job this worker is running, or null when idle. */
  job: number | null;
}

export class DecapPool {
  private workers: Slot[] = [];
  private queue: { id: number; keyId: number; ct: Buffer }[] = [];
  private waiting = new Map<number, { resolve: (b: Buffer) => void; reject: (e: Error) => void }>();
  private nextId = 1;
  private closing = false;
  /** Workers replaced after dying; for health and tests. */
  respawned = 0;

  constructor(
    private readonly keys: { keyId: number; sk: Buffer }[],
    readonly size: number,
    readonly queueMax: number,
    private readonly workerFile = path.join(__dirname, "decap-worker.ts"),
  ) {
    for (let i = 0; i < size; i++) {
      const slot: Slot = { w: this.spawn(), job: null };
      this.workers.push(slot);
      this.attach(slot);
    }
  }

  private spawn(): Worker {
    // Workers do not inherit the `--import tsx` hook, so a CommonJS
    // bootstrap registers tsx before loading the TypeScript worker.
    return this.workerFile.endsWith(".ts")
      ? new Worker(`require("tsx/cjs/api").register(); require(${JSON.stringify(this.workerFile)});`, {
          eval: true,
          workerData: { keys: this.keys },
        })
      : new Worker(this.workerFile, { workerData: { keys: this.keys } });
  }

  private settle(id: number | null, outcome: { ss: Buffer } | { error: Error }): void {
    if (id === null) return;
    const p = this.waiting.get(id);
    this.waiting.delete(id);
    if (!p) return;
    if ("ss" in outcome) p.resolve(outcome.ss);
    else p.reject(outcome.error);
  }

  private attach(slot: Slot): void {
    const w = slot.w;
    let dead = false;
    w.on("message", (m: { id: number; ss?: Uint8Array; error?: string }) => {
      slot.job = null;
      this.settle(m.id, m.ss ? { ss: Buffer.from(m.ss) } : { error: new Error(m.error ?? "decapsulation failed") });
      this.dispatch();
    });
    const died = (e: Error) => {
      if (dead) return;
      dead = true;
      this.settle(slot.job, { error: e });
      slot.job = null;
      if (this.closing) return;
      slot.w = this.spawn();
      this.respawned++;
      this.attach(slot);
      this.dispatch();
    };
    w.on("error", (e) => died(e as Error));
    w.on("exit", (code) => died(new Error(`decapsulation worker exited (${code})`)));
  }

  decapsulate(keyId: number, ct: Buffer): Promise<Buffer> {
    if (this.queue.length >= this.queueMax) return Promise.reject(new Error("decapsulation queue full"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      this.queue.push({ id, keyId, ct });
      this.dispatch();
    });
  }

  private dispatch(): void {
    for (const slot of this.workers) {
      if (slot.job !== null) continue;
      const job = this.queue.shift();
      if (!job) return;
      slot.job = job.id;
      slot.w.postMessage(job);
    }
  }

  get queued(): number {
    return this.queue.length;
  }

  async close(): Promise<void> {
    this.closing = true;
    await Promise.all(this.workers.map((s) => s.w.terminate()));
  }
}
