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
 */
export class DecapPool {
  private workers: { w: Worker; busy: boolean }[] = [];
  private queue: { id: number; keyId: number; ct: Buffer }[] = [];
  private waiting = new Map<number, { resolve: (b: Buffer) => void; reject: (e: Error) => void }>();
  private nextId = 1;

  constructor(
    keys: { keyId: number; sk: Buffer }[],
    readonly size: number,
    readonly queueMax: number,
    workerFile = path.join(__dirname, "decap-worker.ts"),
  ) {
    for (let i = 0; i < size; i++) {
      // Workers do not inherit the `--import tsx` hook, so a CommonJS
      // bootstrap registers tsx before loading the TypeScript worker.
      const w = workerFile.endsWith(".ts")
        ? new Worker(`require("tsx/cjs/api").register(); require(${JSON.stringify(workerFile)});`, {
            eval: true,
            workerData: { keys },
          })
        : new Worker(workerFile, { workerData: { keys } });
      const slot = { w, busy: false };
      w.on("message", (m: { id: number; ss?: Uint8Array; error?: string }) => {
        slot.busy = false;
        const p = this.waiting.get(m.id);
        this.waiting.delete(m.id);
        if (p) m.ss ? p.resolve(Buffer.from(m.ss)) : p.reject(new Error(m.error ?? "decapsulation failed"));
        this.dispatch();
      });
      w.on("error", (e) => {
        // A dead worker fails only its in-flight job.
        slot.busy = false;
        for (const [id, p] of this.waiting) {
          p.reject(e as Error);
          this.waiting.delete(id);
        }
      });
      this.workers.push(slot);
    }
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
      if (slot.busy) continue;
      const job = this.queue.shift();
      if (!job) return;
      slot.busy = true;
      slot.w.postMessage(job);
    }
  }

  get queued(): number {
    return this.queue.length;
  }

  async close(): Promise<void> {
    await Promise.all(this.workers.map((s) => s.w.terminate()));
  }
}
