/**
 * HQC-256 decapsulation, off the gateway's event loop.
 *
 * The core's call is synchronous and takes milliseconds; on the main thread one
 * burst of handshakes would stall every established stream the process
 * carries. The secret keys arrive once, in workerData, and never leave.
 */
import { parentPort, workerData } from "node:worker_threads";
import { core } from "../common/core";

const secretKeys = new Map<number, Buffer>(
  (workerData.keys as { keyId: number; sk: Uint8Array }[]).map((k) => [k.keyId, Buffer.from(k.sk)]),
);

parentPort!.on("message", (m: { id: number; keyId: number; ct: Uint8Array }) => {
  const sk = secretKeys.get(m.keyId);
  try {
    if (!sk) throw new Error("unknown key id");
    const ss = core.hqcDecapsulate(sk, Buffer.from(m.ct));
    parentPort!.postMessage({ id: m.id, ss });
  } catch (e) {
    parentPort!.postMessage({ id: m.id, error: (e as Error).message });
  }
});
