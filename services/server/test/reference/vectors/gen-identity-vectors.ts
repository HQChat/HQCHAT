/**
 * Prints test/helpers/identity-vectors.json: client ids, id = sha256(lowercase
 * hex of the public key), for full-size and edge-case keys. Read by the
 * TypeScript and Swift identity tests.
 *
 *   npx tsx test/reference/vectors/gen-identity-vectors.ts > test/helpers/identity-vectors.json
 */

import * as crypto from "node:crypto";
import { peerId } from "../protocol/identity";

/** HQC-256 public key size (test/reference/protocol/hqc.ts). */
const PUBLIC_KEY_BYTES = 7237;

/** A deterministic key of the real HQC-256 size. */
function deterministicKey(label: string): string {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  while (Buffer.concat(out).length < PUBLIC_KEY_BYTES) {
    out.push(block);
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, PUBLIC_KEY_BYTES).toString("hex");
}

const keys = [
  {
    label: "full-size HQC-256 public key",
    publicKeyHex: deterministicKey("hqchat/identity-vector/a"),
  },
  {
    label: "a second full-size key, so the ids are known to differ",
    publicKeyHex: deterministicKey("hqchat/identity-vector/b"),
  },
  {
    label: "a short value — the digest is over the hex text, not over key bytes",
    publicKeyHex: "a1b2c3d4e5f6",
  },
  {
    label: "uppercase hex names the same client as its lowercase form",
    publicKeyHex: "A1B2C3D4E5F6",
  },
];

console.log(
  JSON.stringify(
    {
      _comment:
        "Client ids: sha256(lowercase hex public key). Regenerate with test/reference/vectors/gen-identity-vectors.ts.",
      version: 1,
      publicKeyBytes: PUBLIC_KEY_BYTES,
      keys: keys.map((k) => ({ ...k, id: peerId(k.publicKeyHex) })),
    },
    null,
    2,
  ),
);
