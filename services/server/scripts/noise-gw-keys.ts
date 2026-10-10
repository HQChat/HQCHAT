// Generates a noise-gw key: the SECRET seed file the gateway loads, and the
// PUBLIC keys the app pins.
//
//   npx tsx scripts/noise-gw-keys.ts --key-id 1 --secret keys.json [--public pub.json]
//
// Appends to an existing secret file (rotation holds two key ids at once); an
// empty file counts as none.
// Refuses to overwrite an existing key id.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { loadServerKeys, parseKeySeeds, publicKeys } from "../src/gateway/keys";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const keyId = Number(arg("--key-id") ?? "1");
const secretFile = arg("--secret");
if (!secretFile) {
  console.error("--secret <file> is required");
  process.exit(2);
}

const current = fs.existsSync(secretFile) ? fs.readFileSync(secretFile, "utf8").trim() : "";
const existing: { keys: Array<{ keyId: number; x25519: string; hqcSeed: string }> } = current
  ? JSON.parse(current)
  : { keys: [] };
if (existing.keys.some((k) => Number(k.keyId) === keyId)) {
  console.error(`key id ${keyId} already exists in ${secretFile}`);
  process.exit(1);
}
existing.keys.push({
  keyId,
  x25519: crypto.randomBytes(32).toString("hex"),
  hqcSeed: crypto.randomBytes(32).toString("hex"),
});
fs.writeFileSync(secretFile, `${JSON.stringify(existing, null, 2)}\n`, { mode: 0o600 });

const pub = { keys: publicKeys(loadServerKeys(parseKeySeeds(JSON.stringify(existing)))) };
const publicFile = arg("--public");
if (publicFile) fs.writeFileSync(publicFile, `${JSON.stringify(pub, null, 2)}\n`);
else process.stdout.write(`${JSON.stringify(pub, null, 2)}\n`);
