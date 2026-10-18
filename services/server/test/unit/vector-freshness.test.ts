// The committed cross-implementation vectors still match their generators.
//
// Both suites read these files, so a generator change without a regeneration
// would leave both agreeing with a file that describes neither implementation.
// This is also what makes excluding `scripts/gen-*.ts` from coverage honest.
//
// Every generator is deterministic, so this is a byte comparison.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

const ROOT = path.join(__dirname, "..", "..");

const VECTORS: Array<{ generator: string; file: string }> = [
  { generator: "test/reference/vectors/gen-identity-vectors.ts", file: "test/helpers/identity-vectors.json" },
  { generator: "test/reference/vectors/gen-envelope-v3-vectors.ts", file: "test/helpers/envelope-v3-vectors.json" },
  { generator: "test/reference/vectors/gen-handshake-vectors.ts", file: "test/helpers/handshake-vectors.json" },
  { generator: "test/reference/vectors/gen-ratchet-vectors.ts", file: "test/helpers/double-ratchet-vectors.json" },
  { generator: "test/reference/vectors/gen-mqtt-proof-vectors.ts", file: "test/helpers/mqtt-proof-vectors.json" },
  { generator: "test/reference/vectors/gen-noise-hqn-vectors.ts", file: "test/helpers/noise-hqn-vectors.json" },
];

function generate(generator: string): string {
  return execFileSync("npx", ["tsx", generator], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

for (const { generator, file } of VECTORS) {
  test(`${path.basename(file)} is what its generator produces`, () => {
    const committed = fs.readFileSync(path.join(ROOT, file), "utf8");
    const fresh = generate(generator);
    assert.equal(
      fresh.trim(),
      committed.trim(),
      `${file} is stale.\n` +
        `Both suites are asserting against a file that no longer matches ${generator}, ` +
        `so they agree with each other for the wrong reason.\n` +
        `Regenerate it:  npx tsx ${generator} > ${file}`,
    );
  });
}

test("every generator has a committed file, and every file has a generator", () => {
  // A generator whose output nobody committed is dead code pretending to be
  // covered; a vector file with no generator cannot be checked by the tests
  // above and would drift silently, which is the whole failure being guarded.
  const generators = fs
    .readdirSync(path.join(ROOT, "test/reference/vectors"))
    .filter((f) => f.startsWith("gen-") && f.endsWith(".ts"))
    .map((f) => `test/reference/vectors/${f}`);
  assert.deepEqual(
    generators.sort(),
    VECTORS.map((v) => v.generator).sort(),
    "a gen-*.ts script is not covered by this file",
  );

  const helpers = fs
    .readdirSync(path.join(ROOT, "test/helpers"))
    .filter((f) => f.endsWith("-vectors.json"))
    .map((f) => `test/helpers/${f}`);
  assert.deepEqual(helpers.sort(), VECTORS.map((v) => v.file).sort(), "a vector file has no generator checking it");
});

test("the generators are deterministic, or this file proves nothing", () => {
  // A generator that reseeded per run would make every comparison above fail
  // for a reason that has nothing to do with drift — and the obvious response
  // would be to delete the check. Asserted on the cheapest one.
  const a = generate("test/reference/vectors/gen-identity-vectors.ts");
  const b = generate("test/reference/vectors/gen-identity-vectors.ts");
  assert.equal(a, b, "gen-identity-vectors is not deterministic; the freshness check cannot work");
});
