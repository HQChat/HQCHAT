// The core addon as the server loads it (src/core.ts): the declared
// exports match the addon's, and HQC gives the shipped known answers.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { CORE_EXPORTS, core } from "../../src/core";

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

test("the declared exports are exactly the addon's", () => {
  assert.deepEqual(Object.keys(core).sort(), [...CORE_EXPORTS].sort());
});

test("HQC through the addon matches the shipped known answers", () => {
  const { pk, sk } = core.hqcKeypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i)));
  assert.equal(sha(pk), "25cebbbb79c410d5b8c1ae0d5e5c35ff2735e7c1f51105a21e6ea7f83391f56c");
  assert.equal(sha(sk), "79471d21ef264d3f59c693ed20f44c0a59daec8b8b9c2708da529ef491a8022b");
  const { ct, ss } = core.hqcEncapsulate(pk);
  assert.ok(core.hqcDecapsulate(sk, ct).equals(ss));
});
