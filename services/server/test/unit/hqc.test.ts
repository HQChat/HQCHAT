// The HQC KEM wrapper: keygen, encapsulate, decapsulate and the error paths,
// against the library built from the pinned upstream source (native/hqc).

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";

test("HQC KEM wrapper", async (t) => {
  let hqc: typeof import("../reference/protocol/hqc");
  try {
    hqc = await import("../reference/protocol/hqc");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }
  const { HqcWrapper, HQC_CONSTANTS } = hqc;

  const validSeed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);

  // --- key generation ------------------------------------------------------

  await t.test("generates a keypair with the documented buffer sizes", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    assert.ok(keys.pk, "public key should exist");
    assert.ok(keys.sk, "secret key should exist");
    assert.equal(keys.pk.length, HQC_CONSTANTS.PUBLIC_KEY_BYTES, "pk length");
    assert.equal(keys.sk.length, HQC_CONSTANTS.SECRET_KEY_BYTES, "sk length");
  });

  await t.test("is deterministic — the same seed yields the same keys", () => {
    const seed = Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 0xaa);
    const a = HqcWrapper.keypairFromSeed(seed);
    const b = HqcWrapper.keypairFromSeed(seed);
    assert.deepEqual(a.pk, b.pk, "public keys must be identical for one seed");
    assert.deepEqual(a.sk, b.sk, "secret keys must be identical for one seed");
  });

  await t.test("different seeds yield different keys", () => {
    const a = HqcWrapper.keypairFromSeed(Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 1));
    const b = HqcWrapper.keypairFromSeed(Buffer.alloc(HQC_CONSTANTS.SEED_BYTES, 2));
    assert.notDeepEqual(a.pk, b.pk, "public keys should differ");
    assert.notDeepEqual(a.sk, b.sk, "secret keys should differ");
  });

  // --- encapsulation / decapsulation ---------------------------------------

  await t.test("encapsulates to a valid ciphertext and a 32-byte secret", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    assert.equal(ct.length, HQC_CONSTANTS.CIPHERTEXT_BYTES, "ciphertext size");
    assert.equal(ss.length, HQC_CONSTANTS.SHARED_SECRET_BYTES, "shared secret size");
  });

  await t.test("each encapsulation is fresh", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const a = HqcWrapper.encapsulate(keys.pk);
    const b = HqcWrapper.encapsulate(keys.pk);
    assert.notDeepEqual(a.ct, b.ct, "ciphertexts should differ");
    assert.notDeepEqual(a.ss, b.ss, "shared secrets should differ");
  });

  await t.test("keygen → encapsulate → decapsulate round-trips", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    assert.deepEqual(
      HqcWrapper.decapsulate(keys.sk, ct),
      ss,
      "the decapsulated secret must match the encapsulated one",
    );
  });

  // The IND-CCA2 property: decapsulating a tampered
  // ciphertext returns a pseudo-random secret in constant time, never throws
  // and never leaks the real one.
  await t.test("a corrupted ciphertext does not decapsulate to the real secret", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    const { ct, ss } = HqcWrapper.encapsulate(keys.pk);
    const bad = Buffer.from(ct);
    bad[0] = (bad[0] ?? 0) ^ 0xff;
    assert.notDeepEqual(
      HqcWrapper.decapsulate(keys.sk, bad),
      ss,
      "a tampered ciphertext must not recover the real secret",
    );
  });

  // --- refusals ------------------------------------------------------------

  await t.test("refuses a wrong-sized seed", () => {
    assert.throws(() => HqcWrapper.keypairFromSeed(Buffer.alloc(10)), /Seed must be 32 bytes/);
  });

  await t.test("refuses a wrong-sized public key", () => {
    assert.throws(() => HqcWrapper.encapsulate(Buffer.alloc(100)), /Invalid PK length/);
  });

  await t.test("refuses a wrong-sized ciphertext", () => {
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    assert.throws(() => HqcWrapper.decapsulate(keys.sk, Buffer.alloc(64)), /Invalid Ciphertext length/);
  });

  // --- resource hygiene ----------------------------------------------------
  //
  // The wrappers write into caller-allocated Buffers and return a status,
  // so there is no native malloc and no cross-module free. This is the check
  // that would notice if that ever stopped being true.
  await t.test("1000 encapsulate/decapsulate cycles do not leak", () => {
    const iterations = 1000;
    const before = process.memoryUsage().rss;
    const keys = HqcWrapper.keypairFromSeed(validSeed);
    for (let i = 0; i < iterations; i++) {
      const { ct } = HqcWrapper.encapsulate(keys.pk);
      HqcWrapper.decapsulate(keys.sk, ct);
    }
    const grewMB = (process.memoryUsage().rss - before) / 1024 / 1024;
    assert.ok(grewMB < 500, `rss grew ${grewMB.toFixed(2)} MB over ${iterations} cycles`);
  });
});

// ── The claim that makes any of this portable ────────────────────────────────
//
// `native/hqc/HQC_UPSTREAM.txt` states that the Linux .so files, the macOS
// dylib and the iOS xcframework are all byte-compatible with one pinned commit.
// Everything rests on that: the server encapsulates to a public key the Swift
// client generated, so two builds from different revisions do not merely differ
// — they fail to communicate, and the failure looks like a decryption error.
//
// Nothing checked it. It was a sentence in a text file, and this file skipped on
// the one platform where the other binary is used. These digests are now
// asserted on every platform the suite runs on, so a library rebuilt from a
// different revision fails here rather than in a conversation.
//
// Generated on macOS/arm64 from the pinned source. If this
// fails on Linux, the two libraries are NOT byte-compatible and that is the
// finding — do not regenerate the digests to make it pass.

import { createHash } from "node:crypto";

/** Bytes 0..31. Arbitrary, fixed, and readable in a hex dump. */
const KAT_SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

const KAT = {
  pk: "25cebbbb79c410d5b8c1ae0d5e5c35ff2735e7c1f51105a21e6ea7f83391f56c",
  sk: "79471d21ef264d3f59c693ed20f44c0a59daec8b8b9c2708da529ef491a8022b",
  // Decapsulation is deterministic in (sk, ct), so a FIXED ciphertext pins it
  // too — and since this one is not a real encapsulation, what it pins is the
  // implicit-rejection derivation: the pseudo-random secret a chosen ciphertext
  // yields. That is the CCA2 property, and it is derived differently by
  // different revisions.
  ss: "8a380b3e4d305322ecb4f438bf060f4da8d0f395614be39c881f67018a3ad0f4",
};

test("the native library matches the committed known-answer test", async (t) => {
  let hqc: typeof import("../reference/protocol/hqc");
  try {
    hqc = await import("../reference/protocol/hqc");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }
  const { HqcWrapper, HQC_CONSTANTS, loadedLibrary } = hqc;
  const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

  // Which binary answered. Printed rather than asserted — it differs by
  // platform, and a KEM assertion is meaningless without knowing its source.
  t.diagnostic(`HQC library: ${loadedLibrary()}`);

  const { pk, sk } = HqcWrapper.keypairFromSeed(KAT_SEED);
  const drift =
    "\nThis library is not byte-compatible with the one these digests came from. " +
    "HQC's sampling changes between upstream revisions, so a server built from one " +
    "and a client from another cannot hold a conversation. Rebuild every target from " +
    "one ref (native/hqc/package.nix, core/hqc-sys) rather than updating this digest.";

  assert.equal(sha(pk), KAT.pk, `public key drift${drift}`);
  assert.equal(sha(sk), KAT.sk, `secret key drift${drift}`);

  const ct = Buffer.alloc(HQC_CONSTANTS.CIPHERTEXT_BYTES);
  for (let i = 0; i < ct.length; i++) ct[i] = (i * 7 + 13) & 0xff;
  assert.equal(sha(HqcWrapper.decapsulate(sk, ct)), KAT.ss, `implicit-rejection drift${drift}`);
});

// ── The skip has to be able to fail ──────────────────────────────────────────
//
// Every test in this file is behind a guarded dynamic import, which is right: a
// host with no native library should skip rather than take the file down. But a
// skip is silent, and that is how eleven KEM assertions — the post-quantum
// primitive this whole product rests on — stopped running on the platform they
// are developed on, for as long as `test/reference/protocol/hqc.ts` named one library outright.
//
// Verified, not assumed: reverting the platform selection in `test/reference/protocol/hqc.ts` gives
// "5 skipped, 0 failed" across this file and bot-crypto.test.ts. A green run.
//
// So on a platform this repo SHIPS a library for, failing to load one is a
// failure and not a skip. Anywhere else it still skips, because there is
// genuinely nothing to test.

const SHIPS_A_LIBRARY = process.platform === "darwin" || process.platform === "linux";

test("the native library loads on a platform that ships one", async (t) => {
  if (!SHIPS_A_LIBRARY) {
    return t.skip(`no HQC library is built for ${process.platform} — see native/hqc/package.nix`);
  }
  try {
    const { loadedLibrary } = await import("../reference/protocol/hqc");
    t.diagnostic(`HQC library: ${loadedLibrary()}`);
    assert.ok(loadedLibrary().length > 0, "a library loaded but did not report which");
  } catch (e) {
    // Deliberately a failure. The guards above would turn this into a quiet
    // skip, and the whole KEM surface would stop being tested without anything
    // going red.
    assert.fail(
      `HQC did not load on ${process.platform}/${process.arch}, so every KEM test ` +
        `in this file and in bot-crypto.test.ts has silently stopped running.\n${(e as Error).message}`,
    );
  }
});
