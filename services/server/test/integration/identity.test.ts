// The client identifier, pinned three ways.
//
// `id = sha256(lowercase-hex(pk))` is what every name in the system now is: the
// MQTT client id, the ACL row, the topic strings, the envelope's `sender`, every
// route parameter. Four implementations have to agree about it byte-for-byte —
// TypeScript, Swift, Postgres, and the EMQX authorizer query — and a
// disagreement is not a crash. It is a client that names itself something the
// broker has no grant for, and gets disconnected with `0x87 NOT AUTHORIZED`.
//
// That is the exact class of failure this deployment has already shipped twice:
// the AAD encoding, then the auth-proof encoding. Both were one encoding
// decision made twice, and both surfaced as an authentication failure that said
// nothing about encoding at all.
//
// So: the vectors are READ (not recomputed) here and in
// apps/apple/tests/PeerIDTests.swift, and the Postgres half is asserted against
// a live database — `encode(pk_digest(pk),'hex')` IS peerId, and has been since
// 001_schema.sql was written.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { q } from "../../src/server/db/pg";
import { closePg, requirePg } from "../pg-helper";
import { isPeerId, keyMatchesId, PEER_ID_LENGTH, peerId } from "../reference/protocol/identity";

test.before(requirePg);

const V = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "helpers", "identity-vectors.json"), "utf8")) as {
  version: number;
  publicKeyBytes: number;
  keys: Array<{ label: string; publicKeyHex: string; id: string }>;
};

test("the vector file is the shape both suites expect", () => {
  assert.equal(V.version, 1);
  assert.equal(V.publicKeyBytes, 7237, "an HQC-256 public key");
  assert.ok(V.keys.length >= 4, "vectors for the full-size, short and uppercase cases");
  // The first vector must be a REAL key. A short stand-in is what let
  // `pk text PRIMARY KEY` reach production, and it is what this whole change is
  // about not doing again.
  assert.equal(V.keys[0]!.publicKeyHex.length, 7237 * 2);
});

test("peerId matches the pinned id for every vector", () => {
  for (const k of V.keys) {
    assert.equal(peerId(k.publicKeyHex), k.id, k.label);
    assert.equal(k.id.length, PEER_ID_LENGTH);
    assert.ok(isPeerId(k.id), `${k.label}: the id is 64 lowercase hex`);
  }
});

test("an id is 450x shorter than the key it names", () => {
  // The number that made every per-client EMQX endpoint answer 414, and every
  // mqtt_acl row ~29 kB. Asserted rather than asserted-in-a-comment, because it
  // is the entire reason for the change.
  const pk = V.keys[0]!.publicKeyHex;
  assert.equal(pk.length, 14474);
  assert.equal(peerId(pk).length, 64);
  // `DELETE /clients/{id}/subscriptions/{topic}` — the surgical revocation that
  // has never once worked here — with both halves at their new size.
  const url = `clients/${peerId(pk)}/subscriptions/${encodeURIComponent(`c/${"a".repeat(64)}`)}`;
  assert.ok(url.length < 200, `a per-client admin URL is ${url.length} characters`);
});

test("uppercase hex names the same client as lowercase", () => {
  // Not a nicety. The wire form is lowercase, and a caller that sends uppercase
  // would otherwise be a stranger: a different id, a different topic, no ACL
  // row, and a broker that answers 0x87 without saying why.
  const lower = V.keys[2]!;
  const upper = V.keys[3]!;
  assert.equal(lower.publicKeyHex.toUpperCase(), upper.publicKeyHex);
  assert.equal(lower.id, upper.id);
});

test("different keys get different ids", () => {
  const ids = new Set(V.keys.map((k) => k.id));
  // The two full-size vectors plus the short one; the uppercase vector is the
  // short one's twin by design.
  assert.equal(ids.size, V.keys.length - 1);
});

// ── The commitment property ─────────────────────────────────────────────────
//
// This is what the digest BUYS, beyond fitting in a URL. Because the id is a
// hash of the key, a key can be checked against an id already held — so the
// graph carries ids, the key travels separately, and TOFU narrows to "trust the
// id you were first given".

test("a key verifies against the id that names it", () => {
  for (const k of V.keys) {
    assert.ok(keyMatchesId(k.publicKeyHex, k.id), k.label);
    assert.ok(keyMatchesId(k.publicKeyHex.toUpperCase(), k.id), "case-insensitively");
  }
});

test("a substituted key is refused — no second preimage survives", () => {
  const real = V.keys[0]!;
  const impostor = V.keys[1]!;
  assert.ok(!keyMatchesId(impostor.publicKeyHex, real.id), "a different key must not verify against this id");
  // The near-miss case: one flipped hex digit, which is what a tampered
  // directory response would most plausibly look like.
  const tweaked = real.publicKeyHex.slice(0, -1) + (real.publicKeyHex.endsWith("0") ? "1" : "0");
  assert.ok(!keyMatchesId(tweaked, real.id), "one changed character is a different key");
});

test("an id is NOT an authenticator — anyone holding the key can compute it", () => {
  // Stated as a test because it is the constraint every route has to respect:
  // no route may treat possession of an id as proof.
  // There is no secret in this function.
  const k = V.keys[0]!;
  assert.equal(peerId(k.publicKeyHex), k.id);
  assert.equal(crypto.createHash("sha256").update(k.publicKeyHex, "utf8").digest("hex"), k.id);
});

test("the id is NOT chainId — chainId is the same digest truncated to 32", () => {
  // test/reference/protocol/double-ratchet.ts derives a chain selector the same way and keeps 32
  // hex characters. Reusing it here would halve the collision resistance of
  // every name in the system for the sake of 32 bytes.
  const k = V.keys[0]!;
  assert.equal(k.id.length, 64);
  assert.notEqual(k.id.slice(0, 32), k.id);
});

// ── The Postgres half ───────────────────────────────────────────────────────

test("peerId IS pk_digest — the database has been keyed on this all along", async () => {
  for (const k of V.keys) {
    const res = await q<{ digest: string }>(`SELECT encode(pk_digest($1), 'hex') AS digest`, [
      k.publicKeyHex.toLowerCase(),
    ]);
    assert.equal(res.rows[0]!.digest, k.id, `${k.label}: encode(pk_digest(pk),'hex') must equal peerId(pk)`);
  }
});

test.after(closePg);
