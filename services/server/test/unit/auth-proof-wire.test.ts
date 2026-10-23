// The auth proof's WIRE ENCODING, pinned on both sides of the exchange.
//
// This exists because of a bug that cost a full CI run and told us nothing about
// itself. `test/helpers/mqtt-client.ts` sent the proof as a raw Buffer:
//
//     solution: authProof(ss)
//
// `JSON.stringify` turns a Buffer into `{"type":"Buffer","data":[…]}`, and
// `handleVerify` does `Buffer.from(String(solution), "base64")` — so the server
// base64-decoded the string "[object Object]", got garbage, and returned 401.
// Every e2e test failed on it, and none could say why: **a wrong proof and a
// wrongly-encoded right proof are the same 401**, deliberately, because the
// server must not tell an attacker which of the two they produced.
//
// So the encoding is asserted here instead, where a failure names itself — and
// without needing the native HQC library or a running server, which is what made
// the original bug invisible until CI.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { originOf, signInProof } from "../reference/protocol/auth-proof";

// A fixed key and challenge: the encoding is what is under test here.
const PK = crypto.randomBytes(7237);
const CT = crypto.randomBytes(14421);
const authProof = (ss: Buffer) => signInProof(ss, "https://hqchat.test", PK, CT);

/** Exactly what `handleVerify` in auth/main.ts does with the field. */
function serverParse(solution: unknown): string {
  return Buffer.from(String(solution ?? ""), "base64").toString("hex");
}

/** What `DB.startAuthChallenge` stored when the challenge was opened. */
function serverExpects(ss: Buffer): string {
  return authProof(ss).toString("hex");
}

/** Round-trip through the HTTP layer, which is where the Buffer was lost. */
function overTheWire(body: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(body));
}

test("a base64 proof survives JSON and matches what the server stored", () => {
  const ss = crypto.randomBytes(32);
  const sent = overTheWire({ pk: "aa", solution: authProof(ss).toString("base64") });
  assert.equal(
    serverParse(sent.solution),
    serverExpects(ss),
    "the client's encoding and the server's parse must agree",
  );
});

test("a raw Buffer proof does NOT survive JSON — the bug this pins", () => {
  const ss = crypto.randomBytes(32);
  const sent = overTheWire({ pk: "aa", solution: authProof(ss) });

  // What actually goes on the wire.
  assert.deepEqual(
    Object.keys(sent.solution as object).sort(),
    ["data", "type"],
    "JSON.stringify expands a Buffer into an object",
  );
  assert.equal(String(sent.solution), "[object Object]");

  // And what the server makes of it: not the proof, and not an error either.
  assert.notEqual(
    serverParse(sent.solution),
    serverExpects(ss),
    "this is the 401 — silent, and indistinguishable from a forged proof",
  );
});

test("hex is not base64 — the other way to get this wrong", () => {
  // `startAuthChallenge` stores HEX and `handleVerify` decodes BASE64, so a
  // client that mirrored the stored form would also 401. Worth pinning: the two
  // encodings appear within three lines of each other in auth/main.ts.
  const ss = crypto.randomBytes(32);
  const sent = overTheWire({ solution: authProof(ss).toString("hex") });
  assert.notEqual(serverParse(sent.solution), serverExpects(ss), "sending the stored hex form is also refused");
});

test("authProof is deterministic and domain-separated", () => {
  const ss = crypto.randomBytes(32);
  assert.equal(authProof(ss).toString("hex"), authProof(ss).toString("hex"), "deterministic");
  assert.equal(authProof(ss).length, 32);

  // Not the raw shared secret: the server must never see a value it could
  // replay into anything that consumes `ss` directly.
  assert.notEqual(authProof(ss).toString("hex"), ss.toString("hex"));

  const other = crypto.randomBytes(32);
  assert.notEqual(authProof(other).toString("hex"), authProof(ss).toString("hex"));
});

test("the proof matches the core's vector, with Node's own HKDF", () => {
  // core/hqchat-protocol/src/auth_proof.rs: the_proof_matches_its_vector.
  const { HqcWrapper } = require("../reference/protocol/hqc") as typeof import("../reference/protocol/hqc");
  const { pk } = HqcWrapper.keypairFromSeed(Buffer.alloc(32, 3));
  const ss = Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i));
  const proof = signInProof(ss, "https://api.hqchat.app", pk, Buffer.alloc(14421, 7));
  assert.equal(proof.toString("hex"), "ec47c5b474c9250f750aef96ad5c2161160eedd167a9c04bc6d2aa1f30f83fd4");
});

test("an origin has the core's one form", () => {
  for (const [url, origin] of [
    ["https://API.hqchat.app/", "https://api.hqchat.app"],
    ["https://api.hqchat.app:443/x?y", "https://api.hqchat.app"],
    ["http://127.0.0.1:8090", "http://127.0.0.1:8090"],
    ["http://127.0.0.1:80", "http://127.0.0.1"],
    ["ftp://x", null],
    ["https://user@host", null],
    ["https://", null],
  ] as const) {
    assert.equal(originOf(url), origin, url);
  }
});
