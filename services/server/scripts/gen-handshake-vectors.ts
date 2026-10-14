// Regenerates test/helpers/handshake-vectors.json.
//
//   npx tsx scripts/gen-handshake-vectors.ts > test/helpers/handshake-vectors.json
//
// The proof is the one value in this exchange that both implementations must
// compute identically from the same inputs. If they disagree by a byte, every
// handshake fails and every first contact stops working — with a log line on
// each side saying the other could not prove possession, which is the most
// misleading failure this protocol could produce.
//
// So the derivation is pinned here, from a FIXED shared secret rather than a
// real decapsulation: what is under test is the HKDF and the binding, not HQC.

import * as crypto from "node:crypto";
import {
  encodeHandshake,
  HANDSHAKE_NONCE_BYTES,
  HANDSHAKE_PROOF_BYTES,
  HANDSHAKE_VERSION,
  handshakeProof,
  initTranscript,
} from "../src/protocol/handshake";
import { peerId } from "../src/protocol/identity";

function bytes(label: string, length: number): Buffer {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  let total = 0;
  while (total < length) {
    out.push(block);
    total += block.length;
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, length);
}

const CHALLENGER = peerId(bytes("hqchat/handshake-vector/challenger", 7237).toString("hex"));
const PROVER = peerId(bytes("hqchat/handshake-vector/prover", 7237).toString("hex"));
const NONCE = bytes("hqchat/handshake-vector/nonce", HANDSHAKE_NONCE_BYTES);
const SS = bytes("hqchat/handshake-vector/ss", 32);
const CT = bytes("hqchat/handshake-vector/ct", 14421);

/** The init the challenge is about: sent by PROVER to CHALLENGER. */
const INIT = {
  rk: bytes("hqchat/handshake-vector/init/rk", 7237),
  ctId: bytes("hqchat/handshake-vector/init/ctId", 14421),
  ctMt: bytes("hqchat/handshake-vector/init/ctMt", 14421),
  ctOt: bytes("hqchat/handshake-vector/init/ctOt", 14421),
  otId: 7,
  cid: "00".repeat(16),
};
const TRANSCRIPT = initTranscript(PROVER, CHALLENGER, INIT);
const TRANSCRIPT_NO_OT = initTranscript(PROVER, CHALLENGER, { ...INIT, ctOt: null, otId: null });
const PROOF = handshakeProof(SS, NONCE, CHALLENGER, PROVER, TRANSCRIPT);

/** The same secret bound to a different pair, to pin that the ids are in. */
const SWAPPED = handshakeProof(SS, NONCE, PROVER, CHALLENGER, TRANSCRIPT);

console.log(
  JSON.stringify(
    {
      _comment:
        "The client-to-client handshake proof, asserted by BOTH " +
        "services/server/test/handshake.test.ts and apps/apple/tests/HandshakeTests.swift, " +
        "which READ this file. `proof` is HKDF-SHA256(ikm=ss, salt='salt', " +
        "info='hqchat/handshake/v2'||nonce||challenger||prover||transcript, 32) — every component " +
        "fixed-width, so there are no delimiters for the two sides to disagree about. " +
        "`proofSwapped` pins that the two ids are bound IN ORDER: a proof cannot be " +
        "reflected back at its own author. `transcript` is initTranscript(prover, challenger, init): " +
        "SHA-256('hqchat/handshake/v2/init'||sender||to||lp(rk)||lp(ctId)||lp(ctMt)||lp(ctOt or empty)" +
        "||u32(otId or 0xffffffff)), lp = u32 big-endian length + bytes. The init's large fields are " +
        "derived by sha256-chaining their labels (see the generator), not stored here.",
      version: HANDSHAKE_VERSION,
      input: {
        challenger: CHALLENGER,
        prover: PROVER,
        nonceHex: NONCE.toString("hex"),
        ssHex: SS.toString("hex"),
        init: {
          rkLabel: "hqchat/handshake-vector/init/rk",
          ctIdLabel: "hqchat/handshake-vector/init/ctId",
          ctMtLabel: "hqchat/handshake-vector/init/ctMt",
          ctOtLabel: "hqchat/handshake-vector/init/ctOt",
          otId: INIT.otId,
        },
      },
      transcriptHex: TRANSCRIPT.toString("hex"),
      transcriptNoOneTimeHex: TRANSCRIPT_NO_OT.toString("hex"),
      proofHex: PROOF.toString("hex"),
      proofBytes: HANDSHAKE_PROOF_BYTES,
      proofSwappedHex: SWAPPED.toString("hex"),
      frames: {
        challenge: {
          ctHex: CT.toString("hex"),
          frameHex: encodeHandshake({
            kind: "chal",
            from: CHALLENGER,
            to: PROVER,
            nonce: NONCE,
            ct: CT,
          }).toString("hex"),
        },
        proof: {
          frameHex: encodeHandshake({
            kind: "proof",
            from: PROVER,
            to: CHALLENGER,
            nonce: NONCE,
            proof: PROOF,
          }).toString("hex"),
        },
      },
    },
    null,
    2,
  ),
);
