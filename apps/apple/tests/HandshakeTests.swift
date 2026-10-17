// HQChat tests
//
// The client-to-client handshake proof, against the SAME vectors the server
// asserts. If the two sides disagree by a byte, every handshake fails and every
// first contact stops working — with a log line on each side saying the other
// could not prove possession of its key, which is the most misleading failure
// this protocol could produce. Hence a pinned vector rather than a round trip
// against ourselves.

import Foundation
import CryptoKit

guard CommandLine.arguments.count > 1 else {
    print("  ✗ no vector path given — run.sh must pass handshake-vectors.json")
    exit(1)
}
guard let raw = FileManager.default.contents(atPath: CommandLine.arguments[1]),
      let V = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
      let input = V["input"] as? [String: Any],
      let frames = V["frames"] as? [String: Any] else {
    print("  ✗ could not read vectors at \(CommandLine.arguments[1])")
    exit(1)
}

func hexData(_ s: String) -> Data? {
    guard s.count % 2 == 0 else { return nil }
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
        out.append(b); i = j
    }
    return out
}
func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

check((V["version"] as? Int) == Int(Handshake.version), "vector file matches the wire version")

let challenger = input["challenger"] as! String
let prover = input["prover"] as! String
let nonce = hexData(input["nonceHex"] as! String)!
let ss = hexData(input["ssHex"] as! String)!

/// The generator's `bytes(label, length)`: SHA-256 of the label, then SHA-256
/// of each block, concatenated and truncated.
func chained(_ label: String, _ length: Int) -> Data {
    var out = Data()
    var block = Data(SHA256.hash(data: Data(label.utf8)))
    while out.count < length {
        out += block
        block = Data(SHA256.hash(data: block))
    }
    return out.prefix(length)
}

// ── The init transcript ──────────────────────────────────────────────────────
print("── the init transcript ────────────────────────")

let initV = input["init"] as! [String: Any]
let rk = chained(initV["rkLabel"] as! String, 7237)
let ctId = chained(initV["ctIdLabel"] as! String, 14421)
let ctMt = chained(initV["ctMtLabel"] as! String, 14421)
let ctOt = chained(initV["ctOtLabel"] as! String, 14421)
let otId = initV["otId"] as! Int

// The init is the PROVER's: it initiated, the challenger holds its init.
let transcript = Handshake.initTranscript(sender: prover, to: challenger,
                                          rk: rk, ctId: ctId, ctMt: ctMt, ctOt: ctOt, otId: otId)
check(transcript.map(hexString) == V["transcriptHex"] as? String,
      "the transcript matches the TypeScript twin byte for byte")
let noOneTime = Handshake.initTranscript(sender: prover, to: challenger,
                                         rk: rk, ctId: ctId, ctMt: ctMt, ctOt: nil, otId: nil)
check(noOneTime.map(hexString) == V["transcriptNoOneTimeHex"] as? String,
      "…and so does the transcript of an init without a one-time key")
check(Handshake.initTranscript(sender: prover, to: challenger,
                               rk: rk, ctId: ctId, ctMt: ctMt, ctOt: nil, otId: 99) == noOneTime,
      "an otId without a ctOt is not part of the session, nor of the transcript")
var otherCtMt = ctMt
otherCtMt[otherCtMt.startIndex] ^= 0x01
check(Handshake.initTranscript(sender: prover, to: challenger,
                               rk: rk, ctId: ctId, ctMt: otherCtMt, ctOt: ctOt, otId: otId) != transcript,
      "another init (one flipped ciphertext bit) has another transcript")
check(Handshake.initTranscript(sender: challenger, to: prover,
                               rk: rk, ctId: ctId, ctMt: ctMt, ctOt: ctOt, otId: otId) != transcript,
      "…and so does the same init in the other direction")

// ── The derivation ───────────────────────────────────────────────────────────
print("")
print("── the proof derivation ───────────────────────")

let produced = Handshake.proof(ss: ss, nonce: nonce, challenger: challenger, prover: prover,
                               transcript: transcript!)
check(produced != nil, "the proof derives")
check(produced.map(hexString) == V["proofHex"] as? String,
      "…and matches the TypeScript twin byte for byte")

// The two ids are bound IN ORDER. Swapping them is what a reflection attack
// would need: presenting a proof back to the party that asked for it.
let swapped = Handshake.proof(ss: ss, nonce: nonce, challenger: prover, prover: challenger,
                              transcript: transcript!)
check(swapped.map(hexString) == V["proofSwappedHex"] as? String,
      "swapping the roles gives the pinned DIFFERENT proof")
check(produced != swapped, "…so a proof cannot be reflected at its own author")

// Freshness: the nonce is in the info, so yesterday's proof answers nothing.
var otherNonce = nonce
otherNonce[otherNonce.startIndex] ^= 0xff
check(Handshake.proof(ss: ss, nonce: otherNonce, challenger: challenger, prover: prover,
                      transcript: transcript!) != produced,
      "a different nonce gives a different proof")

// And the secret is what makes it unforgeable — this is the whole finding.
var otherSs = ss
otherSs[otherSs.startIndex] ^= 0xff
check(Handshake.proof(ss: otherSs, nonce: nonce, challenger: challenger, prover: prover,
                      transcript: transcript!) != produced,
      "a different shared secret gives a different proof")

// The binding this version adds: the real peer's proof for ITS init does not
// release a forged init naming it.
check(Handshake.proof(ss: ss, nonce: nonce, challenger: challenger, prover: prover,
                      transcript: noOneTime!) != produced,
      "a proof for one init does not answer a challenge about another")
check(Handshake.proof(ss: ss, nonce: nonce, challenger: challenger, prover: prover,
                      transcript: Data(count: 16)) == nil,
      "a wrong-width transcript is refused, not padded")

check(Handshake.proof(ss: ss, nonce: Data(count: 8), challenger: challenger, prover: prover,
                      transcript: transcript!) == nil,
      "a wrong-width nonce is refused, not padded")
check(Handshake.proof(ss: ss, nonce: nonce, challenger: "nope", prover: prover,
                      transcript: transcript!) == nil,
      "a malformed id is refused, not zero-filled")

// ── Constant-time comparison ─────────────────────────────────────────────────
print("")
print("── proof comparison ───────────────────────────")
let expected = produced!
check(Handshake.proofMatches(expected: expected, offered: expected), "the right proof matches")
var wrong = expected
wrong[wrong.startIndex] ^= 0x01
check(!Handshake.proofMatches(expected: expected, offered: wrong), "one flipped bit does not")
check(!Handshake.proofMatches(expected: expected, offered: Data(count: 4)),
      "a short proof is refused rather than trapping")
check(!Handshake.proofMatches(expected: expected, offered: Data()),
      "…and so is an empty one")

// ── The frames ───────────────────────────────────────────────────────────────
print("")
print("── the wire frames ────────────────────────────")

let chalV = frames["challenge"] as! [String: Any]
let chalFrame = hexData(chalV["frameHex"] as! String)!
let ct = hexData(chalV["ctHex"] as! String)!

let gotChal = Handshake.decode(chalFrame)
check(gotChal?.kind == .challenge, "the pinned challenge decodes")
check(gotChal?.from == challenger && gotChal?.to == prover, "…with both ids intact")
check(gotChal?.nonce == nonce, "…and the nonce")
check(gotChal?.ct == ct, "…and the ciphertext")
check(Handshake.encode(gotChal!) == chalFrame, "…and re-encodes to the same bytes")

let proofV = frames["proof"] as! [String: Any]
let proofFrame = hexData(proofV["frameHex"] as! String)!
let gotProof = Handshake.decode(proofFrame)
check(gotProof?.kind == .proof, "the pinned proof frame decodes")
check(gotProof?.proof == expected, "…carrying the proof the derivation produced")
check(Handshake.encode(gotProof!) == proofFrame, "…and re-encodes to the same bytes")

// Hostile input is refused, never trapped: this parses bytes off the network
// before anything has authenticated them.
var allRefused = true
func mutated(_ base: Data, _ change: (inout Data) -> Void) -> Data {
    var d = base; change(&d); return d
}
let hostile: [(String, Data)] = [
    ("empty", Data()),
    ("magic only", Data("HQCH".utf8)),
    ("truncated challenge", chalFrame.dropLast()),
    ("trailing byte", proofFrame + Data([0])),
    ("bad magic", mutated(chalFrame) { $0[$0.startIndex] = 0x58 }),
    ("unknown kind", mutated(proofFrame) { $0[$0.startIndex + 5] = 9 }),
    ("v1 (unbound proof)", mutated(proofFrame) { $0[$0.startIndex + 4] = 1 }),
    ("huge ct length", mutated(chalFrame) {
        let at = $0.startIndex + 102
        $0[at] = 0x0f; $0[at + 1] = 0xff; $0[at + 2] = 0xff; $0[at + 3] = 0xff
    }),
]
for (name, bytes) in hostile where Handshake.decode(bytes) != nil {
    print("  ✗ accepted hostile input: \(name)")
    allRefused = false
}
check(allRefused, "every hostile frame is refused")

finish()
