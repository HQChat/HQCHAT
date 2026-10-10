# End-to-end encryption protocol

What two clients speak to each other. The TypeScript implementation is in
`services/server/src/protocol/` (used by the bot and the tests); the Swift one
in `apps/apple/HQChat/Services/`. Each piece below is pinned byte for byte
between the two by a vector file in `services/server/test/helpers/`.

## Primitives

| Use | Primitive |
|---|---|
| Every key agreement | HQC-256 KEM (IND-CCA2, implicit rejection): public key 7,237 B, ciphertext 14,421 B, shared secret 32 B |
| Message encryption | AES-256-GCM, 12-byte IV, 16-byte tag, the frame header as AAD |
| Key derivation | HKDF-SHA256, salt `"salt"`, a distinct `info` per use |
| Fingerprints, ids | SHA-256 |
| At rest on Apple devices | P-256 ECIES in the Secure Enclave wrapping a per-message AES-256-GCM key |

HQC is built from a pinned upstream commit (`native/hqc/HQC_UPSTREAM.txt`) and
checked against committed known-answer digests.

## Prekeys

Each profile publishes, through `POST /prekeys`:

- one **medium-term prekey**, an HQC public key, replaced every 7 days;
- a pool of **one-time prekeys**, topped up to 8 whenever fewer than 4 remain.

`POST /prekeys/claim { peer }` (friends only) returns the peer's identity key,
medium-term prekey and, while the pool lasts, one one-time prekey with its id,
which is consumed by the claim. Prekeys are not signed (HQC cannot sign); a
substituted prekey gains nothing, because the session root also needs the
encapsulation to the pinned identity key.

## Starting a session (`init`)

The initiator, holding the peer's pinned identity key and a claimed bundle:

```
(ctId, ssId) = Encaps(identityPk)        authenticates the responder
(ctMt, ssMt) = Encaps(mediumPk)          forward secrecy
(ctOt, ssOt) = Encaps(oneTimePk)         forward secrecy, when a one-time key was claimed
ikm   = ssId ‖ ssMt [‖ ssOt]
root  = HKDF(ikm, "hqchat/v2/init/root")
chain = HKDF(ikm, "hqchat/v2/init/chain")    the initiator's first sending chain
(rkPub, rkSec) = new HQC key pair             the initiator's first ratchet key
```

Every message the initiator sends carries the init fields (`ctId`, `ctMt`,
`ctOt`, `otId`, its identity key and `rk`) until it first hears back, so a
burst sent while the peer is offline is all typed `init`, and any one of them
can open the session.

The responder decapsulates the three ciphertexts (refusing an `otId` whose
secret is already consumed), derives the same root and opens the first
message. A one-time secret is deleted only after the payload authenticates. An
`init` from a peer we already have a session with never replaces it: its
payload is opened as an ordinary message, or, when both sides started at once,
the lower client id keeps its own session and the other yields and re-sends.

## Proving the initiator (handshake)

An `init` is built only from the responder's public keys, so it proves nothing
about who sent it. Before accepting the first `init` from a contact in a given
app run, the responder challenges on the friendship's `hs/` topic:

```
challenge:  (ct, ss) = Encaps(initiator's pinned identity key), nonce = 32 random bytes
proof    =  HKDF-SHA256(ss, "salt", "hqchat/handshake/v1" ‖ nonce ‖ challengerId ‖ proverId, 32)
```

The initiator answers only challenges for handshakes it started. The proof is
compared in constant time; the held `init` is processed once it matches.

Handshake frame (`HQCH`, version 1, fixed offsets, big-endian):

| Offset | Field | Size |
|---|---|---|
| 0 | magic `HQCH` | 4 |
| 4 | version | 1 |
| 5 | kind (0 challenge, 1 proof) | 1 |
| 6 | from (raw client id) | 32 |
| 38 | to (raw client id) | 32 |
| 70 | nonce | 32 |
| 102 | challenge: `u32 len` + HQC ciphertext; proof: 32 bytes | |

## The double ratchet

A KEM double ratchet: since a KEM cannot be "combined" like Diffie-Hellman, a
step carries the sender's new ratchet public key and a ciphertext encapsulated
to the key the peer last advertised.

```
step (sender):    (kemCt, ss) = Encaps(peerRkPub);  new (rkPub, rkSec)
                  root', ck = HKDF(root ‖ ss, "hqchat/v2/root"), HKDF(root ‖ ss, "hqchat/v2/chain")
step (receiver):  ss = Decaps(rkSec, kemCt), same derivation, adopt peerRkPub = rk
message key:      mk  = HKDF(ck, "hqchat/v2/msg")
next chain key:   ck' = HKDF(ck, "hqchat/v2/ck")
chain id:         cid = first 16 bytes of SHA-256(rkPub), as hex
```

- **When to step:** the first send after hearing from the peer always steps;
  after that a sending chain steps only once it has been used and has carried
  32 messages or lived 15 minutes. These bounds are the post-compromise window.
- **Out of order:** keys skipped on the way to a later message are cached by
  chain and index, at most 2,000 across all chains, oldest evicted.
- **Replays and forged steps:** a cached key is consumed only if its payload
  authenticates; a chain already left is never re-entered (the last 64 chain
  ids are remembered); everything a step would change is computed first and
  committed only after the payload authenticates. HQC's implicit rejection
  means a forged step decapsulates to a random secret, so the AEAD tag is the
  only authenticator, and nothing is written before it passes.

## The frame

Every conversation message is one binary frame. The header runs from byte 0
to the start of the payload length, and that whole span is the AAD, so a
receiver authenticates exactly the bytes it received.

| Offset | Field | Size |
|---|---|---|
| 0 | magic `HQCE` | 4 |
| 4 | version (3) | 1 |
| 5 | kind (0 msg, 1 init, 2 receipt) | 1 |
| 6 | flags: bit0 `rk`, bit1 `kemCt`, bit2 one-time | 1 |
| 7 | sender (raw client id) | 32 |
| 39 | to (raw client id) | 32 |
| 71 | cid (raw) | 16 |
| 87 | n | u32 |
| 91 | pn (length of the previous sending chain) | u32 |
| 95 | msgId length (1..128) | u8 |
| 96 | msgId, UTF-8 | |
| | `rk` | `u32 len` + bytes, when flagged |
| | `kemCt` | `u32 len` + bytes, when flagged |
| | init only: sender public key, `ctId`, `ctMt` | 3 × (`u32 len` + bytes) |
| | one-time: `ctOt` + `otId` | `u32 len` + bytes, `u32` |
| | payload `[IV 12][tag 16][ciphertext]` | `u32 len` + bytes |

A `receipt` is laid out exactly as a `msg`: it is sealed with the next message
key like any message, its payload is the empty string, and its `msgId` names
the message it acknowledges. A client sends one for every message it opens
(an `init`'s included), never for a receipt, and only inside a session the
peer has answered, so a receipt never opens one.

Rules both decoders enforce: unknown kinds and flags, a `msg` or `receipt` with `rk` but no `kemCt`
(or the reverse), an `init` without `rk` or with `kemCt`, empty or
over-1-MiB fields, invalid UTF-8, trailing bytes, a malformed id, and an
`init` whose sender key does not hash to `sender` are all refused.

Approximate sizes: a plain message is about 130 bytes plus its text; a
stepping message adds about 21.7 kB; an `init` with a one-time prekey is about
58 kB.

## Routing rules on receipt

A frame is accepted only if it is addressed to this client (`to`), comes from a
known contact that has not vanished, and arrived on the topic its kind allows:
an `init` on our inbox, a `msg` or `receipt` only on that friendship's `cv/` topic.

## Verification

The safety number is SHA-256 of the two identity public keys in sorted order,
shown as 12 groups of 5 digits (and a QR code). Because an id is the hash of a
key, a changed key is a new contact: the old one is marked vanished and kept
read-only, never silently re-keyed.

## At rest on the device

Each stored body is sealed with a fresh AES-256-GCM key, which is wrapped with
ECIES (`eciesEncryptionCofactorX963SHA256AESGCM`) to the profile's Secure
Enclave public key. Sealing needs no user, so messages received in the
background are stored sealed; opening needs the Enclave private key, gated by
the profile's protection tier. Deleting a profile deletes its key pair, which
makes its rows permanently unreadable.

## Not provided

Read receipts, typing indicators, disappearing messages, attachments, multi-device
for one identity, and padding against size analysis.
