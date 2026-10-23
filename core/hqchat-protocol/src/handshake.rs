//! Proof that an `init` came from the peer it names. An `init` is derived
//! only from the responder's public keys, so on its own it authenticates
//! nobody. The responder answers with a challenge, an HQC encapsulation to
//! the initiator's identity key, and the initiator proves possession with
//!
//! ```text
//! info  = "hqchat/handshake/v2" ‖ nonce(32) ‖ challenger(32) ‖ prover(32) ‖ transcript(32)
//! proof = HKDF-SHA256(ikm = ss, salt = "salt", info, 32)
//! ```
//!
//! The nonce gives freshness, the ordered ids bind the proof to one pair, and
//! the transcript binds it to one init: each side derives it from the init it
//! holds or sent, so a forged init naming the initiator is not released by
//! the initiator's proof for its genuine one. The transcript is never sent.
//!
//! Wire format (big-endian): `"HQCH"`, version u8 (2), kind u8 (0 challenge,
//! 1 proof), from 32 B, to 32 B, nonce 32 B, then a challenge's `u32 len +
//! ciphertext` or a proof's 32 bytes.

use hqc::SharedSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::kdf::hkdf_sha256;
use crate::ratchet::InitHeader;
use crate::wire::{Reader, len_u32, prefix_u32, usize_from};
use crate::{Entropy, Error, PeerId};

/// The handshake wire version; v1 proofs were not bound to an init.
pub const HANDSHAKE_VERSION: u8 = 2;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 32;
/// Proof length in bytes.
pub const PROOF_BYTES: usize = 32;
/// Transcript length in bytes.
pub const TRANSCRIPT_BYTES: usize = 32;
/// Upper bound on a challenge's ciphertext.
pub const MAX_CT_BYTES: usize = 1 << 20;

const MAGIC: &[u8; 4] = b"HQCH";
const INFO_PREFIX: &[u8] = b"hqchat/handshake/v2";
const TRANSCRIPT_LABEL: &[u8] = b"hqchat/handshake/v2/init";
/// `otId` in the transcript when the init carries no one-time prekey.
const NO_ONE_TIME: u32 = u32::MAX;
const KIND_CHALLENGE: u8 = 0;
const KIND_PROOF: u8 = 1;
const OFF_BODY: usize = 102;
/// A challenge frame as the engine sends it: header, length and one HQC ciphertext.
const CHALLENGE_CAPACITY: usize = OFF_BODY + 4 + hqc::CIPHERTEXT_BYTES;

/// A challenge or its proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeFrame {
    /// The responder's challenge.
    Challenge {
        /// The responder.
        from: PeerId,
        /// The initiator.
        to: PeerId,
        /// Fresh per challenge.
        nonce: [u8; NONCE_BYTES],
        /// Encapsulated to the initiator's identity key; raw bytes, as on the
        /// wire, so its size is checked where it is decapsulated.
        ct: Vec<u8>,
    },
    /// The initiator's answer.
    Proof {
        /// The initiator.
        from: PeerId,
        /// The responder.
        to: PeerId,
        /// The challenge's nonce.
        nonce: [u8; NONCE_BYTES],
        /// [`handshake_proof`] over the decapsulated secret.
        proof: [u8; PROOF_BYTES],
    },
}

/// A fresh challenge nonce.
pub fn handshake_nonce(entropy: &mut dyn Entropy) -> Result<[u8; NONCE_BYTES], Error> {
    let mut nonce = [0u8; NONCE_BYTES];
    entropy.fill(&mut nonce)?;
    Ok(nonce)
}

/// The hash of one init's session-defining fields:
///
/// ```text
/// SHA-256("hqchat/handshake/v2/init" ‖ sender ‖ to ‖ lp(rk) ‖ lp(ctId) ‖ lp(ctMt)
///         ‖ lp(ctOt or empty) ‖ u32(otId or 0xffffffff))
/// ```
///
/// Every frame of an initiator's init burst shares these fields, so one proof
/// covers the burst; a forged init, built from other ciphertexts, has another.
pub fn init_transcript(sender: &PeerId, to: &PeerId, init: &InitHeader) -> [u8; TRANSCRIPT_BYTES] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_LABEL);
    h.update(sender.to_bytes());
    h.update(to.to_bytes());
    // Every field has a fixed size, so each length prefix is a constant.
    const PK_LEN: [u8; 4] = prefix_u32(hqc::PUBLIC_KEY_BYTES);
    const CT_LEN: [u8; 4] = prefix_u32(hqc::CIPHERTEXT_BYTES);
    const EMPTY_LEN: [u8; 4] = prefix_u32(0);
    let mut field = |len: [u8; 4], bytes: &[u8]| {
        h.update(len);
        h.update(bytes);
    };
    field(PK_LEN, init.rk.as_bytes());
    field(CT_LEN, init.ct_id.as_bytes());
    field(CT_LEN, init.ct_mt.as_bytes());
    match &init.one_time {
        Some((ct_ot, _)) => field(CT_LEN, ct_ot.as_bytes()),
        None => field(EMPTY_LEN, &[]),
    }
    let ot_id = init.one_time.as_ref().map_or(NO_ONE_TIME, |(_, id)| *id);
    h.update(ot_id.to_be_bytes());
    h.finalize().into()
}

/// The proof for a challenge that decapsulated to `ss`. `challenger` and
/// `prover` are bound in that order, so the roles cannot be swapped.
pub fn handshake_proof(
    ss: &SharedSecret,
    nonce: &[u8; NONCE_BYTES],
    challenger: &PeerId,
    prover: &PeerId,
    transcript: &[u8; TRANSCRIPT_BYTES],
) -> [u8; PROOF_BYTES] {
    let mut info = Vec::with_capacity(INFO_PREFIX.len().saturating_add(128));
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(nonce);
    info.extend_from_slice(&challenger.to_bytes());
    info.extend_from_slice(&prover.to_bytes());
    info.extend_from_slice(transcript);
    *hkdf_sha256::<PROOF_BYTES>(b"salt", ss.as_bytes(), &info)
}

/// Constant-time comparison of an offered proof against the expected one.
pub fn proof_matches(expected: &[u8; PROOF_BYTES], offered: &[u8; PROOF_BYTES]) -> bool {
    expected.ct_eq(offered).into()
}

/// The frame's wire bytes; refuses a challenge with an empty or oversized
/// ciphertext, which [`decode`] could not read back.
pub fn encode(frame: &HandshakeFrame) -> Result<Vec<u8>, Error> {
    let (kind, from, to, nonce) = match frame {
        HandshakeFrame::Challenge {
            from, to, nonce, ..
        } => (KIND_CHALLENGE, from, to, nonce),
        HandshakeFrame::Proof {
            from, to, nonce, ..
        } => (KIND_PROOF, from, to, nonce),
    };
    let mut out = Vec::with_capacity(CHALLENGE_CAPACITY);
    out.extend_from_slice(MAGIC);
    out.push(HANDSHAKE_VERSION);
    out.push(kind);
    out.extend_from_slice(&from.to_bytes());
    out.extend_from_slice(&to.to_bytes());
    out.extend_from_slice(nonce);
    match frame {
        HandshakeFrame::Challenge { ct, .. } => {
            if ct.is_empty() || ct.len() > MAX_CT_BYTES {
                return Err(Error::Invalid("a challenge needs a ciphertext under 1 MiB"));
            }
            out.extend_from_slice(
                &len_u32(ct.len(), "a challenge needs a ciphertext under 1 MiB")?.to_be_bytes(),
            );
            out.extend_from_slice(ct);
        }
        HandshakeFrame::Proof { proof, .. } => out.extend_from_slice(proof),
    }
    Ok(out)
}

/// Decodes a handshake frame; never panics on what the network sends.
pub fn decode(raw: &[u8]) -> Result<HandshakeFrame, Error> {
    if raw.len() < OFF_BODY || !raw.starts_with(MAGIC) {
        return Err(Error::Malformed("not a handshake frame"));
    }
    let mut r = Reader::new(raw, "not a handshake frame");
    r.take(MAGIC.len())?;
    if r.u8()? != HANDSHAKE_VERSION {
        return Err(Error::Malformed("not a v2 handshake frame"));
    }
    let kind = r.u8()?;
    let from = PeerId::from_bytes(r.array()?);
    let to = PeerId::from_bytes(r.array()?);
    let nonce = *r.array::<NONCE_BYTES>()?;
    match kind {
        KIND_CHALLENGE => {
            let len = r
                .u32()
                .map_err(|_| Error::Malformed("challenge without a ciphertext"))?;
            let len = usize_from(len);
            if len == 0 || len > MAX_CT_BYTES || r.remaining() != len {
                return Err(Error::Malformed("bad challenge ciphertext length"));
            }
            Ok(HandshakeFrame::Challenge {
                from,
                to,
                nonce,
                ct: r.rest().to_vec(),
            })
        }
        KIND_PROOF => {
            let proof: [u8; PROOF_BYTES] = r
                .rest()
                .try_into()
                .map_err(|_| Error::Malformed("a proof is exactly 32 bytes"))?;
            Ok(HandshakeFrame::Proof {
                from,
                to,
                nonce,
                proof,
            })
        }
        _ => Err(Error::Malformed("unknown handshake kind")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(fill: u8) -> PeerId {
        PeerId::of_hex(&hex::encode([fill; 7237]))
    }

    fn proof_frame() -> HandshakeFrame {
        HandshakeFrame::Proof {
            from: id(1),
            to: id(2),
            nonce: [3; 32],
            proof: [4; 32],
        }
    }

    #[test]
    fn frames_round_trip() {
        let challenge = HandshakeFrame::Challenge {
            from: id(2),
            to: id(1),
            nonce: [3; 32],
            ct: vec![5; 99],
        };
        for frame in [challenge, proof_frame()] {
            assert_eq!(decode(&encode(&frame).unwrap()).unwrap(), frame);
        }
    }

    #[test]
    fn garbage_is_refused_rather_than_panicking() {
        let good = encode(&proof_frame()).unwrap();
        let mut v1 = good.clone();
        v1[4] = 1;
        let mut kind = good.clone();
        kind[5] = 7;
        let mut zero_len = encode(&HandshakeFrame::Challenge {
            from: id(2),
            to: id(1),
            nonce: [3; 32],
            ct: vec![5; 8],
        })
        .unwrap();
        zero_len[OFF_BODY..OFF_BODY + 4].copy_from_slice(&0u32.to_be_bytes());
        for (name, bytes) in [
            ("empty", vec![]),
            ("magic only", b"HQCH".to_vec()),
            ("a v1 frame", v1),
            ("unknown kind", kind),
            ("short proof", good[..good.len() - 1].to_vec()),
            ("long proof", [good.as_slice(), &[0]].concat()),
            ("zero-length ciphertext", zero_len),
        ] {
            assert!(decode(&bytes).is_err(), "{name} must be refused");
        }
    }

    #[test]
    fn a_challenge_without_a_ciphertext_is_not_encoded() {
        let empty = HandshakeFrame::Challenge {
            from: id(2),
            to: id(1),
            nonce: [3; 32],
            ct: vec![],
        };
        assert!(encode(&empty).is_err());
    }

    #[test]
    fn a_proof_is_bound_to_its_nonce_and_secret() {
        let ss = SharedSecret::from_bytes([9; 32]);
        let base = handshake_proof(&ss, &[1; 32], &id(1), &id(2), &[0; 32]);
        assert_ne!(
            base,
            handshake_proof(&ss, &[2; 32], &id(1), &id(2), &[0; 32]),
            "nonce"
        );
        let other = SharedSecret::from_bytes([8; 32]);
        assert_ne!(
            base,
            handshake_proof(&other, &[1; 32], &id(1), &id(2), &[0; 32]),
            "secret"
        );
        assert!(proof_matches(&base, &base));
        assert!(!proof_matches(&base, &[0; 32]));
    }

    #[test]
    fn nonces_are_fresh() {
        let mut os = crate::OsEntropy;
        assert_ne!(
            handshake_nonce(&mut os).unwrap(),
            handshake_nonce(&mut os).unwrap()
        );
    }
}
