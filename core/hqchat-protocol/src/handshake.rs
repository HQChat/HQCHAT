//! Proving the initiator: before opening an unproven `init`, the responder
//! encapsulates to the sender's identity key and challenges it on the
//! friendship's handshake topic; the proof binds the init's transcript.

use hqc::{Ciphertext, SharedSecret};

use crate::ratchet::InitHeader;
use crate::{Entropy, Error, PeerId};

/// The handshake wire version.
pub const HANDSHAKE_VERSION: u8 = 2;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 32;
/// Proof length in bytes.
pub const PROOF_BYTES: usize = 32;
/// Transcript length in bytes.
pub const TRANSCRIPT_BYTES: usize = 32;

/// A challenge or its proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeFrame {
    /// The responder's challenge: a fresh nonce and a ciphertext to `to`'s
    /// identity key.
    Challenge {
        /// The responder.
        from: PeerId,
        /// The initiator.
        to: PeerId,
        /// Fresh per challenge.
        nonce: [u8; NONCE_BYTES],
        /// Encapsulated to the initiator's identity key.
        ct: Ciphertext,
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
    todo!("lib/protocol-handshake")
}

/// The digest of an init, bound into its proof, so a proof releases only the
/// frames of the init the sender actually built.
pub fn init_transcript(sender: &PeerId, to: &PeerId, init: &InitHeader) -> [u8; TRANSCRIPT_BYTES] {
    todo!("lib/protocol-handshake")
}

/// The proof for a challenge that decapsulated to `ss`.
pub fn handshake_proof(
    ss: &SharedSecret,
    nonce: &[u8; NONCE_BYTES],
    challenger: &PeerId,
    prover: &PeerId,
    transcript: &[u8; TRANSCRIPT_BYTES],
) -> [u8; PROOF_BYTES] {
    todo!("lib/protocol-handshake")
}

/// Constant-time comparison of an offered proof against the expected one.
pub fn proof_matches(expected: &[u8; PROOF_BYTES], offered: &[u8; PROOF_BYTES]) -> bool {
    todo!("lib/protocol-handshake")
}

/// The frame's wire bytes.
pub fn encode(frame: &HandshakeFrame) -> Vec<u8> {
    todo!("lib/protocol-handshake")
}

/// Decodes a handshake frame.
pub fn decode(raw: &[u8]) -> Result<HandshakeFrame, Error> {
    todo!("lib/protocol-handshake")
}
