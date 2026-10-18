//! AES-256-GCM for message payloads: 12-byte IV, 16-byte tag, the frame
//! header as AAD. Sealed bytes are `iv ‖ ciphertext ‖ tag`.

use crate::{Entropy, Error};

/// IV length in bytes.
pub const IV_BYTES: usize = 12;
/// Tag length in bytes.
pub const TAG_BYTES: usize = 16;

/// Seals `plaintext` under `key`, bound to `aad`, with a fresh IV.
pub fn seal_payload(
    plaintext: &[u8],
    key: &[u8; 32],
    aad: &[u8],
    entropy: &mut dyn Entropy,
) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-aead-envelope")
}

/// Opens what [`seal_payload`] produced; [`Error::Authentication`] when the
/// key, the AAD or any byte differs.
pub fn open_payload(sealed: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-aead-envelope")
}
