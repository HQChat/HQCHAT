//! AES-256-GCM for message payloads, laid out `IV (12) ‖ tag (16) ‖
//! ciphertext` as in the Swift `AESService` and the TS `aead.ts`. The frame
//! header is always bound as AAD.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;

use crate::wire::Reader;
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
    let mut iv = [0u8; IV_BYTES];
    entropy.fill(&mut iv)?;
    let mut ciphertext = plaintext.to_vec();
    let tag = Aes256Gcm::new(key.into())
        .encrypt_in_place_detached(&iv.into(), aad, &mut ciphertext)
        .map_err(|_| Error::Invalid("payload too large for AES-GCM"))?;
    let mut out = Vec::with_capacity((IV_BYTES + TAG_BYTES).saturating_add(ciphertext.len()));
    out.extend_from_slice(&iv);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens what [`seal_payload`] produced; [`Error::Authentication`] when the
/// key, the AAD or any byte differs.
pub fn open_payload(sealed: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(sealed, "payload shorter than IV and tag");
    let iv: &[u8; IV_BYTES] = r.array()?;
    let tag: &[u8; TAG_BYTES] = r.array()?;
    let mut plaintext = r.rest().to_vec();
    Aes256Gcm::new(key.into())
        .decrypt_in_place_detached(&(*iv).into(), aad, &mut plaintext, &(*tag).into())
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Yields 0, 1, 2, … so the IV is known.
    struct Counting(u8);

    impl Entropy for Counting {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    const KEY: [u8; 32] = [0x42; 32];
    const AAD: &[u8] = b"header-bytes";

    #[test]
    fn sealing_matches_node_crypto_byte_for_byte() {
        // Node's aes-256-gcm (what aead.ts calls) with the same key, IV 0..11,
        // AAD and plaintext, laid out IV ‖ tag ‖ ciphertext.
        let sealed =
            seal_payload("hello, café 🔒".as_bytes(), &KEY, AAD, &mut Counting(0)).unwrap();
        assert_eq!(
            hex::encode(&sealed),
            "000102030405060708090a0b6ec26c454e9bc2411cb3da64dfddce9f6dbbfdb1de00d268fc6087baf12dc4afa0"
        );
        assert_eq!(
            open_payload(&sealed, &KEY, AAD).unwrap(),
            "hello, café 🔒".as_bytes()
        );
    }

    #[test]
    fn a_wrong_key_aad_or_byte_does_not_authenticate() {
        let sealed = seal_payload(b"text", &KEY, AAD, &mut crate::OsEntropy).unwrap();
        assert_eq!(
            open_payload(&sealed, &[0x43; 32], AAD),
            Err(Error::Authentication)
        );
        assert_eq!(
            open_payload(&sealed, &KEY, b"other"),
            Err(Error::Authentication)
        );
        for i in 0..sealed.len() {
            let mut flipped = sealed.clone();
            flipped[i] ^= 1;
            assert_eq!(
                open_payload(&flipped, &KEY, AAD),
                Err(Error::Authentication),
                "byte {i}"
            );
        }
    }

    #[test]
    fn an_empty_plaintext_seals_and_a_short_payload_is_refused() {
        let sealed = seal_payload(b"", &KEY, AAD, &mut crate::OsEntropy).unwrap();
        assert_eq!(sealed.len(), IV_BYTES + TAG_BYTES);
        assert_eq!(open_payload(&sealed, &KEY, AAD).unwrap(), b"");
        assert!(matches!(
            open_payload(&sealed[..27], &KEY, AAD),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn every_seal_uses_a_fresh_iv() {
        let a = seal_payload(b"same", &KEY, AAD, &mut crate::OsEntropy).unwrap();
        let b = seal_payload(b"same", &KEY, AAD, &mut crate::OsEntropy).unwrap();
        assert_ne!(a[..IV_BYTES], b[..IV_BYTES]);
    }
}
