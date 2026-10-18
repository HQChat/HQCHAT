//! HKDF-SHA256 (RFC 5869) into fixed-size outputs, the one key derivation
//! every layer uses.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The longest output HKDF-SHA256 allows: 255 blocks of 32 bytes.
const MAX_OUTPUT: usize = 255 * 32;

/// `N` bytes of HKDF-SHA256 output, wiped when dropped.
pub fn hkdf_sha256<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    // HKDF fails only when asked for more than MAX_OUTPUT bytes, which this
    // refuses at compile time, so the error below cannot occur at run time.
    const { assert!(N <= MAX_OUTPUT, "HKDF-SHA256 output is at most 8160 bytes") };
    let mut out = Zeroizing::new([0u8; N]);
    #[expect(
        clippy::expect_used,
        reason = "the only failure is an output length the const assert above rules out"
    )]
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .expect("N <= 8160, checked at compile time");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_test_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf_sha256::<42>(&salt, &ikm, &info);
        assert_eq!(
            hex::encode(okm.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
