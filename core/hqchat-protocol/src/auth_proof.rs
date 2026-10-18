//! The sign-in proof: `HKDF-SHA256(ss, salt "salt", info "auth")` of the
//! secret decapsulated from the `/auth/init` challenge. The secret itself is
//! never sent, and the server keeps only this value, so the exchange is not a
//! decryption oracle.

use hqc::SharedSecret;
use subtle::ConstantTimeEq;

use crate::kdf::hkdf_sha256;

/// The proof `/auth/verify` expects for a challenge that decapsulated to `ss`.
pub fn auth_proof(ss: &SharedSecret) -> [u8; 32] {
    *hkdf_sha256::<32>(b"salt", ss.as_bytes(), b"auth")
}

/// Constant-time comparison of a presented proof against the expected one;
/// any other length is a mismatch.
pub fn proof_matches(expected: &[u8; 32], offered: &[u8]) -> bool {
    offered.len() == expected.len() && bool::from(expected.ct_eq(offered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proof_matches_node_crypto() {
        // hkdfSync("sha256", ss, "salt", "auth", 32), as auth-proof.ts computes
        // it, for ss = 255, 254, …, 224.
        let ss = SharedSecret::from_bytes(std::array::from_fn(|i| 255 - i as u8));
        assert_eq!(
            hex::encode(auth_proof(&ss)),
            "991f558722ac976ef5b5f26e30dc778048b6b6876c26a83dbad86b2014a09574"
        );
    }

    #[test]
    fn only_the_exact_proof_matches() {
        let expected = [7u8; 32];
        assert!(proof_matches(&expected, &[7u8; 32]));
        assert!(!proof_matches(&expected, &[8u8; 32]));
        assert!(!proof_matches(&expected, &[7u8; 31]));
        assert!(!proof_matches(&expected, &[]));
    }
}
