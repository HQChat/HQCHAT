//! The sign-in proof: `HKDF(ss, "auth")` of the decapsulated `/auth/init`
//! challenge. The server keeps only this value, never `ss`.

use hqc::SharedSecret;

/// The proof `/auth/verify` expects for a challenge that decapsulated to `ss`.
pub fn auth_proof(ss: &SharedSecret) -> [u8; 32] {
    todo!("lib/protocol-aead-envelope")
}

/// Constant-time comparison of a presented proof against the expected one.
pub fn proof_matches(expected: &[u8; 32], offered: &[u8]) -> bool {
    todo!("lib/protocol-aead-envelope")
}
