//! The sign-in proof (v2). `/auth/init` encapsulates to the account's
//! public key; the client proves it could decapsulate by returning
//!
//! ```text
//! HKDF-SHA256(ikm = ss, salt = "hqchat/v2/sign-in",
//!             info = "hqchat/v2/sign-in" ‖ len‖origin ‖ SHA-256(pk) ‖ SHA-256(ct))
//! ```
//!
//! The secret itself is never sent, and the server keeps only the expected
//! proof (never `ss`: [`challenge`] drops it before returning), so the
//! exchange is not a decryption oracle. The proof is bound to the origin
//! the client signed in at, to the key and to that one challenge: a server
//! that relays a client's sign-in to another cannot use the answer there.

use hqc::{Ciphertext, PublicKey, SharedSecret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Error;
use crate::kdf::hkdf_sha256;
use crate::wire::len_u8;

const LABEL: &[u8] = b"hqchat/v2/sign-in";

/// The origin as both sides bind it: `scheme://host[:port]`, lowercase,
/// with no path and the scheme's default port left out. `None` for anything
/// that is not an http(s) URL.
pub fn origin_of(url: &str) -> Option<String> {
    let url = url.trim().to_ascii_lowercase();
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.strip_suffix(default_port).unwrap_or(authority);
    Some(format!("{scheme}://{authority}"))
}

/// The proof `/auth/verify` expects for a challenge `ct` to `pk` that
/// decapsulated to `ss`, signed in at `origin` (as [`origin_of`] gives it).
pub fn sign_in_proof(
    ss: &SharedSecret,
    origin: &str,
    pk: &PublicKey,
    ct: &Ciphertext,
) -> Result<[u8; 32], Error> {
    let mut info = LABEL.to_vec();
    info.push(len_u8(origin.len(), "an origin is at most 255 bytes")?);
    info.extend_from_slice(origin.as_bytes());
    info.extend_from_slice(&Sha256::digest(pk.as_bytes()));
    info.extend_from_slice(&Sha256::digest(ct.as_bytes()));
    Ok(*hkdf_sha256::<32>(LABEL, ss.as_bytes(), &info))
}

/// The server's side: a challenge to `pk` for a sign-in at `origin`, and the
/// proof that answers it. The shared secret does not outlive this call.
pub fn challenge(pk: &PublicKey, origin: &str) -> Result<(Ciphertext, [u8; 32]), Error> {
    let (ct, ss) = hqc::encapsulate(pk)?;
    let proof = sign_in_proof(&ss, origin, pk, &ct)?;
    Ok((ct, proof))
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
    fn an_origin_has_one_form() {
        for (url, origin) in [
            ("https://API.hqchat.app/", Some("https://api.hqchat.app")),
            (
                "https://api.hqchat.app:443/x?y",
                Some("https://api.hqchat.app"),
            ),
            ("http://127.0.0.1:8090", Some("http://127.0.0.1:8090")),
            ("http://127.0.0.1:80", Some("http://127.0.0.1")),
            ("ftp://x", None),
            ("https://user@host", None),
            ("https://", None),
        ] {
            assert_eq!(origin_of(url).as_deref(), origin, "{url}");
        }
    }

    #[test]
    fn the_proof_is_bound_to_origin_key_and_challenge() {
        let a = hqc::generate_keypair().unwrap();
        let b = hqc::generate_keypair().unwrap();
        let (ct, expected) = challenge(&a.public, "https://api.hqchat.app").unwrap();
        let ss = hqc::decapsulate(&a.secret, &ct).unwrap();
        let proof = |origin: &str, pk: &PublicKey, ct: &Ciphertext| {
            sign_in_proof(&ss, origin, pk, ct).unwrap()
        };
        assert!(proof_matches(
            &expected,
            &proof("https://api.hqchat.app", &a.public, &ct)
        ));
        assert!(!proof_matches(
            &expected,
            &proof("https://evil.example", &a.public, &ct)
        ));
        assert!(!proof_matches(
            &expected,
            &proof("https://api.hqchat.app", &b.public, &ct)
        ));
        let (other_ct, _) = hqc::encapsulate(&a.public).unwrap();
        assert!(!proof_matches(
            &expected,
            &proof("https://api.hqchat.app", &a.public, &other_ct)
        ));
    }

    #[test]
    fn the_proof_matches_its_vector() {
        // Shared with services/server/test/reference/protocol/auth-proof.ts.
        let pair = hqc::keypair_from_seed(&hqc::Seed::from_bytes([3; 32])).unwrap();
        let ct = Ciphertext::from_bytes(&[7; hqc::CIPHERTEXT_BYTES]).unwrap();
        let ss = SharedSecret::from_bytes(std::array::from_fn(|i| 255 - i as u8));
        let p = sign_in_proof(&ss, "https://api.hqchat.app", &pair.public, &ct).unwrap();
        assert_eq!(hex::encode(p), VECTOR);
    }

    const VECTOR: &str = "ec47c5b474c9250f750aef96ad5c2161160eedd167a9c04bc6d2aa1f30f83fd4";

    #[test]
    fn only_the_exact_proof_matches() {
        let expected = [7u8; 32];
        assert!(proof_matches(&expected, &[7u8; 32]));
        assert!(!proof_matches(&expected, &[8u8; 32]));
        assert!(!proof_matches(&expected, &[7u8; 31]));
        assert!(!proof_matches(&expected, &[]));
    }
}
