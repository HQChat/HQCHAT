//! The MQTT CONNECT password: an Ed25519 signature by a per-session key the
//! client registered over HTTPS at sign-in or refresh
//! (docs/architecture/auth-flow.md). The signed message is
//!
//! ```text
//! "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16 raw bytes)
//! ```
//!
//! and the password is
//!
//! ```text
//! v1.<keyId: 32 hex>.<ts: unix seconds>.<nonce: 16 B base64url>.<sig: 64 B base64url>
//! ```
//!
//! The server stores only public keys. A captured CONNECT is useless after
//! its single-use nonce or its ±60 s timestamp, and cannot be moved to
//! another client id. No field can contain 0x00, so the encoding is
//! unambiguous, and the grammar is exact, so a proof has one password.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::is_lower_hex;
use crate::{Entropy, Error, PeerId};

/// The signing context.
pub const MQTT_PROOF_CONTEXT: &str = "hqchat-mqtt-connect/1";
/// The accepted distance between a timestamp and the server clock, in seconds.
pub const MQTT_PROOF_SKEW_SECONDS: i64 = 60;
/// How long the server remembers a spent nonce: the whole window in which its
/// timestamp could still be accepted.
pub const MQTT_PROOF_NONCE_TTL_SECONDS: i64 = 2 * MQTT_PROOF_SKEW_SECONDS;

// A spent nonce must outlive every timestamp that could still be accepted with it.
const _: () = assert!(MQTT_PROOF_NONCE_TTL_SECONDS >= 2 * MQTT_PROOF_SKEW_SECONDS);

/// A parsed CONNECT password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectProof {
    /// The registered signing key's id, 32 lowercase hex.
    pub key_id: String,
    /// Unix seconds on the server's clock.
    pub ts: i64,
    /// Single-use nonce.
    pub nonce: [u8; 16],
    /// Ed25519 signature over [`proof_message`].
    pub signature: [u8; 64],
}

/// A session's Ed25519 signing key; the private half lives in memory only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey([u8; 32]);

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(…)")
    }
}

impl SigningKey {
    /// A fresh key; register [`SigningKey::public_key`] as `mqttSigningKey`.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<SigningKey, Error> {
        let mut seed = [0u8; 32];
        entropy.fill(&mut seed)?;
        Ok(SigningKey(seed))
    }

    /// The key a 32-byte seed determines (RFC 8032), for vectors.
    pub fn from_seed(seed: [u8; 32]) -> SigningKey {
        SigningKey(seed)
    }

    /// The raw 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.dalek().verifying_key().to_bytes()
    }

    fn dalek(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

/// Parses a password; `None` for anything but the exact v1 shape: lowercase
/// hex key id, a timestamp without sign or leading zero (12 digits at most),
/// and canonical unpadded base64url.
pub fn parse_password(password: &str) -> Option<ConnectProof> {
    let mut parts = password.split('.');
    let (version, key_id, ts, nonce, signature) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if parts.next().is_some() || version != "v1" || !is_lower_hex(key_id, 32) {
        return None;
    }
    let digits_ok = !ts.is_empty()
        && ts.len() <= 12
        && ts.bytes().all(|b| b.is_ascii_digit())
        && (ts == "0" || !ts.starts_with('0'));
    if !digits_ok {
        return None;
    }
    Some(ConnectProof {
        key_id: key_id.to_owned(),
        ts: ts.parse().ok()?,
        nonce: canonical_base64(nonce)?,
        signature: canonical_base64(signature)?,
    })
}

/// Decodes unpadded base64url to exactly `N` bytes, only if re-encoding gives
/// the same text: spare bits in the last character must be zero.
fn canonical_base64<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let out: [u8; N] = bytes.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(out) == text).then_some(out)
}

/// Formats a proof as a password.
pub fn format_password(proof: &ConnectProof) -> String {
    format!(
        "v1.{}.{}.{}.{}",
        proof.key_id,
        proof.ts,
        URL_SAFE_NO_PAD.encode(proof.nonce),
        URL_SAFE_NO_PAD.encode(proof.signature)
    )
}

/// The exact bytes the signature covers.
pub fn proof_message(clientid: &PeerId, key_id: &str, ts: i64, nonce: &[u8; 16]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MQTT_PROOF_CONTEXT.len() + 64 + key_id.len() + 16 + 20);
    for field in [
        MQTT_PROOF_CONTEXT,
        clientid.as_str(),
        key_id,
        &ts.to_string(),
    ] {
        m.extend_from_slice(field.as_bytes());
        m.push(0);
    }
    m.extend_from_slice(nonce);
    m
}

/// Whether `ts` is within ±[`MQTT_PROOF_SKEW_SECONDS`] of `now_sec`, inclusive.
pub fn is_fresh_timestamp(ts: i64, now_sec: i64) -> bool {
    ts.abs_diff(now_sec) <= MQTT_PROOF_SKEW_SECONDS as u64
}

/// A fresh password: a new nonce every call. `now_sec` must be server time.
pub fn sign_connect(
    clientid: &PeerId,
    key_id: &str,
    key: &SigningKey,
    now_sec: i64,
    entropy: &mut dyn Entropy,
) -> Result<String, Error> {
    if !is_lower_hex(key_id, 32) {
        return Err(Error::Invalid("a key id is 32 lowercase hex characters"));
    }
    let mut nonce = [0u8; 16];
    entropy.fill(&mut nonce)?;
    let signature = key
        .dalek()
        .sign(&proof_message(clientid, key_id, now_sec, &nonce));
    Ok(format_password(&ConnectProof {
        key_id: key_id.to_owned(),
        ts: now_sec,
        nonce,
        signature: signature.to_bytes(),
    }))
}

/// Whether `signature` over `message` verifies under the raw `public_key`.
/// Strict: small-order and non-canonical keys or signatures are refused.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_plus_or_minus_skew_inclusive() {
        let now = 1_790_000_000;
        assert!(is_fresh_timestamp(now, now));
        assert!(is_fresh_timestamp(now - MQTT_PROOF_SKEW_SECONDS, now));
        assert!(is_fresh_timestamp(now + MQTT_PROOF_SKEW_SECONDS, now));
        assert!(!is_fresh_timestamp(now - MQTT_PROOF_SKEW_SECONDS - 1, now));
        assert!(!is_fresh_timestamp(now + MQTT_PROOF_SKEW_SECONDS + 1, now));
        assert!(
            !is_fresh_timestamp(i64::MIN, now),
            "no overflow at the extremes"
        );
    }

    #[test]
    fn only_a_real_key_and_signature_verify() {
        assert!(
            !verify_signature(&[0; 32], b"m", &[0; 64]),
            "the identity point is not a key"
        );
        let key = SigningKey::from_seed([1; 32]);
        assert!(!verify_signature(&key.public_key(), b"m", &[0; 64]));
    }

    #[test]
    fn sign_connect_is_accepted_and_fresh_each_time() {
        let key = SigningKey::generate(&mut crate::OsEntropy).unwrap();
        let clientid = PeerId::parse(&"ab".repeat(32)).unwrap();
        let key_id = "0f".repeat(16);
        let a = sign_connect(
            &clientid,
            &key_id,
            &key,
            1_790_000_000,
            &mut crate::OsEntropy,
        )
        .unwrap();
        let b = sign_connect(
            &clientid,
            &key_id,
            &key,
            1_790_000_000,
            &mut crate::OsEntropy,
        )
        .unwrap();
        assert_ne!(a, b, "a new nonce every CONNECT");
        for password in [a, b] {
            let p = parse_password(&password).unwrap();
            assert_eq!(p.ts, 1_790_000_000);
            let message = proof_message(&clientid, &key_id, p.ts, &p.nonce);
            assert!(verify_signature(&key.public_key(), &message, &p.signature));
        }
        assert!(sign_connect(&clientid, "ABC", &key, 0, &mut crate::OsEntropy).is_err());
    }
}
