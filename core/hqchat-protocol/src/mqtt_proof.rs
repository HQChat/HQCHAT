//! The MQTT CONNECT password: a fresh Ed25519 proof per CONNECT
//! (docs/architecture/auth-flow.md).
//!
//! ```text
//! signed   = "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16)
//! password = v1.<keyId: 32 hex>.<ts>.<nonce: base64url>.<signature: base64url>
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Entropy, Error, PeerId};

/// The signing context.
pub const MQTT_PROOF_CONTEXT: &str = "hqchat-mqtt-connect/1";
/// The accepted clock difference, in seconds.
pub const MQTT_PROOF_SKEW_SECONDS: i64 = 60;
/// How long the server remembers a spent nonce, in seconds.
pub const MQTT_PROOF_NONCE_TTL_SECONDS: i64 = 2 * MQTT_PROOF_SKEW_SECONDS;

/// A parsed CONNECT password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectProof {
    /// The registered signing key's id, 32 hex.
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
        todo!("lib/protocol-mqtt-proof")
    }

    /// The raw 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        todo!("lib/protocol-mqtt-proof")
    }
}

/// Parses a password; `None` for anything off the exact shape.
pub fn parse_password(password: &str) -> Option<ConnectProof> {
    todo!("lib/protocol-mqtt-proof")
}

/// Formats a proof as a password.
pub fn format_password(proof: &ConnectProof) -> String {
    todo!("lib/protocol-mqtt-proof")
}

/// The bytes the signature covers.
pub fn proof_message(clientid: &PeerId, key_id: &str, ts: i64, nonce: &[u8; 16]) -> Vec<u8> {
    todo!("lib/protocol-mqtt-proof")
}

/// Whether `ts` is within the skew of `now_sec` (server clock).
pub fn is_fresh_timestamp(ts: i64, now_sec: i64) -> bool {
    todo!("lib/protocol-mqtt-proof")
}

/// A fresh password: new nonce every call. `now_sec` must be server time.
pub fn sign_connect(
    clientid: &PeerId,
    key_id: &str,
    key: &SigningKey,
    now_sec: i64,
    entropy: &mut dyn Entropy,
) -> Result<String, Error> {
    todo!("lib/protocol-mqtt-proof")
}

/// Whether `signature` over `message` verifies under the raw `public_key`.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    todo!("lib/protocol-mqtt-proof")
}
