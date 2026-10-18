//! Client ids: `id = sha256(lowercase hex of the public key)`, 64 hex chars.
//! An id commits to its key and proves nothing on its own.

use hqc::PublicKey;

use crate::Error;

/// Length of an id in hex characters.
pub const PEER_ID_LENGTH: usize = 64;

/// A client id: 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(String);

impl PeerId {
    /// The id a public key hashes to.
    pub fn of(public_key: &PublicKey) -> PeerId {
        todo!("lib/protocol-identity-topics")
    }

    /// Reads an id; refuses anything but 64 lowercase hex characters.
    pub fn parse(value: &str) -> Result<PeerId, Error> {
        todo!("lib/protocol-identity-topics")
    }

    /// The id as hex.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id's 32 bytes, as frames carry it.
    pub fn to_bytes(&self) -> [u8; 32] {
        todo!("lib/protocol-identity-topics")
    }

    /// Whether `public_key` hashes to this id.
    pub fn matches(&self, public_key: &PublicKey) -> bool {
        todo!("lib/protocol-identity-topics")
    }
}
