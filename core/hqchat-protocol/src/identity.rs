//! Client ids: `id = sha256(lowercase hex of the public key)`, 64 hex chars.
//! An id commits to its key and proves nothing on its own: anyone holding the
//! public key can compute it. A received key that does not hash to the id it
//! claims must be refused, never pinned.

use hqc::PublicKey;
use sha2::{Digest, Sha256};

use crate::Error;

/// Length of an id in hex characters.
pub const PEER_ID_LENGTH: usize = 64;

/// A client id: 32 bytes, shown as 64 lowercase hex characters. Both forms
/// are kept, built together, so neither can be invalid and converting
/// between them cannot fail. Lowercase hex sorts as the bytes do, so the
/// derived order and equality agree with the hex the other clients compare.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    bytes: [u8; 32],
    hex: String,
}

impl PeerId {
    /// The id a public key hashes to.
    pub fn of(public_key: &PublicKey) -> PeerId {
        Self::of_hex(&hex::encode(public_key.as_bytes()))
    }

    /// The id of a public key given as hex in either case: the digest is over
    /// the lowercase hex text, not the key bytes.
    pub fn of_hex(public_key_hex: &str) -> PeerId {
        Self::from_bytes(&Sha256::digest(public_key_hex.to_ascii_lowercase()).into())
    }

    /// Reads an id; refuses anything but 64 lowercase hex characters.
    pub fn parse(value: &str) -> Result<PeerId, Error> {
        let mut bytes = [0u8; 32];
        if !is_lower_hex(value, PEER_ID_LENGTH) || hex::decode_to_slice(value, &mut bytes).is_err() {
            return Err(Error::Malformed("an id is 64 lowercase hex characters"));
        }
        Ok(Self::from_bytes(&bytes))
    }

    /// The id's 32 bytes, as frames carry it.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// The id that 32 frame bytes carry.
    pub fn from_bytes(bytes: &[u8; 32]) -> PeerId {
        PeerId {
            bytes: *bytes,
            hex: hex::encode(bytes),
        }
    }

    /// The id as hex.
    pub fn as_str(&self) -> &str {
        &self.hex
    }

    /// Whether `public_key` hashes to this id.
    pub fn matches(&self, public_key: &PublicKey) -> bool {
        Self::of(public_key) == *self
    }
}

impl core::fmt::Display for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.hex)
    }
}

/// Exactly `len` characters of lowercase hex, and nothing else.
pub(crate) fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "f25f33617a50eb83c2d695798e186e0ef2fb91018220e8383cf8577cc905e231";

    #[test]
    fn parse_takes_exactly_64_lowercase_hex() {
        assert_eq!(PeerId::parse(ID).unwrap().as_str(), ID);
        assert!(PeerId::parse(&ID.to_uppercase()).is_err());
        assert!(PeerId::parse(&ID[1..]).is_err());
        assert!(PeerId::parse(&format!("{ID}0")).is_err());
        assert!(PeerId::parse(&ID.replace('f', "g")).is_err());
        assert!(PeerId::parse("").is_err());
    }

    #[test]
    fn bytes_round_trip() {
        let id = PeerId::parse(ID).unwrap();
        assert_eq!(PeerId::from_bytes(&id.to_bytes()), id);
    }

    #[test]
    fn a_key_matches_its_own_id_only() {
        let a = hqc::generate_keypair().unwrap().public;
        let b = hqc::generate_keypair().unwrap().public;
        let id = PeerId::of(&a);
        assert!(id.matches(&a));
        assert!(!id.matches(&b));
    }
}
