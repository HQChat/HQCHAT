//! The client-to-client frame (v3): length-prefixed binary whose header is
//! also the AAD the payload is sealed against. A receiver binds the exact
//! bytes that arrived; there is no second canonical encoding.
//!
//! ```text
//! 0   magic "HQCE" · 4 version u8 (3) · 5 kind u8 · 6 flags u8
//! 7   sender 32 B · 39 to 32 B · 71 cid 16 B · 87 n u32 · 91 pn u32
//! 95  msgIdLen u8 (1..128) · 96 msgId UTF-8
//!     [rk] [kemCt] [init: senderPk, ctId, ctMt] [oneTime: ctOt, otId]
//!     payload (each blob u32 length + bytes, big-endian)
//! ```

use hqc::{Ciphertext, PublicKey};

use crate::{Error, PeerId};

/// The frame version this crate speaks.
pub const FRAME_VERSION: u8 = 3;
/// The largest `n`, `pn` or `otId` a frame carries.
pub const MAX_COUNTER: u32 = u32::MAX;
/// The longest message id, in bytes.
pub const MAX_MSG_ID_BYTES: usize = 128;

/// Whether a frame opens a session, carries a message, or acknowledges one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A message inside a session (byte 0).
    Msg,
    /// A message that also opens the session (byte 1).
    Init,
    /// A delivery receipt for the message whose id it carries (byte 2).
    Receipt,
}

/// The handshake fields an `init` frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitFields {
    /// The initiator's identity key; must hash to `sender`.
    pub sender_pk: PublicKey,
    /// Encapsulated to the responder's identity key.
    pub ct_id: Ciphertext,
    /// Encapsulated to the responder's medium-term prekey.
    pub ct_mt: Ciphertext,
    /// Encapsulated to a one-time prekey, with its id, while the pool lasted.
    pub one_time: Option<(Ciphertext, u32)>,
}

/// Every header field: what the AAD is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Kind of frame.
    pub kind: Kind,
    /// Sender's client id.
    pub sender: PeerId,
    /// Recipient's client id.
    pub to: PeerId,
    /// Message id (1..128 bytes of UTF-8); a receipt carries the acknowledged one.
    pub msg_id: String,
    /// Chain selector: `chainId` of the sender's current ratchet key.
    pub cid: [u8; 16],
    /// Index in the sending chain.
    pub n: u32,
    /// Length of the previous sending chain.
    pub pn: u32,
    /// The sender's new ratchet public key, on a step or an init.
    pub rk: Option<PublicKey>,
    /// Encapsulated to the receiver's previous ratchet key, on a step.
    pub kem_ct: Option<Ciphertext>,
    /// On `init` only.
    pub init: Option<InitFields>,
}

/// A whole frame: header and sealed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The header.
    pub header: Header,
    /// The AES-GCM sealed payload (`aead::seal_payload`).
    pub payload: Vec<u8>,
}

/// Why these fields cannot make a well-formed frame, or `Ok` when they can.
pub fn validate(header: &Header) -> Result<(), Error> {
    todo!("lib/protocol-aead-envelope")
}

/// The header bytes: the AAD to seal the payload against.
pub fn header_bytes(header: &Header) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-aead-envelope")
}

/// The frame's wire bytes; derives the same header as [`header_bytes`].
pub fn encode(frame: &Frame) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-aead-envelope")
}

/// A cheap check of magic and version, before a full decode.
pub fn looks_like_frame(raw: &[u8]) -> bool {
    todo!("lib/protocol-aead-envelope")
}

/// Decodes a frame and returns it with its AAD, the header bytes exactly as
/// they arrived.
pub fn decode(raw: &[u8]) -> Result<(Frame, Vec<u8>), Error> {
    todo!("lib/protocol-aead-envelope")
}
