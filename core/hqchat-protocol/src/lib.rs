//! What two HQChat clients and the server say to each other, byte for byte:
//! the port of `services/server/test/reference/protocol/` plus the MQTT 3.1.1 codec.
//!
//! Pure: no I/O, no clock (callers pass `now`), no global randomness
//! (callers pass an [`Entropy`]), so every function replays its vectors
//! exactly. The tests read the vector files in
//! `services/server/test/helpers/` in place, so the TS, Swift and Rust suites
//! share one copy of each.

pub mod aead;
pub mod auth_proof;
pub mod envelope;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod mqtt;
pub mod mqtt_proof;
pub mod noise;
pub mod ratchet;
pub mod topics;
pub mod wire;

pub use identity::PeerId;
pub use kem::{HqcKem, Kem};

/// Randomness the protocol draws: nonces, IVs, ephemeral keys. Production
/// passes [`OsEntropy`]; vectors pass a fixed stream.
pub trait Entropy {
    /// Fills `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// The OS random generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Entropy)
    }
}

/// Why a protocol operation failed. Decoding failures carry the reason a
/// frame was dropped, as the TS and Swift clients log it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The HQC layer failed.
    Hqc(hqc::Error),
    /// The OS random generator failed.
    Entropy,
    /// Bytes that are not a well-formed frame of the expected kind.
    Malformed(&'static str),
    /// Fields that cannot make a well-formed frame; encoders refuse rather
    /// than pad, clip or wrap.
    Invalid(&'static str),
    /// An AEAD tag did not verify.
    Authentication,
}

impl From<hqc::Error> for Error {
    fn from(e: hqc::Error) -> Self {
        Error::Hqc(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Hqc(e) => write!(f, "{e}"),
            Error::Entropy => f.write_str("the OS random generator failed"),
            Error::Malformed(why) => write!(f, "malformed: {why}"),
            Error::Invalid(why) => write!(f, "invalid: {why}"),
            Error::Authentication => f.write_str("did not authenticate"),
        }
    }
}

impl std::error::Error for Error {}
