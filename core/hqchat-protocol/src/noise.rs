//! hqn/1: MQTT over `Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256`
//! (docs/architecture/transport.md). The client knows the gateway's static
//! X25519 and HQC keys in advance and stays anonymous at this layer.
//!
//! ```text
//! <- s, s_pq                  pre-message: both gateway statics
//! -> e, es, kem, [CONNECT]    msg1 (~14.7 kB)
//! <- e, ee, [ ]               msg2, then CONNACK as the first transport frame
//! ```

use hqc::{Ciphertext, KeyPair, PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Entropy, Error, Kem};

/// The wire version.
pub const HQN_VERSION: u8 = 1;
/// The Noise protocol name.
pub const HQN_PROTOCOL_NAME: &str = "Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256";
/// The prologue label.
pub const HQN_PROLOGUE_LABEL: &str = "hqchat-noise/1";
/// The largest transport frame.
pub const MAX_FRAME: usize = 65535;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;

/// An X25519 secret key. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub [u8; 32]);

impl core::fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519Secret(…)")
    }
}

/// The gateway's static keys, as `GET /auth/transport` advertises them.
#[derive(Debug, Clone)]
pub struct ServerStaticPublic {
    /// Which key pair, during a rotation.
    pub key_id: u8,
    /// The X25519 public key.
    pub x25519: [u8; 32],
    /// The HQC public key.
    pub hqc: PublicKey,
}

/// The gateway's static keys with their secrets.
#[derive(Debug, Clone)]
pub struct ServerStatic {
    /// Which key pair, during a rotation.
    pub key_id: u8,
    /// The X25519 secret key.
    pub x25519: X25519Secret,
    /// The HQC key pair.
    pub hqc: KeyPair,
}

/// One direction of an established channel: ChaCha20-Poly1305 with a counter nonce.
#[derive(Debug)]
pub struct CipherState {
    key: [u8; 32],
    nonce: u64,
}

impl CipherState {
    /// Seals one transport frame's body.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        todo!("lib/protocol-noise")
    }

    /// Opens one transport frame's body.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        todo!("lib/protocol-noise")
    }
}

/// The two directions after the handshake.
#[derive(Debug)]
pub struct Transport {
    /// For what this side sends.
    pub send: CipherState,
    /// For what this side receives.
    pub recv: CipherState,
    /// The final handshake hash.
    pub handshake_hash: [u8; 32],
}

/// The client's side of one hqn/1 connection.
#[derive(Debug)]
pub struct HqnInitiator {
    server: ServerStaticPublic,
}

impl HqnInitiator {
    /// Starts a handshake to `server`, with a fresh ephemeral key.
    pub fn new(server: ServerStaticPublic, entropy: &mut dyn Entropy) -> Result<Self, Error> {
        todo!("lib/protocol-noise")
    }

    /// The two cleartext bytes a connection opens with: version and key id.
    pub fn opening(&self) -> [u8; 2] {
        todo!("lib/protocol-noise")
    }

    /// msg1 = e ‖ enc(ct) ‖ enc(payload); the payload is the MQTT CONNECT.
    pub fn write_message1(&mut self, kem: &dyn Kem, payload: &[u8]) -> Result<Vec<u8>, Error> {
        todo!("lib/protocol-noise")
    }

    /// msg2 = re ‖ enc(payload). Returns the payload and the transport.
    pub fn read_message2(self, message: &[u8]) -> Result<(Vec<u8>, Transport), Error> {
        todo!("lib/protocol-noise")
    }
}

/// The gateway's side of one hqn/1 connection. Message 1 is read in three
/// steps so the HQC decapsulation can run on a worker thread.
#[derive(Debug)]
pub struct HqnResponder {
    server: ServerStatic,
}

impl HqnResponder {
    /// Starts a handshake as `server`.
    pub fn new(server: ServerStatic) -> Self {
        todo!("lib/protocol-noise")
    }

    /// The initiator's ephemeral key, read from msg1 before any work.
    pub fn ephemeral_of(message1: &[u8]) -> Result<[u8; 32], Error> {
        todo!("lib/protocol-noise")
    }

    /// Reads msg1 up to the KEM ciphertext, which it returns for decapsulation.
    pub fn open_message1(&mut self, message1: &[u8]) -> Result<Ciphertext, Error> {
        todo!("lib/protocol-noise")
    }

    /// Finishes msg1 with the decapsulated secret; returns the payload (CONNECT).
    pub fn finish_message1(&mut self, shared_secret: &SharedSecret) -> Result<Vec<u8>, Error> {
        todo!("lib/protocol-noise")
    }

    /// msg2 with a fresh ephemeral key; returns it and the transport.
    pub fn write_message2(
        self,
        payload: &[u8],
        entropy: &mut dyn Entropy,
    ) -> Result<(Vec<u8>, Transport), Error> {
        todo!("lib/protocol-noise")
    }
}

/// The prologue both sides bind: label, version, key id.
pub fn prologue(version: u8, key_id: u8) -> Vec<u8> {
    todo!("lib/protocol-noise")
}

/// A `u16` big-endian length and the body.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-noise")
}

/// Seals `data` as transport frames, split at the frame limit.
pub fn seal_frames(send: &mut CipherState, data: &[u8]) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-noise")
}

/// Reassembles length-prefixed frames from a byte stream.
#[derive(Debug, Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    /// Appends bytes as they arrive.
    pub fn push(&mut self, chunk: &[u8]) {
        todo!("lib/protocol-noise")
    }

    /// The next complete frame body, if one has arrived.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        todo!("lib/protocol-noise")
    }

    /// Bytes buffered and not yet a whole frame.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}
