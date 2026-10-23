//! hqn/1: MQTT over raw TCP inside a hybrid post-quantum Noise handshake
//! (docs/architecture/transport.md), ported from `noise.ts`.
//!
//! ```text
//! Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256
//!
//! <- s, s_pq                 pre-message: both server statics, pinned
//! -> e, es, kem, [payload]   msg1: the MQTT CONNECT rides here
//! <- e, ee, [payload]        msg2
//!
//! e    write/read the ephemeral X25519 key; MixHash(e)
//! es   MixKey(DH(e_client, s_server))
//! kem  (ct, ss) = HQC-256.Encaps(s_pq); EncryptAndHash(ct); MixKey(ss)
//! ee   MixKey(DH(e_client, e_server))
//! ```
//!
//! Every transport key depends on es, the HQC secret and ee, so breaking
//! X25519 or HQC alone is not enough. msg1's payload has no forward secrecy
//! against a later compromise of both server statics and is replayable; the
//! CONNECT it carries is a single-use, timestamped proof.
//!
//! Wire: the client opens with two cleartext bytes, version and key id, both
//! bound into the prologue. Every later message is a `u16` big-endian length
//! and that many bytes; a transport frame is ChaCha20-Poly1305 ciphertext of
//! at most 65535 bytes including the tag.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use hqc::{Ciphertext, KeyPair, PublicKey, SharedSecret};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::wire::{Reader, len_u16};
use crate::{Entropy, Error, Kem};

/// The wire version.
pub const HQN_VERSION: u8 = 1;
/// The Noise protocol name.
pub const HQN_PROTOCOL_NAME: &str = "Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256";
/// The prologue label.
pub const HQN_PROLOGUE_LABEL: &str = "hqchat-noise/1";
/// X25519 key and output length.
pub const DH_LEN: usize = 32;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// The largest ciphertext a `u16` length prefix can describe.
pub const MAX_FRAME: usize = 65535;
/// The largest plaintext one transport frame carries.
pub const MAX_FRAME_PLAINTEXT: usize = MAX_FRAME - TAG_LEN;

/// msg1's length for a given payload: e, the encrypted KEM ciphertext and
/// the encrypted payload. The gateway refuses any other length before doing
/// any cryptography.
pub const fn msg1_length(payload_len: usize) -> usize {
    // Saturates instead of wrapping: no message has usize::MAX bytes, so an
    // absurd payload length makes every msg1 the wrong length.
    (DH_LEN + hqc::CIPHERTEXT_BYTES + TAG_LEN + TAG_LEN).saturating_add(payload_len)
}

// ── X25519 ──────────────────────────────────────────────────────────────────

/// An X25519 secret key. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub [u8; 32]);

impl core::fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519Secret(…)")
    }
}

impl X25519Secret {
    /// A fresh secret from `entropy`.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self, Error> {
        // Filled in place: no unwiped copy of the secret is left behind.
        let mut secret = Self([0u8; 32]);
        entropy.fill(&mut secret.0)?;
        Ok(secret)
    }

    /// Its public key (RFC 7748; the secret is clamped).
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.0)).to_bytes()
    }
}

/// X25519. Refuses the all-zero result, which a low-order public key would
/// otherwise let an attacker force.
pub fn dh(secret: &X25519Secret, public: &[u8; 32]) -> Result<[u8; 32], Error> {
    let shared = x25519_dalek::StaticSecret::from(secret.0)
        .diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(Error::Invalid("X25519 produced the all-zero secret"));
    }
    Ok(shared.to_bytes())
}

// ── CipherState and SymmetricState (Noise §5.1, §5.2) ────────────────────────

/// One direction of an established channel, or the handshake's current key:
/// ChaCha20-Poly1305 with a 64-bit counter nonce.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherState {
    key: Option<[u8; 32]>,
    #[zeroize(skip)]
    nonce: u64,
}

impl core::fmt::Debug for CipherState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CipherState(n = {})", self.nonce)
    }
}

impl CipherState {
    fn new(key: Option<[u8; 32]>) -> Self {
        Self { key, nonce: 0 }
    }

    /// The nonce as ChaCha20-Poly1305 takes it: 32 zero bits, then the counter little-endian.
    fn nonce_bytes(&self) -> Result<[u8; 12], Error> {
        // 2^64 - 1 is reserved by the spec: a state that reaches it is exhausted.
        if self.nonce == u64::MAX {
            return Err(Error::Invalid("nonce exhausted"));
        }
        // 4 zero bytes, then the counter little-endian (spec §5.1, ChaChaPoly).
        let [a, b, c, d, e, f, g, h] = self.nonce.to_le_bytes();
        Ok([0, 0, 0, 0, a, b, c, d, e, f, g, h])
    }

    /// Moves to the next nonce; `nonce_bytes` already refused the reserved last one.
    fn advance_nonce(&mut self) -> Result<(), Error> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(Error::Invalid("nonce exhausted"))?;
        Ok(())
    }

    /// Encrypts with additional data; without a key, returns the plaintext.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(key) = &self.key else {
            return Ok(plaintext.to_vec());
        };
        let nonce = self.nonce_bytes()?;
        let out = ChaCha20Poly1305::new(key.into())
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Invalid("ChaCha20-Poly1305 refused the input"))?;
        self.advance_nonce()?;
        Ok(out)
    }

    /// Decrypts with additional data; without a key, returns the input. On
    /// failure the nonce does not advance, but callers treat a failure as
    /// fatal for the connection anyway.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(key) = &self.key else {
            return Ok(ciphertext.to_vec());
        };
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Malformed("ciphertext shorter than its tag"));
        }
        let nonce = self.nonce_bytes()?;
        let out = ChaCha20Poly1305::new(key.into())
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        self.advance_nonce()?;
        Ok(out)
    }

    /// Seals one transport frame's body.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_with_ad(&[], plaintext)
    }

    /// Opens one transport frame's body.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_with_ad(&[], ciphertext)
    }

    #[cfg(test)]
    pub(crate) fn set_nonce_for_testing(&mut self, n: u64) {
        self.nonce = n;
    }
}

/// The Noise HKDF (spec §4.3) with two outputs: HMAC-SHA256 chained, which
/// is RFC 5869 HKDF with the chaining key as salt and empty info.
pub fn hkdf2(chaining_key: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let temp_key = hmac_sha256(chaining_key, &[ikm]);
    let first = hmac_sha256(&temp_key, &[&[0x01]]);
    let second = hmac_sha256(&temp_key, &[first.as_slice(), &[0x02]]);
    (first, second)
}

/// HMAC-SHA256 of the concatenated `parts` under a 32-byte key, wiped when
/// dropped. RFC 2104 zero-pads a key shorter than the 64-byte block, so the
/// padded key goes in as a block and setting the key cannot fail.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut block = Zeroizing::new([0u8; 64]);
    for (b, k) in block.iter_mut().zip(key) {
        *b = *k;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new(&(*block).into());
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// The handshake's running hash, chaining key and cipher.
#[derive(Debug)]
pub struct SymmetricState {
    ck: Ck,
    /// The handshake hash: after the handshake, a channel binding.
    pub h: [u8; 32],
    cs: CipherState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Ck([u8; 32]);

impl core::fmt::Debug for Ck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ck(…)")
    }
}

impl SymmetricState {
    /// Starts from a protocol name: padded to 32 bytes, or hashed if longer.
    pub fn new(protocol_name: &str) -> Self {
        let name = protocol_name.as_bytes();
        let mut h = [0u8; 32];
        if name.len() <= 32 {
            for (slot, byte) in h.iter_mut().zip(name) {
                *slot = *byte;
            }
        } else {
            h = Sha256::digest(name).into();
        }
        Self {
            ck: Ck(h),
            h,
            cs: CipherState::new(None),
        }
    }

    /// MixKey: new chaining key and cipher key from `ikm`.
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck.0, ikm);
        self.ck = Ck(*ck);
        self.cs = CipherState::new(Some(*k));
    }

    /// MixHash: `h = SHA-256(h ‖ data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// EncryptAndHash.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let ct = self.cs.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    /// DecryptAndHash.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let pt = self.cs.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Split: the initiator's sending cipher, then the responder's.
    pub fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck.0, &[]);
        (CipherState::new(Some(*k1)), CipherState::new(Some(*k2)))
    }
}

// ── The handshake ───────────────────────────────────────────────────────────

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

impl ServerStatic {
    /// The public half, as clients pin it.
    pub fn public(&self) -> ServerStaticPublic {
        ServerStaticPublic {
            key_id: self.key_id,
            x25519: self.x25519.public_key(),
            hqc: self.hqc.public.clone(),
        }
    }
}

/// The two directions after the handshake.
#[derive(Debug)]
pub struct Transport {
    /// For what this side sends.
    pub send: CipherState,
    /// For what this side receives.
    pub recv: CipherState,
    /// The handshake hash, identical on both ends.
    pub handshake_hash: [u8; 32],
}

/// The prologue both sides bind: label, version, key id.
pub fn prologue(version: u8, key_id: u8) -> Vec<u8> {
    let mut p = HQN_PROLOGUE_LABEL.as_bytes().to_vec();
    p.extend_from_slice(&[version, key_id]);
    p
}

fn initial_state(server: &ServerStaticPublic) -> SymmetricState {
    let mut ss = SymmetricState::new(HQN_PROTOCOL_NAME);
    ss.mix_hash(&prologue(HQN_VERSION, server.key_id));
    // Pre-message `<- s, s_pq`: both statics bound into the transcript.
    ss.mix_hash(&server.x25519);
    ss.mix_hash(server.hqc.as_bytes());
    ss
}

/// The client's side of one hqn/1 connection.
#[derive(Debug)]
pub struct HqnInitiator {
    server: ServerStaticPublic,
    ss: SymmetricState,
    e: X25519Secret,
    sent: bool,
}

impl HqnInitiator {
    /// Starts a handshake to `server`, with an ephemeral key from `entropy`.
    pub fn new(server: ServerStaticPublic, entropy: &mut dyn Entropy) -> Result<Self, Error> {
        let e = X25519Secret::generate(entropy)?;
        Ok(Self {
            ss: initial_state(&server),
            server,
            e,
            sent: false,
        })
    }

    /// The two cleartext bytes a connection opens with: version and key id.
    pub fn opening(&self) -> [u8; 2] {
        [HQN_VERSION, self.server.key_id]
    }

    /// msg1 = e ‖ enc(ct) ‖ enc(payload); the payload is the MQTT CONNECT.
    pub fn write_message1(&mut self, kem: &dyn Kem, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.sent {
            return Err(Error::Invalid("message 1 already written"));
        }
        self.sent = true;
        let e_pub = self.e.public_key();
        self.ss.mix_hash(&e_pub);
        self.ss.mix_key(&dh(&self.e, &self.server.x25519)?);
        let (ct, ss) = kem.encapsulate(&self.server.hqc)?;
        let enc_ct = self.ss.encrypt_and_hash(ct.as_bytes())?;
        self.ss.mix_key(ss.as_bytes());
        let enc_payload = self.ss.encrypt_and_hash(payload)?;
        Ok([e_pub.as_slice(), &enc_ct, &enc_payload].concat())
    }

    /// msg2 = re ‖ enc(payload). Returns the payload and the transport.
    pub fn read_message2(mut self, message: &[u8]) -> Result<(Vec<u8>, Transport), Error> {
        if !self.sent {
            return Err(Error::Invalid("message 1 not written yet"));
        }
        if message.len() < DH_LEN + TAG_LEN {
            return Err(Error::Malformed("message 2 too short"));
        }
        let mut r = Reader::new(message, "message 2 too short");
        let re = *r.array::<DH_LEN>()?;
        self.ss.mix_hash(&re);
        self.ss.mix_key(&dh(&self.e, &re)?);
        let payload = self.ss.decrypt_and_hash(r.rest())?;
        let (send, recv) = self.ss.split();
        Ok((
            payload,
            Transport {
                send,
                recv,
                handshake_hash: self.ss.h,
            },
        ))
    }
}

/// The gateway's side of one hqn/1 connection. msg1 is read in two steps so
/// the HQC decapsulation can run on a worker: random bytes fail the first
/// step's tag for the cost of one X25519 and never reach decapsulation.
#[derive(Debug)]
pub struct HqnResponder {
    server: ServerStatic,
    ss: SymmetricState,
    re: Option<[u8; 32]>,
    pending_payload: Option<Vec<u8>>,
    opened: bool,
}

impl HqnResponder {
    /// Starts a handshake as `server`.
    pub fn new(server: ServerStatic) -> Self {
        let ss = initial_state(&server.public());
        Self {
            server,
            ss,
            re: None,
            pending_payload: None,
            opened: false,
        }
    }

    /// The initiator's ephemeral key, readable before any work: the gateway
    /// checks it against a replay cache ahead of decapsulation.
    pub fn ephemeral_of(message1: &[u8]) -> Result<[u8; 32], Error> {
        Reader::new(message1, "message 1 too short")
            .array::<DH_LEN>()
            .copied()
    }

    /// msg1 in one step, decapsulating with `kem`.
    pub fn read_message1(&mut self, kem: &dyn Kem, message1: &[u8]) -> Result<Vec<u8>, Error> {
        let ct = self.open_message1(message1)?;
        let ss = kem.decapsulate(&self.server.hqc.secret, &ct)?;
        self.finish_message1(&ss)
    }

    /// First half of msg1: X25519 and the tag over the KEM ciphertext, which
    /// it returns for decapsulation.
    pub fn open_message1(&mut self, message1: &[u8]) -> Result<Ciphertext, Error> {
        if self.re.is_some() {
            return Err(Error::Invalid("message 1 already read"));
        }
        if message1.len() < msg1_length(0) {
            return Err(Error::Malformed("message 1 too short"));
        }
        let mut r = Reader::new(message1, "message 1 too short");
        let re = *r.array::<DH_LEN>()?;
        let enc_ct = r.take(hqc::CIPHERTEXT_BYTES + TAG_LEN)?;
        self.re = Some(re);
        self.ss.mix_hash(&re);
        self.ss.mix_key(&dh(&self.server.x25519, &re)?);
        let ct = self.ss.decrypt_and_hash(enc_ct)?;
        self.pending_payload = Some(r.rest().to_vec());
        Ok(Ciphertext::from_bytes(&ct)?)
    }

    /// Second half of msg1: mix the KEM secret in and open the payload (the CONNECT).
    pub fn finish_message1(&mut self, shared_secret: &SharedSecret) -> Result<Vec<u8>, Error> {
        let enc = self
            .pending_payload
            .take()
            .ok_or(Error::Invalid("message 1 not opened"))?;
        self.ss.mix_key(shared_secret.as_bytes());
        let payload = self.ss.decrypt_and_hash(&enc)?;
        self.opened = true;
        Ok(payload)
    }

    /// msg2 with an ephemeral key from `entropy`; returns it and the transport.
    pub fn write_message2(
        mut self,
        payload: &[u8],
        entropy: &mut dyn Entropy,
    ) -> Result<(Vec<u8>, Transport), Error> {
        let re = match (self.re, self.opened) {
            (Some(re), true) => re,
            _ => return Err(Error::Invalid("message 1 not read yet")),
        };
        let e = X25519Secret::generate(entropy)?;
        let e_pub = e.public_key();
        self.ss.mix_hash(&e_pub);
        self.ss.mix_key(&dh(&e, &re)?);
        let enc = self.ss.encrypt_and_hash(payload)?;
        let (c1, c2) = self.ss.split();
        let message = [e_pub.as_slice(), &enc].concat();
        Ok((
            message,
            Transport {
                send: c2,
                recv: c1,
                handshake_hash: self.ss.h,
            },
        ))
    }
}

// ── Plain NK, for the published vectors ─────────────────────────────────────
//
// hqn/1 is NK with one extra token. Running plain NK through the same
// SymmetricState, dh and AEAD, and matching the published
// Noise_NK_25519_ChaChaPoly_SHA256 vector, shows the core is Noise and not
// merely self-consistent.

/// Plain NK message 1 from the initiator.
pub fn nk_initiator_message1(
    prologue: &[u8],
    rs: &[u8; 32],
    e: &X25519Secret,
    payload: &[u8],
) -> Result<(Vec<u8>, SymmetricState), Error> {
    let mut ss = SymmetricState::new("Noise_NK_25519_ChaChaPoly_SHA256");
    ss.mix_hash(prologue);
    ss.mix_hash(rs);
    let e_pub = e.public_key();
    ss.mix_hash(&e_pub);
    ss.mix_key(&dh(e, rs)?);
    let enc = ss.encrypt_and_hash(payload)?;
    Ok(([e_pub.as_slice(), &enc].concat(), ss))
}

/// Plain NK message 2 from the responder: returns message 1's payload,
/// message 2 and the state.
pub fn nk_responder_message2(
    prologue: &[u8],
    s: &X25519Secret,
    message1: &[u8],
    e: &X25519Secret,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, SymmetricState), Error> {
    let mut ss = SymmetricState::new("Noise_NK_25519_ChaChaPoly_SHA256");
    ss.mix_hash(prologue);
    ss.mix_hash(&s.public_key());
    let mut r = Reader::new(message1, "message 1 too short");
    let re = *r.array::<DH_LEN>()?;
    ss.mix_hash(&re);
    ss.mix_key(&dh(s, &re)?);
    let payload1 = ss.decrypt_and_hash(r.rest())?;
    let e_pub = e.public_key();
    ss.mix_hash(&e_pub);
    ss.mix_key(&dh(e, &re)?);
    let enc = ss.encrypt_and_hash(payload)?;
    Ok((payload1, [e_pub.as_slice(), &enc].concat(), ss))
}

// ── Framing ─────────────────────────────────────────────────────────────────

/// One length-prefixed message or transport frame.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_FRAME {
        return Err(Error::Invalid("frame too large"));
    }
    let len = len_u16(body.len(), "frame too large")?;
    let mut out = Vec::with_capacity(body.len().saturating_add(2));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Seals a byte stream chunk into as few transport frames as it needs.
pub fn seal_frames(send: &mut CipherState, data: &[u8]) -> Result<Vec<u8>, Error> {
    let frames = data.len().div_ceil(MAX_FRAME_PLAINTEXT);
    let overhead = frames.saturating_mul(2 + TAG_LEN);
    let mut out = Vec::with_capacity(data.len().saturating_add(overhead));
    for chunk in data.chunks(MAX_FRAME_PLAINTEXT) {
        out.extend_from_slice(&frame(&send.encrypt(chunk)?)?);
    }
    Ok(out)
}

/// Reassembles length-prefixed frames from a byte stream. A caller that
/// drains [`FrameReader::next_frame`] after every push holds at most one
/// partial frame: 65537 bytes, whatever the peer sends.
#[derive(Debug, Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    /// Appends bytes as they arrive.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// The next complete frame body, if one has arrived.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.buffer, "partial frame");
        let len = usize::from(r.u16().ok()?);
        let body = r.take(len).ok()?.to_vec();
        self.buffer.drain(..len.saturating_add(2));
        Some(body)
    }

    /// Bytes buffered and not yet a whole frame.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nonce_counter_refuses_to_wrap() {
        let mut cs = CipherState::new(Some([1; 32]));
        cs.set_nonce_for_testing(u64::MAX - 1);
        assert!(cs.encrypt(b"last").is_ok());
        assert!(cs.encrypt(b"one too many").is_err());
    }

    #[test]
    fn frames_reassemble_from_any_split_and_a_frame_cannot_exceed_u16() {
        let bytes: Vec<u8> = [
            frame(b"one").unwrap(),
            frame(b"").unwrap(),
            frame(&[7; 300]).unwrap(),
        ]
        .concat();
        for split in 0..bytes.len() {
            let mut r = FrameReader::default();
            let mut got = vec![];
            for part in [&bytes[..split], &bytes[split..]] {
                r.push(part);
                while let Some(f) = r.next_frame() {
                    got.push(f);
                }
            }
            assert_eq!(
                got,
                vec![b"one".to_vec(), vec![], vec![7; 300]],
                "split at {split}"
            );
            assert_eq!(r.pending(), 0);
        }
        assert!(frame(&vec![0; MAX_FRAME + 1]).is_err());
    }
}
