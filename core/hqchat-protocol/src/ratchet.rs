//! The KEM double ratchet with prekeys (docs/architecture/e2ee-protocol.md):
//! session start from a prekey bundle, the step policy, sealing and opening
//! with skipped keys, and the KDF chain under them.

use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Kem};

/// Most message keys kept for out-of-order delivery.
pub const MAX_SKIPPED: usize = 2000;
/// A sending chain steps after this long, once it has been used.
pub const RATCHET_MIN_STEP_INTERVAL_MS: i64 = 900_000;
/// A sending chain steps after this many messages.
pub const RATCHET_MAX_MESSAGES_PER_CHAIN: u32 = 32;

/// A 32-byte symmetric key: a root, a chain key or a message key. Wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(…)")
    }
}

/// One direction's chain.
#[derive(Debug, Clone)]
pub struct Chain {
    /// The chain key.
    pub ck: SymmetricKey,
    /// Next index this chain produces or expects.
    pub n: u32,
}

/// A message key kept for a message that has not arrived yet.
#[derive(Debug, Clone)]
pub struct SkippedKey {
    /// `chain_id` of the ratchet key whose chain produced it.
    pub chain: [u8; 16],
    /// Its index.
    pub n: u32,
    /// The message key.
    pub key: SymmetricKey,
}

/// What an `init` carries besides the message header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitHeader {
    /// Encapsulated to the responder's identity key.
    pub ct_id: Ciphertext,
    /// Encapsulated to the responder's medium-term prekey.
    pub ct_mt: Ciphertext,
    /// Encapsulated to a one-time prekey, with its id.
    pub one_time: Option<(Ciphertext, u32)>,
    /// The initiator's first ratchet key.
    pub rk: PublicKey,
    /// `chain_id(rk)`.
    pub cid: [u8; 16],
}

/// The per-message header; every field is bound as AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// `chain_id` of the sender's current ratchet key.
    pub cid: [u8; 16],
    /// On a step: the sender's new ratchet key.
    pub rk: Option<PublicKey>,
    /// On a step: encapsulated to the receiver's previous ratchet key.
    pub kem_ct: Option<Ciphertext>,
    /// Index in the sending chain.
    pub n: u32,
    /// Length of the previous sending chain.
    pub pn: u32,
}

/// A conversation's ratchet state. Serialized by the engine, sealed at rest.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// The root key.
    pub root: SymmetricKey,
    /// My ratchet keypair.
    pub rk: KeyPair,
    /// The peer's advertised ratchet key; `None` until the initiator hears back.
    pub peer_rk: Option<PublicKey>,
    /// The sending chain.
    pub send: Option<Chain>,
    /// The receiving chain.
    pub recv: Option<Chain>,
    /// Length of the previous sending chain (the `pn` field).
    pub prev_send_n: u32,
    /// Keys for messages that have not arrived yet.
    pub skipped: Vec<SkippedKey>,
    /// Repeated on every outbound frame until the first successful open.
    pub pending_init: Option<InitHeader>,
    /// Chains already stepped into, newest last, so a replayed step cannot
    /// re-derive the root.
    pub seen_chains: Vec<[u8; 16]>,
    /// Messages sent on the current sending chain.
    pub sent_on_chain: u32,
    /// When the current sending chain started, in milliseconds.
    pub chain_started_at: i64,
}

/// The peer's published bundle, as claimed from `/prekeys/claim`.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    /// The peer's pinned identity key.
    pub identity_pk: PublicKey,
    /// The peer's medium-term prekey.
    pub medium_pk: PublicKey,
    /// One one-time prekey and its id, while the pool lasted.
    pub one_time: Option<(PublicKey, u32)>,
}

/// My prekey secrets, to answer an `init`.
pub trait PrekeySecrets {
    /// My identity secret key.
    fn identity_sk(&self) -> &SecretKey;
    /// My medium-term prekey secret.
    fn medium_sk(&self) -> &SecretKey;
    /// The one-time secret for the id the initiator echoed, if not consumed.
    fn one_time_sk(&self, id: u32) -> Option<&SecretKey>;
}

/// What [`seal`] returns.
#[derive(Debug)]
pub struct Sealed {
    /// The message key: seal the payload with it.
    pub key: SymmetricKey,
    /// The header to frame and bind as AAD.
    pub header: MessageHeader,
    /// Present until the peer answers; see [`SessionState::pending_init`].
    pub init: Option<InitHeader>,
}

/// Initiator side: derives the root from the peer's bundle and opens a
/// sending chain, so the first message can be sent while the peer is offline.
pub fn start_as_initiator(
    kem: &dyn Kem,
    bundle: &PrekeyBundle,
    now: i64,
) -> Result<(SessionState, InitHeader), Error> {
    todo!("lib/protocol-ratchet")
}

/// Responder side: rebuilds the root from an `init`. `None` when a
/// ciphertext does not open or the one-time secret is gone; callers keep any
/// existing session then, so a replayed init cannot reset a conversation.
pub fn start_as_responder(
    kem: &dyn Kem,
    secrets: &dyn PrekeySecrets,
    init: &InitHeader,
    now: i64,
) -> Option<SessionState> {
    todo!("lib/protocol-ratchet")
}

/// Whether the next send steps the ratchet.
pub fn should_step(state: &SessionState, now: i64) -> bool {
    todo!("lib/protocol-ratchet")
}

/// Takes the next sending key, stepping first when [`should_step`] says so.
pub fn seal(kem: &dyn Kem, state: &mut SessionState, now: i64) -> Result<Sealed, Error> {
    todo!("lib/protocol-ratchet")
}

/// Finds the key for `header`. `verify` is the AEAD open and the only
/// authenticator (HQC rejects implicitly), so `state` is written only after
/// it returns true. `None` when nothing verifies.
pub fn open(
    kem: &dyn Kem,
    state: &mut SessionState,
    header: &MessageHeader,
    verify: &mut dyn FnMut(&SymmetricKey) -> bool,
) -> Option<SymmetricKey> {
    todo!("lib/protocol-ratchet")
}

/// Root and first chain from the init secrets.
pub fn init_root(
    ss_id: &SharedSecret,
    ss_mt: &SharedSecret,
    ss_ot: Option<&SharedSecret>,
) -> (SymmetricKey, SymmetricKey) {
    todo!("lib/protocol-ratchet")
}

/// Next root and chain from a step's secret.
pub fn root_step(root: &SymmetricKey, ss: &SharedSecret) -> (SymmetricKey, SymmetricKey) {
    todo!("lib/protocol-ratchet")
}

/// The message key at a chain key.
pub fn message_key(ck: &SymmetricKey) -> SymmetricKey {
    todo!("lib/protocol-ratchet")
}

/// The next chain key.
pub fn chain_next(ck: &SymmetricKey) -> SymmetricKey {
    todo!("lib/protocol-ratchet")
}

/// What walking a chain to a target index yields.
#[derive(Debug)]
pub struct ChainWalk {
    /// Keys for the indexes passed on the way, to keep as skipped.
    pub skipped: Vec<(u32, SymmetricKey)>,
    /// The target's message key.
    pub key: SymmetricKey,
    /// The chain key after the target.
    pub next_ck: SymmetricKey,
}

/// Walks a chain from `from_n` to `target_n`; refuses a walk longer than
/// [`MAX_SKIPPED`].
pub fn walk_chain(ck: &SymmetricKey, from_n: u32, target_n: u32) -> Result<ChainWalk, Error> {
    todo!("lib/protocol-ratchet")
}

/// The 16-byte selector of a ratchet key's chain.
pub fn chain_id(rk: &PublicKey) -> [u8; 16] {
    todo!("lib/protocol-ratchet")
}
