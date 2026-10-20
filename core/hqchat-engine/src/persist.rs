//! What the engine stores and how it is sealed.
//!
//! | Key | Sealed with | Holds |
//! |---|---|---|
//! | `state` | the device key (ECIES) and the vault's state secret | identity, prekey secrets, friend directory, `data_key` |
//! | `session/{peer tag}` | `data_key` | one ratchet session |
//! | `msg/{peer tag}/{at}/{id tag}` | `data_key` | one message |
//! | `pending/{seq}` | the device key | an inbound frame that arrived while locked |
//!
//! `state` joins the vault's 256-bit state secret to the ECDH secret in its
//! KDF, so it does not rest on P-256 alone; it is only ever written while
//! unlocked. Pending frames, sealed while locked, are ratchet ciphertext
//! already, and need no more than the device key.
//!
//! Device sealing is ECIES on P-256: a fresh ephemeral key, ECDH with the
//! device public key (no user needed, so it works while locked), HKDF-SHA256
//! over the secret and both public keys, AES-256-GCM. Opening needs one
//! [`KeyVault::agree`], the hardware ECDH; unlocking opens `state` alone, and
//! everything else is under the `data_key` it holds. Every blob is bound to
//! its key as AAD, so blobs cannot be swapped between slots.
//!
//! Plaintext is `postcard`, versioned by the first field of each record.
//!
//! Slot names never hold a friend's id or a message id: a copy of the store
//! would otherwise list who the user talks to, and the ids the server saw.
//! Both are tagged with a key derived from `data_key` ([`SlotNames`]). The
//! time of each message stays in its name, which orders the history.

use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey};
use hqchat_protocol::kdf::hkdf_sha256;
use hqchat_protocol::ratchet::{Chain, InitHeader, SessionState, SkippedKey, SymmetricKey};
use hqchat_protocol::wire::Reader;
use hqchat_protocol::{OsEntropy, PeerId, aead};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ports::{KeyVault, Store};
use crate::types::{CoreError, Delivery};

/// The version of every record this module writes.
pub(crate) const FORMAT: u16 = 1;
const SEAL_VERSION: u8 = 1;
const STATE_SEAL_VERSION: u8 = 2;
const P256_POINT: usize = 65;

pub(crate) const STATE: &str = "state";

pub(crate) const SESSION_PREFIX: &str = "session/";
pub(crate) const MESSAGE_PREFIX: &str = "msg/";

/// Names slots by keyed tags of a friend's id and of message ids. Derived
/// from `data_key`, and kept after a lock: a friend can be forgotten, and
/// the list can tell who has a session, while locked.
pub(crate) struct SlotNames(Zeroizing<[u8; 32]>);

impl SlotNames {
    pub(crate) fn of(data_key: &[u8; 32]) -> Self {
        Self(hkdf_sha256::<32>(
            b"hqchat/v1/at-rest",
            data_key,
            b"hqchat/v1/slot-names",
        ))
    }

    fn tag(&self, what: &str, value: &str) -> String {
        hex::encode(*hkdf_sha256::<16>(
            self.0.as_ref(),
            value.as_bytes(),
            what.as_bytes(),
        ))
    }

    pub(crate) fn session(&self, peer: &PeerId) -> String {
        format!(
            "{SESSION_PREFIX}{}",
            self.tag("hqchat/v1/slot/peer", peer.as_str())
        )
    }

    pub(crate) fn messages_prefix(&self, peer: &PeerId) -> String {
        format!(
            "{MESSAGE_PREFIX}{}/",
            self.tag("hqchat/v1/slot/peer", peer.as_str())
        )
    }

    /// Sorted by time, then id: the store lists keys in order.
    pub(crate) fn message(&self, peer: &PeerId, at: i64, msg_id: &str) -> String {
        format!(
            "{}{:020}/{}",
            self.messages_prefix(peer),
            at.max(0),
            self.message_tag(msg_id)
        )
    }

    pub(crate) fn message_tag(&self, msg_id: &str) -> String {
        self.tag("hqchat/v1/slot/message", msg_id)
    }
}

pub(crate) const PENDING_PREFIX: &str = "pending/";

/// Sorted by arrival: the device clock, then a per-process counter. A
/// counter in `state` would not do: `state` cannot be rewritten while locked.
pub(crate) fn pending_slot(at: i64, seq: u64) -> String {
    format!("pending/{:020}/{seq:010}", at.max(0))
}

// ── Sealing ────────────────────────────────────────────────────────────────

fn device_kdf(shared: &[u8], ephemeral: &[u8], device: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut info = b"hqchat/at-rest/v1".to_vec();
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(device);
    hkdf_sha256::<32>(b"salt", shared, &info)
}

fn protocol(e: hqchat_protocol::Error) -> CoreError {
    CoreError::from(e)
}

/// Seals `plaintext` to the device public key, bound to `slot`. Needs no user.
pub(crate) fn seal_device(
    device_public: &[u8],
    slot: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let device = p256::PublicKey::from_sec1_bytes(device_public)
        .map_err(|_| CoreError::State("the device public key is not a P-256 point".into()))?;
    let ephemeral = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CoreError::State("no entropy".into()))?;
        if let Ok(key) = p256::SecretKey::from_slice(bytes.as_ref()) {
            break key;
        }
    };
    let ephemeral_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), device.as_affine());
    let key = device_kdf(shared.raw_secret_bytes(), &ephemeral_public, device_public);
    let sealed =
        aead::seal_payload(plaintext, &key, slot.as_bytes(), &mut OsEntropy).map_err(protocol)?;
    let mut out = Vec::with_capacity((1 + P256_POINT).saturating_add(sealed.len()));
    out.push(SEAL_VERSION);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// `state`'s key: the ECDH secret and the vault's state secret together, so
/// breaking P-256 alone opens nothing (SP 800-56C: one KDF over both).
fn state_kdf(
    shared: &[u8],
    state_secret: &[u8],
    ephemeral: &[u8],
    device: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if state_secret.len() != 32 {
        return Err(CoreError::State(
            "the vault's state secret is not 32 bytes".into(),
        ));
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(state_secret);
    let mut info = b"hqchat/at-rest/v2/state".to_vec();
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(device);
    Ok(hkdf_sha256::<32>(b"hqchat/at-rest/v2", &ikm, &info))
}

/// Seals `state` to the device key and the vault's state secret: needs the
/// unlock, which every write of `state` has.
pub(crate) fn seal_state(vault: &dyn KeyVault, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let device_public = vault.device_public_key()?;
    let device = p256::PublicKey::from_sec1_bytes(&device_public)
        .map_err(|_| CoreError::State("the device public key is not a P-256 point".into()))?;
    let state_secret = Zeroizing::new(vault.state_secret()?);
    let ephemeral = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CoreError::State("no entropy".into()))?;
        if let Ok(key) = p256::SecretKey::from_slice(bytes.as_ref()) {
            break key;
        }
    };
    let ephemeral_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), device.as_affine());
    let key = state_kdf(
        shared.raw_secret_bytes(),
        &state_secret,
        &ephemeral_public,
        &device_public,
    )?;
    let sealed =
        aead::seal_payload(plaintext, &key, STATE.as_bytes(), &mut OsEntropy).map_err(protocol)?;
    let mut out = Vec::with_capacity((1 + P256_POINT).saturating_add(sealed.len()));
    out.push(STATE_SEAL_VERSION);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a [`seal_state`] blob: one ECDH and the state secret, both under
/// the unlock. A blob sealed to the device key alone is refused: `state` is
/// never read from a weaker seal.
pub(crate) fn open_state(
    vault: &dyn KeyVault,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let not_sealed = || CoreError::State("state: not a sealed blob of this version".into());
    let mut r = Reader::new(blob, "sealed blob too short");
    if r.u8().map_err(|_| not_sealed())? != STATE_SEAL_VERSION {
        return Err(not_sealed());
    }
    let ephemeral = r.take(P256_POINT).map_err(|_| not_sealed())?;
    let device = vault.device_public_key()?;
    let shared = Zeroizing::new(vault.agree(ephemeral.to_vec())?);
    let state_secret = Zeroizing::new(vault.state_secret()?);
    let key = state_kdf(&shared, &state_secret, ephemeral, &device)?;
    aead::open_payload(r.rest(), &key, STATE.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::State("state: does not open".into()))
}

/// Opens a [`seal_device`] blob: one hardware ECDH through the vault.
pub(crate) fn open_device(
    vault: &dyn KeyVault,
    slot: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let not_sealed = || CoreError::State(format!("{slot}: not a sealed blob of this version"));
    let mut r = Reader::new(blob, "sealed blob too short");
    if r.u8().map_err(|_| not_sealed())? != SEAL_VERSION {
        return Err(not_sealed());
    }
    let ephemeral = r.take(P256_POINT).map_err(|_| not_sealed())?;
    let device = vault.device_public_key()?;
    let shared = Zeroizing::new(vault.agree(ephemeral.to_vec())?);
    let key = device_kdf(&shared, ephemeral, &device);
    aead::open_payload(r.rest(), &key, slot.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::State(format!("{slot}: does not open")))
}

/// Seals under the symmetric `data_key`, bound to `slot`.
pub(crate) fn seal_data(
    data_key: &[u8; 32],
    slot: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    aead::seal_payload(plaintext, data_key, slot.as_bytes(), &mut OsEntropy).map_err(protocol)
}

/// Opens a [`seal_data`] blob.
pub(crate) fn open_data(
    data_key: &[u8; 32],
    slot: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    aead::open_payload(blob, data_key, slot.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::State(format!("{slot}: does not open")))
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    postcard::to_allocvec(value)
        .map(Zeroizing::new)
        .map_err(|e| CoreError::State(e.to_string()))
}

pub(crate) fn decode<'a, T: Deserialize<'a>>(slot: &str, bytes: &'a [u8]) -> Result<T, CoreError> {
    postcard::from_bytes(bytes).map_err(|e| CoreError::State(format!("{slot}: {e}")))
}

/// Writes `value` to `slot` under the data key.
pub(crate) fn put_data<T: Serialize>(
    store: &dyn Store,
    data_key: &[u8; 32],
    slot: &str,
    value: &T,
) -> Result<(), CoreError> {
    let plain = encode(value)?;
    store.put(slot.to_owned(), seal_data(data_key, slot, &plain)?)?;
    Ok(())
}

/// Reads `slot` under the data key; `None` when absent.
pub(crate) fn get_data<T: for<'a> Deserialize<'a>>(
    store: &dyn Store,
    data_key: &[u8; 32],
    slot: &str,
) -> Result<Option<T>, CoreError> {
    let Some(blob) = store.get(slot.to_owned()) else {
        return Ok(None);
    };
    let plain = open_data(data_key, slot, &blob)?;
    decode(slot, &plain).map(Some)
}

// ── Records ────────────────────────────────────────────────────────────────

/// The `state` blob.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredState {
    pub format: u16,
    pub identity_pk: Vec<u8>,
    pub identity_sk: Vec<u8>,
    pub data_key: [u8; 32],
    pub prekeys: Option<StoredPrekeys>,
    pub peers: Vec<StoredPeer>,
    /// Outgoing messages not yet acknowledged by the broker: (peer, msg id).
    pub outbox: Vec<(String, String)>,
    /// Friend requests sent and not answered: (to, at).
    pub sent: Vec<(String, i64)>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct StoredPrekeys {
    pub medium_pk: Vec<u8>,
    pub medium_sk: Vec<u8>,
    pub rotated_at: i64,
    pub one_time: Vec<(u32, Vec<u8>)>,
    pub next_id: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct StoredPeer {
    pub id: String,
    pub username: Option<String>,
    pub convo_id: Option<String>,
    pub handshake_id: Option<String>,
    pub pinned_pk: Option<Vec<u8>>,
    pub unread: u32,
    pub read_until: i64,
    pub blocked_at: Option<i64>,
    pub vanished_at: Option<i64>,
    pub verified: bool,
}

/// A message, as the UI shows it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredMessage {
    pub format: u16,
    pub msg_id: String,
    pub outgoing: bool,
    pub text: String,
    pub at: i64,
    pub delivery: Option<u8>,
}

pub(crate) fn delivery_byte(d: Delivery) -> u8 {
    match d {
        Delivery::Sending => 0,
        Delivery::Queued => 1,
        Delivery::Sent => 2,
        Delivery::Delivered => 3,
        Delivery::Failed => 4,
    }
}

pub(crate) fn delivery_of(b: u8) -> Delivery {
    match b {
        1 => Delivery::Queued,
        2 => Delivery::Sent,
        3 => Delivery::Delivered,
        4 => Delivery::Failed,
        _ => Delivery::Sending,
    }
}

/// An inbound publish that arrived while locked, kept as it came.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredPending {
    pub format: u16,
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredChain {
    ck: [u8; 32],
    n: u32,
}

#[derive(Serialize, Deserialize)]
struct StoredInit {
    ct_id: Vec<u8>,
    ct_mt: Vec<u8>,
    one_time: Option<(Vec<u8>, u32)>,
    rk: Vec<u8>,
    cid: [u8; 16],
}

/// A ratchet session.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredSession {
    format: u16,
    root: [u8; 32],
    rk_pk: Vec<u8>,
    rk_sk: Vec<u8>,
    peer_rk: Option<Vec<u8>>,
    send: Option<StoredChain>,
    recv: Option<StoredChain>,
    prev_send_n: u32,
    skipped: Vec<([u8; 16], u32, [u8; 32])>,
    pending_init: Option<StoredInit>,
    seen_chains: Vec<[u8; 16]>,
    sent_on_chain: u32,
    chain_started_at: i64,
    peer_key_fresh: bool,
}

fn state_err(e: hqc::Error) -> CoreError {
    CoreError::State(e.to_string())
}

impl StoredSession {
    pub(crate) fn from_session(s: &SessionState) -> Self {
        let chain = |c: &Option<Chain>| c.as_ref().map(|c| StoredChain { ck: c.ck.0, n: c.n });
        Self {
            format: FORMAT,
            root: s.root.0,
            rk_pk: s.rk.public.as_bytes().to_vec(),
            rk_sk: s.rk.secret.as_bytes().to_vec(),
            peer_rk: s.peer_rk.as_ref().map(|k| k.as_bytes().to_vec()),
            send: chain(&s.send),
            recv: chain(&s.recv),
            prev_send_n: s.prev_send_n,
            skipped: s.skipped.iter().map(|k| (k.chain, k.n, k.key.0)).collect(),
            pending_init: s.pending_init.as_ref().map(|i| StoredInit {
                ct_id: i.ct_id.as_bytes().to_vec(),
                ct_mt: i.ct_mt.as_bytes().to_vec(),
                one_time: i
                    .one_time
                    .as_ref()
                    .map(|(ct, id)| (ct.as_bytes().to_vec(), *id)),
                rk: i.rk.as_bytes().to_vec(),
                cid: i.cid,
            }),
            seen_chains: s.seen_chains.clone(),
            sent_on_chain: s.sent_on_chain,
            chain_started_at: s.chain_started_at,
            peer_key_fresh: s.peer_key_fresh,
        }
    }

    pub(crate) fn to_session(&self) -> Result<SessionState, CoreError> {
        if self.format != FORMAT {
            return Err(CoreError::State(format!("session format {}", self.format)));
        }
        let chain = |c: &Option<StoredChain>| {
            c.as_ref().map(|c| Chain {
                ck: SymmetricKey(c.ck),
                n: c.n,
            })
        };
        let pending_init = match &self.pending_init {
            Some(i) => Some(InitHeader {
                ct_id: Ciphertext::from_bytes(&i.ct_id).map_err(state_err)?,
                ct_mt: Ciphertext::from_bytes(&i.ct_mt).map_err(state_err)?,
                one_time: match &i.one_time {
                    Some((ct, id)) => Some((Ciphertext::from_bytes(ct).map_err(state_err)?, *id)),
                    None => None,
                },
                rk: PublicKey::from_bytes(&i.rk).map_err(state_err)?,
                cid: i.cid,
            }),
            None => None,
        };
        Ok(SessionState {
            root: SymmetricKey(self.root),
            rk: KeyPair {
                public: PublicKey::from_bytes(&self.rk_pk).map_err(state_err)?,
                secret: SecretKey::from_bytes(&self.rk_sk).map_err(state_err)?,
            },
            peer_rk: self
                .peer_rk
                .as_deref()
                .map(PublicKey::from_bytes)
                .transpose()
                .map_err(state_err)?,
            send: chain(&self.send),
            recv: chain(&self.recv),
            prev_send_n: self.prev_send_n,
            skipped: self
                .skipped
                .iter()
                .map(|(chain, n, key)| SkippedKey {
                    chain: *chain,
                    n: *n,
                    key: Box::new(SymmetricKey(*key)),
                })
                .collect(),
            pending_init,
            seen_chains: self.seen_chains.clone(),
            sent_on_chain: self.sent_on_chain,
            chain_started_at: self.chain_started_at,
            peer_key_fresh: self.peer_key_fresh,
        })
    }
}

impl Drop for StoredSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.root.zeroize();
        self.rk_sk.zeroize();
        for (_, _, k) in &mut self.skipped {
            k.zeroize();
        }
    }
}

impl Drop for StoredState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.identity_sk.zeroize();
        self.data_key.zeroize();
    }
}

impl Drop for StoredPrekeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.medium_sk.zeroize();
        for (_, sk) in &mut self.one_time {
            sk.zeroize();
        }
    }
}

impl Drop for StoredChain {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.ck.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software::SoftwareVault;

    fn vault() -> SoftwareVault {
        let v = SoftwareVault::default();
        v.create().unwrap();
        v
    }

    #[test]
    fn device_sealing_round_trips_and_is_bound_to_its_slot() {
        let v = vault();
        let blob = seal_device(&v.device_public_key().unwrap(), "state", b"secret").unwrap();
        assert_eq!(
            open_device(&v, "state", &blob).unwrap().as_slice(),
            b"secret"
        );
        assert!(
            open_device(&v, "pending/1", &blob).is_err(),
            "moved to another slot"
        );
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_device(&v, "state", &tampered).is_err());
    }

    #[test]
    fn sealing_needs_no_user_but_opening_does() {
        let v = vault();
        v.lock();
        let blob = seal_device(&v.device_public_key().unwrap(), "pending/1", b"frame").unwrap();
        assert!(matches!(
            open_device(&v, "pending/1", &blob),
            Err(CoreError::Vault(_))
        ));
        v.unlock();
        assert_eq!(
            open_device(&v, "pending/1", &blob).unwrap().as_slice(),
            b"frame"
        );
    }

    /// A vault that answers the ECDH but whose state secret is another's:
    /// what a quantum attacker who broke P-256 would have.
    struct EcdhOnly(SoftwareVault);

    impl KeyVault for EcdhOnly {
        fn create(&self) -> Result<crate::ports::Tier, crate::ports::VaultError> {
            self.0.create()
        }
        fn device_public_key(&self) -> Result<Vec<u8>, crate::ports::VaultError> {
            self.0.device_public_key()
        }
        fn agree(&self, e: Vec<u8>) -> Result<Vec<u8>, crate::ports::VaultError> {
            self.0.agree(e)
        }
        fn state_secret(&self) -> Result<Vec<u8>, crate::ports::VaultError> {
            Ok(vec![0; 32])
        }
        fn tier(&self) -> crate::ports::Tier {
            self.0.tier()
        }
    }

    #[test]
    fn state_needs_the_state_secret_as_well_as_the_device_key() {
        let v = vault();
        let blob = seal_state(&v, b"identity").unwrap();
        assert_eq!(open_state(&v, &blob).unwrap().as_slice(), b"identity");
        let key = v.export_key().unwrap();
        let ecdh_only = EcdhOnly(SoftwareVault::with_key(key));
        assert!(open_state(&ecdh_only, &blob).is_err());
        // Nor is a state sealed to the device key alone accepted.
        let weak = seal_device(&v.device_public_key().unwrap(), STATE, b"identity").unwrap();
        assert!(open_state(&v, &weak).is_err());
    }

    #[test]
    fn another_device_cannot_open_it() {
        let blob = seal_device(&vault().device_public_key().unwrap(), "state", b"secret").unwrap();
        assert!(open_device(&vault(), "state", &blob).is_err());
    }

    #[test]
    fn data_sealing_is_bound_to_its_slot() {
        let key = [9u8; 32];
        let blob = seal_data(&key, "msg/a", b"hello").unwrap();
        assert_eq!(
            open_data(&key, "msg/a", &blob).unwrap().as_slice(),
            b"hello"
        );
        assert!(open_data(&key, "msg/b", &blob).is_err());
        assert!(open_data(&[8u8; 32], "msg/a", &blob).is_err());
    }

    #[test]
    fn a_session_survives_storage() {
        let kem = hqchat_protocol::HqcKem;
        let bob = hqc::generate_keypair().unwrap();
        let medium = hqc::generate_keypair().unwrap();
        let bundle = hqchat_protocol::ratchet::PrekeyBundle {
            identity_pk: bob.public,
            medium_pk: medium.public,
            one_time: None,
        };
        let (mut s, _) = hqchat_protocol::ratchet::start_as_initiator(&kem, &bundle).unwrap();
        hqchat_protocol::ratchet::seal(&kem, &mut s, 2).unwrap();
        let bytes = encode(&StoredSession::from_session(&s)).unwrap();
        let back = decode::<StoredSession>("session/x", &bytes)
            .unwrap()
            .to_session()
            .unwrap();
        assert_eq!(back.root, s.root);
        assert_eq!(back.send.as_ref().unwrap().n, 1);
        assert_eq!(back.pending_init, s.pending_init);
        assert_eq!(back.rk.public, s.rk.public);
    }

    #[test]
    fn message_slots_sort_by_time() {
        let names = SlotNames::of(&[3; 32]);
        let peer = PeerId::parse(&"a".repeat(64)).unwrap();
        let early = names.message(&peer, 5, "z");
        let late = names.message(&peer, 40, "a");
        assert!(early < late);
        assert!(early.starts_with(&names.messages_prefix(&peer)));
    }

    #[test]
    fn slot_names_carry_no_friend_or_message_id() {
        let names = SlotNames::of(&[3; 32]);
        let peer = PeerId::parse(&"ab".repeat(32)).unwrap();
        for slot in [names.session(&peer), names.message(&peer, 7, "msg-1234")] {
            assert!(!slot.contains("abab"), "{slot}");
            assert!(!slot.contains(&hex::encode("msg-1234")), "{slot}");
        }
        let other = SlotNames::of(&[4; 32]);
        assert_ne!(names.session(&peer), other.session(&peer), "keyed");
    }
}
