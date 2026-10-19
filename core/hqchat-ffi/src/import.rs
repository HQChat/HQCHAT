//! What the Apple app (or any other implementation) brings into the core on
//! its first launch on it: plain bytes and numbers, which the importer fills
//! from its own formats, converted here into the engine's types with every
//! size checked. A malformed field fails the whole import, before anything
//! is written (see `Engine::import`).

use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey};
use hqchat_engine as core;
use hqchat_protocol::ratchet::{Chain, InitHeader, SessionState, SkippedKey, SymmetricKey};
use zeroize::Zeroizing;

use crate::types::{CoreError, Delivery};

/// Everything an import brings.
#[derive(uniffi::Record)]
pub struct ImportData {
    /// The identity's HQC public key (7237 bytes).
    pub identity_public_key: Vec<u8>,
    /// The identity's HQC secret key (7333 bytes).
    pub identity_secret_key: Vec<u8>,
    /// The prekey secrets the published bundle points at, if any.
    pub prekeys: Option<ImportPrekeysData>,
    /// The friends.
    pub peers: Vec<ImportPeerData>,
    /// The message history.
    pub messages: Vec<ImportMessageData>,
    /// Frames that arrived while locked and were never opened.
    pub pending: Vec<ImportPendingData>,
}

/// The prekey secrets.
#[derive(uniffi::Record)]
pub struct ImportPrekeysData {
    /// The medium-term HQC public key.
    pub medium_public_key: Vec<u8>,
    /// The medium-term HQC secret key.
    pub medium_secret_key: Vec<u8>,
    /// When the medium-term key was made, in milliseconds.
    pub rotated_at: i64,
    /// One-time secrets not yet consumed.
    pub one_time: Vec<ImportOneTimeKey>,
    /// The id the next one-time key gets.
    pub next_id: u32,
}

/// One one-time prekey secret.
#[derive(uniffi::Record)]
pub struct ImportOneTimeKey {
    /// Its id.
    pub id: u32,
    /// The HQC secret key.
    pub secret_key: Vec<u8>,
}

/// One friend.
#[derive(uniffi::Record)]
pub struct ImportPeerData {
    /// Their id (64 lowercase hex).
    pub id: String,
    /// Their handle.
    pub username: Option<String>,
    /// The conversation topic id.
    pub convo_id: Option<String>,
    /// The handshake topic id.
    pub handshake_id: Option<String>,
    /// Their identity key, when pinned; must hash to `id`.
    pub pinned_public_key: Option<Vec<u8>>,
    /// The ratchet session with them.
    pub session: Option<ImportSessionData>,
    /// When this user blocked them, in milliseconds.
    pub blocked_at: Option<i64>,
    /// When their identity was found replaced, in milliseconds.
    pub vanished_at: Option<i64>,
}

/// A ratchet session, field for field (`RatchetSessionState` in Swift).
#[derive(uniffi::Record)]
pub struct ImportSessionData {
    /// The root key (32 bytes).
    pub root: Vec<u8>,
    /// My ratchet HQC public key.
    pub ratchet_public_key: Vec<u8>,
    /// My ratchet HQC secret key.
    pub ratchet_secret_key: Vec<u8>,
    /// The peer's advertised ratchet key, once heard.
    pub peer_ratchet_public_key: Option<Vec<u8>>,
    /// The sending chain.
    pub send: Option<ImportChain>,
    /// The receiving chain.
    pub recv: Option<ImportChain>,
    /// Length of the previous sending chain.
    pub previous_send_count: u32,
    /// Keys for messages that have not arrived yet, oldest first.
    pub skipped: Vec<ImportSkippedKey>,
    /// The init header, repeated until the peer answers.
    pub pending_init: Option<ImportInit>,
    /// Chains already stepped into (16 bytes each), newest last.
    pub seen_chains: Vec<Vec<u8>>,
    /// Messages sent on the current sending chain.
    pub sent_on_chain: u32,
    /// When the current sending chain started, in milliseconds.
    pub chain_started_at: i64,
}

/// A chain key and the index it is at.
#[derive(uniffi::Record)]
pub struct ImportChain {
    /// The chain key (32 bytes).
    pub key: Vec<u8>,
    /// The next index.
    pub n: u32,
}

/// A skipped message key.
#[derive(uniffi::Record)]
pub struct ImportSkippedKey {
    /// The chain id (16 bytes).
    pub chain: Vec<u8>,
    /// The index.
    pub n: u32,
    /// The message key (32 bytes).
    pub key: Vec<u8>,
}

/// An init header.
#[derive(uniffi::Record)]
pub struct ImportInit {
    /// Encapsulated to the responder's identity key.
    pub ct_id: Vec<u8>,
    /// Encapsulated to the responder's medium-term prekey.
    pub ct_mt: Vec<u8>,
    /// Encapsulated to a one-time prekey, with `one_time_id`.
    pub ct_ot: Option<Vec<u8>>,
    /// Which one-time prekey.
    pub one_time_id: Option<u32>,
    /// The initiator's first ratchet public key.
    pub ratchet_public_key: Vec<u8>,
    /// Its chain id (16 bytes).
    pub chain: Vec<u8>,
}

/// One message of the history.
#[derive(uniffi::Record)]
pub struct ImportMessageData {
    /// The friend.
    pub peer: String,
    /// The message id.
    pub msg_id: String,
    /// Sent by this profile.
    pub outgoing: bool,
    /// The text.
    pub text: String,
    /// When, in milliseconds.
    pub at: i64,
    /// Where an outgoing message had got to.
    pub delivery: Option<Delivery>,
    /// A received message the user has seen.
    pub read: bool,
}

/// A frame still waiting for an unlock.
#[derive(uniffi::Record)]
pub struct ImportPendingData {
    /// The topic it arrived on.
    pub topic: String,
    /// The frame as it arrived.
    pub payload: Vec<u8>,
    /// When it arrived, in milliseconds.
    pub at: i64,
}

fn invalid(what: &str) -> CoreError {
    core::CoreError::State(format!("import: {what}")).into()
}

fn array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], CoreError> {
    bytes
        .try_into()
        .map_err(|_| invalid(&format!("{what} is not {N} bytes")))
}

fn public_key(bytes: &[u8], what: &str) -> Result<PublicKey, CoreError> {
    PublicKey::from_bytes(bytes).map_err(|_| invalid(what))
}

fn secret_key(bytes: &[u8], what: &str) -> Result<SecretKey, CoreError> {
    SecretKey::from_bytes(bytes).map_err(|_| invalid(what))
}

fn ciphertext(bytes: &[u8], what: &str) -> Result<Ciphertext, CoreError> {
    Ciphertext::from_bytes(bytes).map_err(|_| invalid(what))
}

fn chain(c: Option<ImportChain>) -> Result<Option<Chain>, CoreError> {
    c.map(|c| {
        Ok(Chain {
            ck: SymmetricKey(array(&c.key, "a chain key")?),
            n: c.n,
        })
    })
    .transpose()
}

fn session(s: ImportSessionData) -> Result<SessionState, CoreError> {
    let skipped = s
        .skipped
        .iter()
        .map(|k| {
            Ok(SkippedKey {
                chain: array(&k.chain, "a skipped key's chain id")?,
                n: k.n,
                key: SymmetricKey(array(&k.key, "a skipped message key")?),
            })
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    let seen_chains = s
        .seen_chains
        .iter()
        .map(|c| array(c, "a seen chain id"))
        .collect::<Result<Vec<_>, _>>()?;
    let pending_init = s
        .pending_init
        .map(|i| {
            let one_time = match (i.ct_ot, i.one_time_id) {
                (Some(ct), Some(id)) => {
                    Some((ciphertext(&ct, "an init's one-time ciphertext")?, id))
                }
                (None, None) => None,
                _ => {
                    return Err(invalid(
                        "an init's one-time ciphertext and id come together",
                    ));
                }
            };
            Ok(InitHeader {
                ct_id: ciphertext(&i.ct_id, "an init's identity ciphertext")?,
                ct_mt: ciphertext(&i.ct_mt, "an init's medium-term ciphertext")?,
                one_time,
                rk: public_key(&i.ratchet_public_key, "an init's ratchet key")?,
                cid: array(&i.chain, "an init's chain id")?,
            })
        })
        .transpose()?;
    Ok(SessionState {
        root: SymmetricKey(array(&s.root, "a root key")?),
        rk: KeyPair {
            public: public_key(&s.ratchet_public_key, "a ratchet public key")?,
            secret: secret_key(&s.ratchet_secret_key, "a ratchet secret key")?,
        },
        peer_rk: s
            .peer_ratchet_public_key
            .map(|k| public_key(&k, "a peer ratchet key"))
            .transpose()?,
        send: chain(s.send)?,
        recv: chain(s.recv)?,
        prev_send_n: s.previous_send_count,
        skipped,
        pending_init,
        seen_chains,
        sent_on_chain: s.sent_on_chain,
        chain_started_at: s.chain_started_at,
    })
}

impl TryFrom<ImportData> for core::Import {
    type Error = CoreError;

    fn try_from(d: ImportData) -> Result<Self, CoreError> {
        let prekeys = d.prekeys.map(|p| core::ImportPrekeys {
            medium_public: p.medium_public_key,
            medium_secret: Zeroizing::new(p.medium_secret_key),
            rotated_at: p.rotated_at,
            one_time: p
                .one_time
                .into_iter()
                .map(|k| (k.id, Zeroizing::new(k.secret_key)))
                .collect(),
            next_id: p.next_id,
        });
        let peers = d
            .peers
            .into_iter()
            .map(|p| {
                Ok(core::ImportPeer {
                    id: p.id,
                    username: p.username,
                    convo_id: p.convo_id,
                    handshake_id: p.handshake_id,
                    pinned_pk: p.pinned_public_key,
                    session: p.session.map(session).transpose()?,
                    blocked_at: p.blocked_at,
                    vanished_at: p.vanished_at,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        Ok(core::Import {
            identity: core::ImportIdentity::KeyPair {
                public: d.identity_public_key,
                secret: Zeroizing::new(d.identity_secret_key),
            },
            prekeys,
            peers,
            messages: d
                .messages
                .into_iter()
                .map(|m| core::ImportMessage {
                    peer: m.peer,
                    msg_id: m.msg_id,
                    outgoing: m.outgoing,
                    text: m.text,
                    at: m.at,
                    delivery: m.delivery.map(Into::into),
                    read: m.read,
                })
                .collect(),
            pending: d
                .pending
                .into_iter()
                .map(|f| core::ImportPending {
                    topic: f.topic,
                    payload: f.payload,
                    at: f.at,
                })
                .collect(),
        })
    }
}
