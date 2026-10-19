//! Bringing another implementation's state into a new profile: the TS
//! reference client's file (the bot) now, the Apple app's Keychain and
//! SwiftData (phase 3) later. Everything is checked before anything is
//! written, and sessions go to the store before the state that names them,
//! so an import that stops halfway leaves a profile with no identity, which
//! can be imported again.

use std::collections::{BTreeMap, HashMap};

use hqc::{KeyPair, PublicKey, SecretKey};
use hqchat_protocol::PeerId;
use hqchat_protocol::ratchet::SessionState;
use hqchat_protocol::topics::TopicId;
use zeroize::Zeroizing;

use crate::core::{Core, Peer, Prekeys, Unlocked};
use crate::effect::Effect;
use crate::persist::{self, StoredMessage};
use crate::types::{CoreError, Delivery};

/// The identity being imported.
pub enum ImportIdentity {
    /// A 32-byte seed the HQC key pair derives from (the TS client, the bot).
    Seed([u8; 32]),
    /// The key pair itself.
    KeyPair {
        /// Public key, 7237 bytes.
        public: Vec<u8>,
        /// Secret key, 7333 bytes.
        secret: Zeroizing<Vec<u8>>,
    },
}

/// Prekey secrets that published bundles still point at: without them, an
/// `init` a friend sent before the move cannot be answered.
pub struct ImportPrekeys {
    /// The medium-term public key.
    pub medium_public: Vec<u8>,
    /// The medium-term secret key.
    pub medium_secret: Zeroizing<Vec<u8>>,
    /// When the medium-term key was made, in milliseconds.
    pub rotated_at: i64,
    /// One-time secrets not yet consumed, by id.
    pub one_time: Vec<(u32, Zeroizing<Vec<u8>>)>,
    /// The id the next one-time key gets.
    pub next_id: u32,
}

/// One friend, as the old implementation knew them.
pub struct ImportPeer {
    /// Their id.
    pub id: String,
    /// Their handle, if known.
    pub username: Option<String>,
    /// The conversation topic id.
    pub convo_id: Option<String>,
    /// The handshake topic id.
    pub handshake_id: Option<String>,
    /// Their identity key, if it was pinned; must hash to `id`.
    pub pinned_pk: Option<Vec<u8>>,
    /// The ratchet session with them, if one was open.
    pub session: Option<SessionState>,
    /// When this user blocked them, in milliseconds.
    pub blocked_at: Option<i64>,
    /// When their identity was found replaced, in milliseconds.
    pub vanished_at: Option<i64>,
    /// The user compared the safety number (needs a pinned key).
    pub verified: bool,
}

/// One message of the history, as the UI showed it.
pub struct ImportMessage {
    /// The friend the conversation is with.
    pub peer: String,
    /// Its id.
    pub msg_id: String,
    /// Sent by this profile.
    pub outgoing: bool,
    /// The text.
    pub text: String,
    /// When, in milliseconds.
    pub at: i64,
    /// Where an outgoing message had got to.
    pub delivery: Option<Delivery>,
    /// A received message the user has seen. The conversation is read up to
    /// the newest of these; any unseen one after it counts as unread.
    pub read: bool,
}

/// A frame that arrived while the old implementation was locked and was
/// never opened: still ciphertext, opened by the import's drain.
pub struct ImportPending {
    /// The topic it arrived on.
    pub topic: String,
    /// The frame as it arrived.
    pub payload: Vec<u8>,
    /// When it arrived, in milliseconds; the drain keeps this order.
    pub at: i64,
}

/// Everything an import brings.
pub struct Import {
    /// The identity.
    pub identity: ImportIdentity,
    /// The prekey secrets, if any were published.
    pub prekeys: Option<ImportPrekeys>,
    /// The friends.
    pub peers: Vec<ImportPeer>,
    /// The message history.
    pub messages: Vec<ImportMessage>,
    /// Frames still waiting for an unlock.
    pub pending: Vec<ImportPending>,
    /// Friend requests sent and not answered: (to, at).
    pub sent: Vec<(String, i64)>,
}

fn invalid(what: &str) -> CoreError {
    CoreError::State(format!("import: {what}"))
}

fn identity_of(identity: ImportIdentity) -> Result<KeyPair, CoreError> {
    match identity {
        ImportIdentity::Seed(seed) => Ok(hqc::keypair_from_seed(&hqc::Seed::from_bytes(seed))?),
        ImportIdentity::KeyPair { public, secret } => Ok(KeyPair {
            public: PublicKey::from_bytes(&public).map_err(|_| invalid("identity public key"))?,
            secret: SecretKey::from_bytes(&secret).map_err(|_| invalid("identity secret key"))?,
        }),
    }
}

fn prekeys_of(p: ImportPrekeys, identity_sk: &SecretKey) -> Result<Prekeys, CoreError> {
    let mut one_time = BTreeMap::new();
    for (id, sk) in p.one_time {
        let sk = SecretKey::from_bytes(&sk).map_err(|_| invalid("one-time prekey"))?;
        one_time.insert(id, sk);
    }
    Ok(Prekeys {
        identity_sk: identity_sk.clone(),
        medium: KeyPair {
            public: PublicKey::from_bytes(&p.medium_public)
                .map_err(|_| invalid("medium-term public key"))?,
            secret: SecretKey::from_bytes(&p.medium_secret)
                .map_err(|_| invalid("medium-term secret key"))?,
        },
        rotated_at: p.rotated_at,
        one_time,
        next_id: p.next_id,
    })
}

fn topic(id: Option<String>, what: &str) -> Result<Option<TopicId>, CoreError> {
    id.map(|t| TopicId::parse(&t).map_err(|_| invalid(what)))
        .transpose()
}

fn peer_of(p: ImportPeer) -> Result<(Peer, Option<SessionState>), CoreError> {
    let id = PeerId::parse(&p.id).map_err(|_| invalid("a peer id"))?;
    let pinned = match p.pinned_pk {
        Some(pk) => {
            let key = PublicKey::from_bytes(&pk).map_err(|_| invalid("a pinned key"))?;
            // A key that does not hash to the id it is filed under is refused,
            // never pinned, exactly as when it is fetched.
            if !id.matches(&key) {
                return Err(invalid("a pinned key does not hash to its peer's id"));
            }
            Some(key)
        }
        None => None,
    };
    let verified = p.verified && pinned.is_some();
    let peer = Peer {
        username: p.username,
        convo: topic(p.convo_id, "a conversation topic")?,
        handshake: topic(p.handshake_id, "a handshake topic")?,
        pinned,
        blocked_at: p.blocked_at,
        vanished_at: p.vanished_at,
        verified,
        ..Peer::new(id)
    };
    Ok((peer, p.session))
}

/// Read state from the per-message flags: read up to the newest received
/// message seen, unread for every received one after it.
fn read_state(peers: &mut BTreeMap<PeerId, Peer>, messages: &[(PeerId, StoredMessage, bool)]) {
    for (peer, m, read) in messages {
        if let Some(p) = peers.get_mut(peer)
            && !m.outgoing
            && *read
        {
            p.read_until = p.read_until.max(m.at);
        }
    }
    for (peer, m, _) in messages {
        if let Some(p) = peers.get_mut(peer)
            && !m.outgoing
            && m.at > p.read_until
        {
            p.unread = p.unread.saturating_add(1);
        }
    }
}

fn message_of(m: ImportMessage) -> Result<(PeerId, StoredMessage, bool), CoreError> {
    let peer = PeerId::parse(&m.peer).map_err(|_| invalid("a message's peer id"))?;
    if m.msg_id.is_empty() {
        return Err(invalid("a message without an id"));
    }
    Ok((
        peer,
        StoredMessage {
            format: persist::FORMAT,
            msg_id: m.msg_id,
            outgoing: m.outgoing,
            text: m.text,
            at: m.at,
            delivery: m.delivery.map(persist::delivery_byte),
        },
        m.read,
    ))
}

impl Core {
    /// Imports `import` into this profile, which must have no identity yet,
    /// then opens the frames it brought that were waiting for an unlock.
    pub fn import(&mut self, import: Import, now: i64) -> Result<(), CoreError> {
        if self.has_identity {
            return Err(CoreError::State(
                "this profile already has an identity".into(),
            ));
        }
        let identity = identity_of(import.identity)?;
        let prekeys = import
            .prekeys
            .map(|p| prekeys_of(p, &identity.secret))
            .transpose()?;
        let me = PeerId::of(&identity.public);
        let mut peers = BTreeMap::new();
        let mut sessions = Vec::new();
        for p in import.peers {
            let (peer, session) = peer_of(p)?;
            if let Some(mut session) = session {
                // Older clients kept no record of whose turn it is to step.
                // Both sides of a session break the tie the same way: the
                // lower id may step first, the other once that step arrives.
                session.peer_key_fresh = me < peer.id;
                sessions.push((peer.id.clone(), session));
            }
            peers.insert(peer.id.clone(), peer);
        }
        let messages = import
            .messages
            .into_iter()
            .map(message_of)
            .collect::<Result<Vec<_>, _>>()?;
        read_state(&mut peers, &messages);
        let messages = messages.into_iter().map(|(p, m, _)| (p, m)).collect();
        let pending = import.pending;
        self.sent = import
            .sent
            .into_iter()
            .map(|(to, at)| crate::types::SentInviteView { to, at })
            .collect();

        let result = self.write_import(identity, prekeys, peers, sessions, messages, &pending);
        if result.is_err() {
            // Back to a profile with no identity, which can be imported again.
            self.unlocked = None;
            self.me = None;
            self.peers.clear();
            self.sent.clear();
        }
        result?;
        if !pending.is_empty() {
            self.drain_pending(now);
        }
        Ok(())
    }

    fn write_import(
        &mut self,
        identity: KeyPair,
        prekeys: Option<Prekeys>,
        peers: BTreeMap<PeerId, Peer>,
        sessions: Vec<(PeerId, SessionState)>,
        messages: Vec<(PeerId, StoredMessage)>,
        pending: &[ImportPending],
    ) -> Result<(), CoreError> {
        let tier = self.vault.create()?;
        let mut data_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(data_key.as_mut()).map_err(|_| CoreError::State("no entropy".into()))?;
        self.me = Some(PeerId::of(&identity.public));
        self.unlocked = Some(Unlocked {
            identity,
            data_key,
            prekeys,
            sessions: HashMap::new(),
        });
        self.peers = peers;
        for (peer, session) in sessions {
            self.put_session(&peer, session)?;
        }
        for (peer, message) in &messages {
            self.put_message(peer, message)?;
            // New messages sort after the history.
            self.last_stamp = self.last_stamp.max(message.at);
        }
        for frame in pending {
            self.store_pending(&frame.topic, frame.payload.clone(), frame.at)?;
        }
        // Last: until `state` exists the profile has no identity.
        self.save_state()?;
        self.has_identity = true;
        self.tier = tier;
        self.emit(Effect::TierChanged(tier));
        Ok(())
    }
}
