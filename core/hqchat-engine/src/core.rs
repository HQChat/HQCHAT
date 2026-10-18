//! The engine's state between calls, and the operations every feature
//! shares: sealing state, sessions and messages.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use hqc::{KeyPair, PublicKey, SecretKey};
use hqchat_protocol::ratchet::{PrekeySecrets, SessionState};
use hqchat_protocol::topics::TopicId;
use hqchat_protocol::{HqcKem, PeerId};
use zeroize::Zeroizing;

use crate::effect::Effect;
use crate::persist::{self, StoredMessage, StoredPeer, StoredPrekeys, StoredSession, StoredState};
use crate::ports::{KeyVault, Store, Tier};
use crate::types::{Config, CoreError, FriendView, Message};

/// A friend, as the directory holds them. Public metadata: kept in memory
/// after the first unlock, through later locks.
#[derive(Debug, Clone)]
pub(crate) struct Peer {
    pub id: PeerId,
    pub username: Option<String>,
    pub convo: Option<TopicId>,
    pub handshake: Option<TopicId>,
    /// Their identity key, once fetched and checked against their id.
    pub pinned: Option<PublicKey>,
    pub online: bool,
    /// Messages that arrived while locked and are not opened yet.
    pub unread: u32,
}

/// My prekeys: the medium-term key and the one-time secrets not yet consumed.
pub(crate) struct Prekeys {
    pub identity_sk: SecretKey,
    pub medium: KeyPair,
    pub rotated_at: i64,
    pub one_time: BTreeMap<u32, SecretKey>,
    pub next_id: u32,
}

impl PrekeySecrets for Prekeys {
    fn identity_sk(&self) -> &SecretKey {
        &self.identity_sk
    }
    fn medium_sk(&self) -> &SecretKey {
        &self.medium.secret
    }
    fn one_time_sk(&self, id: u32) -> Option<&SecretKey> {
        self.one_time.get(&id)
    }
}

/// What only an unlock opens. Dropped, and so wiped, on lock.
pub(crate) struct Unlocked {
    pub identity: KeyPair,
    pub data_key: Zeroizing<[u8; 32]>,
    pub prekeys: Option<Prekeys>,
    /// Sessions read so far; the rest stay sealed in the store.
    pub sessions: HashMap<PeerId, SessionState>,
}

pub(crate) struct Core {
    pub config: Config,
    pub vault: Arc<dyn KeyVault>,
    pub store: Arc<dyn Store>,
    pub kem: HqcKem,
    pub has_identity: bool,
    pub tier: Tier,
    /// This client's id, known from the first unlock on.
    pub me: Option<PeerId>,
    pub unlocked: Option<Unlocked>,
    pub peers: BTreeMap<PeerId, Peer>,
    pub next_pending: u64,
    /// Effects of the call in progress, in order.
    pub out: Vec<Effect>,
}

impl Core {
    pub fn new(config: Config, vault: Arc<dyn KeyVault>, store: Arc<dyn Store>) -> Self {
        let has_identity = store.get(persist::STATE.into()).is_some();
        let tier = vault.tier();
        Self {
            config,
            vault,
            store,
            kem: HqcKem,
            has_identity,
            tier,
            me: None,
            unlocked: None,
            peers: BTreeMap::new(),
            next_pending: 0,
            out: Vec::new(),
        }
    }

    pub fn emit(&mut self, effect: Effect) {
        self.out.push(effect);
    }

    pub fn unlocked(&self) -> Result<&Unlocked, CoreError> {
        self.unlocked
            .as_ref()
            .ok_or(CoreError::Vault(crate::ports::VaultError::Locked))
    }

    pub fn unlocked_mut(&mut self) -> Result<&mut Unlocked, CoreError> {
        self.unlocked
            .as_mut()
            .ok_or(CoreError::Vault(crate::ports::VaultError::Locked))
    }

    // ── Identity and state ─────────────────────────────────────────────────

    pub fn create_identity(&mut self) -> Result<(), CoreError> {
        if self.has_identity {
            return Err(CoreError::State(
                "this profile already has an identity".into(),
            ));
        }
        let tier = self.vault.create()?;
        let identity = hqc::keypair_from_seed(&hqc::Seed::generate()?)?;
        let mut data_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(data_key.as_mut()).map_err(|_| CoreError::State("no entropy".into()))?;
        self.me = Some(PeerId::of(&identity.public));
        self.unlocked = Some(Unlocked {
            identity,
            data_key,
            prekeys: None,
            sessions: HashMap::new(),
        });
        self.has_identity = true;
        self.save_state()?;
        self.tier = tier;
        self.emit(Effect::TierChanged(tier));
        Ok(())
    }

    /// Writes the `state` blob, sealed to the device key.
    pub fn save_state(&self) -> Result<(), CoreError> {
        let u = self.unlocked()?;
        let state = StoredState {
            format: persist::FORMAT,
            identity_pk: u.identity.public.as_bytes().to_vec(),
            identity_sk: u.identity.secret.as_bytes().to_vec(),
            data_key: *u.data_key,
            prekeys: u.prekeys.as_ref().map(|p| StoredPrekeys {
                medium_pk: p.medium.public.as_bytes().to_vec(),
                medium_sk: p.medium.secret.as_bytes().to_vec(),
                rotated_at: p.rotated_at,
                one_time: p
                    .one_time
                    .iter()
                    .map(|(id, sk)| (*id, sk.as_bytes().to_vec()))
                    .collect(),
                next_id: p.next_id,
            }),
            peers: self
                .peers
                .values()
                .map(|p| StoredPeer {
                    id: p.id.to_string(),
                    username: p.username.clone(),
                    convo_id: p.convo.as_ref().map(|t| t.as_str().to_owned()),
                    handshake_id: p.handshake.as_ref().map(|t| t.as_str().to_owned()),
                    pinned_pk: p.pinned.as_ref().map(|k| k.as_bytes().to_vec()),
                })
                .collect(),
            next_pending: self.next_pending,
        };
        let plain = persist::encode(&state)?;
        let blob = persist::seal_device(&self.vault.device_public_key()?, persist::STATE, &plain)?;
        self.store.put(persist::STATE.into(), blob)?;
        Ok(())
    }

    /// Opens `state` (one hardware ECDH) and adopts it.
    pub fn open_state(&mut self) -> Result<(), CoreError> {
        if !self.has_identity {
            return Err(CoreError::NoIdentity);
        }
        let blob = self
            .store
            .get(persist::STATE.into())
            .ok_or(CoreError::NoIdentity)?;
        let plain = persist::open_device(self.vault.as_ref(), persist::STATE, &blob)?;
        let state: StoredState = persist::decode(persist::STATE, &plain)?;
        if state.format != persist::FORMAT {
            return Err(CoreError::State(format!("state format {}", state.format)));
        }
        let bad = |e: hqc::Error| CoreError::State(e.to_string());
        let identity = KeyPair {
            public: PublicKey::from_bytes(&state.identity_pk).map_err(bad)?,
            secret: SecretKey::from_bytes(&state.identity_sk).map_err(bad)?,
        };
        let prekeys = match &state.prekeys {
            Some(p) => Some(Prekeys {
                identity_sk: identity.secret.clone(),
                medium: KeyPair {
                    public: PublicKey::from_bytes(&p.medium_pk).map_err(bad)?,
                    secret: SecretKey::from_bytes(&p.medium_sk).map_err(bad)?,
                },
                rotated_at: p.rotated_at,
                one_time: p
                    .one_time
                    .iter()
                    .map(|(id, sk)| Ok((*id, SecretKey::from_bytes(sk).map_err(bad)?)))
                    .collect::<Result<_, CoreError>>()?,
                next_id: p.next_id,
            }),
            None => None,
        };
        let mut peers = BTreeMap::new();
        for p in &state.peers {
            let id = PeerId::parse(&p.id)?;
            let previous = self.peers.get(&id);
            peers.insert(
                id.clone(),
                Peer {
                    id,
                    username: p.username.clone(),
                    convo: p.convo_id.as_deref().map(TopicId::parse).transpose()?,
                    handshake: p.handshake_id.as_deref().map(TopicId::parse).transpose()?,
                    pinned: p
                        .pinned_pk
                        .as_deref()
                        .map(PublicKey::from_bytes)
                        .transpose()
                        .map_err(bad)?,
                    online: previous.is_some_and(|p| p.online),
                    unread: previous.map_or(0, |p| p.unread),
                },
            );
        }
        self.me = Some(PeerId::of(&identity.public));
        self.peers = peers;
        self.next_pending = state.next_pending;
        self.unlocked = Some(Unlocked {
            identity,
            data_key: Zeroizing::new(state.data_key),
            prekeys,
            sessions: HashMap::new(),
        });
        Ok(())
    }

    // ── Sessions ───────────────────────────────────────────────────────────

    /// The session with `peer`, read from the store on first use.
    pub fn session(&mut self, peer: &PeerId) -> Result<Option<&mut SessionState>, CoreError> {
        let store = self.store.clone();
        let u = self.unlocked_mut()?;
        if !u.sessions.contains_key(peer) {
            let slot = persist::session_slot(peer);
            if let Some(stored) =
                persist::get_data::<StoredSession>(store.as_ref(), &u.data_key, &slot)?
            {
                u.sessions.insert(peer.clone(), stored.to_session()?);
            }
        }
        Ok(u.sessions.get_mut(peer))
    }

    /// Stores and keeps `session` as the session with `peer`.
    pub fn put_session(&mut self, peer: &PeerId, session: SessionState) -> Result<(), CoreError> {
        let store = self.store.clone();
        let u = self.unlocked_mut()?;
        let slot = persist::session_slot(peer);
        persist::put_data(
            store.as_ref(),
            &u.data_key,
            &slot,
            &StoredSession::from_session(&session),
        )?;
        u.sessions.insert(peer.clone(), session);
        Ok(())
    }

    /// Writes the in-memory session with `peer` back after it advanced.
    pub fn save_session(&mut self, peer: &PeerId) -> Result<(), CoreError> {
        let store = self.store.clone();
        let u = self.unlocked_mut()?;
        if let Some(s) = u.sessions.get(peer) {
            let slot = persist::session_slot(peer);
            persist::put_data(
                store.as_ref(),
                &u.data_key,
                &slot,
                &StoredSession::from_session(s),
            )?;
        }
        Ok(())
    }

    pub fn forget_session(&mut self, peer: &PeerId) {
        self.store.delete(persist::session_slot(peer));
        if let Some(u) = self.unlocked.as_mut() {
            u.sessions.remove(peer);
        }
    }

    // ── Messages ───────────────────────────────────────────────────────────

    pub fn put_message(&self, peer: &PeerId, m: &StoredMessage) -> Result<(), CoreError> {
        let u = self.unlocked()?;
        persist::put_data(
            self.store.as_ref(),
            &u.data_key,
            &persist::message_slot(peer, m.at, &m.msg_id),
            m,
        )
    }

    /// The slot of the message `msg_id` with `peer`, found by key alone.
    pub fn message_slot_of(&self, peer: &PeerId, msg_id: &str) -> Option<String> {
        let suffix = format!("/{}", hex::encode(msg_id));
        self.store
            .list(persist::messages_prefix(peer))
            .into_iter()
            .find(|k| k.ends_with(&suffix))
    }

    pub fn get_message(&self, slot: &str) -> Result<Option<StoredMessage>, CoreError> {
        let u = self.unlocked()?;
        persist::get_data(self.store.as_ref(), &u.data_key, slot)
    }

    pub fn history(
        &self,
        peer: &PeerId,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Message>, CoreError> {
        self.unlocked()?;
        let mut slots = self.store.list(persist::messages_prefix(peer));
        if let Some(before) = before {
            let cut = format!("{}{:020}", persist::messages_prefix(peer), before.max(0));
            slots.retain(|s| *s < cut);
        }
        let skip = slots.len().saturating_sub(limit as usize);
        let mut out = Vec::new();
        for slot in &slots[skip..] {
            if let Some(m) = self.get_message(slot)? {
                out.push(Message {
                    msg_id: m.msg_id,
                    peer: peer.to_string(),
                    outgoing: m.outgoing,
                    text: m.text,
                    at: m.at,
                    delivery: m.delivery.map(persist::delivery_of),
                });
            }
        }
        Ok(out)
    }

    // ── Directory ──────────────────────────────────────────────────────────

    pub fn friends(&self) -> Vec<FriendView> {
        let mut out: Vec<FriendView> = self
            .peers
            .values()
            .map(|p| FriendView {
                id: p.id.to_string(),
                username: p.username.clone(),
                online: p.online,
                has_session: self.store.get(persist::session_slot(&p.id)).is_some(),
                unread: p.unread,
            })
            .collect();
        out.sort_by(|a, b| {
            (a.username.as_deref().unwrap_or("~"), &a.id)
                .cmp(&(b.username.as_deref().unwrap_or("~"), &b.id))
        });
        out
    }
}
