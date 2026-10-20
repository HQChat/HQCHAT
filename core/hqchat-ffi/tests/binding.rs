//! The binding layer itself: the foreign traits implemented here as the apps
//! will, driven through the FFI Engine.

use std::sync::Arc;

use hqchat_engine::KeyVault as _;
use hqchat_engine::Store as _;
use hqchat_engine::software::{MemoryStore, SoftwareVault};
use hqchat_ffi::*;

struct Vault(SoftwareVault);

impl KeyVault for Vault {
    fn create(&self) -> Result<Tier, VaultError> {
        self.0
            .create()
            .map(Into::into)
            .map_err(|_| VaultError::Missing)
    }
    fn device_public_key(&self) -> Result<Vec<u8>, VaultError> {
        self.0.device_public_key().map_err(|_| VaultError::Missing)
    }
    fn agree(&self, ephemeral_public: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        self.0
            .agree(ephemeral_public)
            .map_err(|_| VaultError::Locked)
    }
    fn state_secret(&self) -> Result<Vec<u8>, VaultError> {
        self.0.state_secret().map_err(|_| VaultError::Locked)
    }
    fn tier(&self) -> Tier {
        Tier::Software
    }
}

struct Blobs(MemoryStore);

impl Store for Blobs {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        self.0.get(key)
    }
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError> {
        self.0.put(key, value).map_err(|_| StoreError::Write {
            message: "full".into(),
        })
    }
    fn delete(&self, key: String) {
        self.0.delete(key)
    }
    fn list(&self, prefix: String) -> Vec<String> {
        self.0.list(prefix)
    }
}

fn config() -> Config {
    Config {
        server_url: "https://hqchat.test".into(),
        profile_id: "p".into(),
        device: Device::Ios,
        hqn_pins: vec![],
    }
}

#[test]
fn an_engine_runs_on_foreign_vault_and_store() {
    let vault: Arc<dyn KeyVault> = Arc::new(Vault(SoftwareVault::default()));
    let store: Arc<dyn Store> = Arc::new(Blobs(MemoryStore::default()));
    let engine = Engine::new(config(), vault.clone(), store.clone()).unwrap();
    assert_eq!(
        engine.create_identity().unwrap(),
        vec![Effect::TierChanged {
            tier: Tier::Software
        }]
    );
    let started = engine.start(
        0,
        NetworkInfo {
            key: "wifi".into(),
            expensive: false,
        },
    );
    assert!(started.iter().any(
        |e| matches!(e, Effect::Http { path, method: Method::Post, .. } if path == "/auth/init")
    ));

    let again = Engine::new(config(), vault, store).unwrap();
    assert_eq!(again.unlock(0).unwrap(), vec![Effect::FriendsChanged]);
    assert_eq!(again.history("a".repeat(64), None, 5).unwrap(), vec![]);
    assert_eq!(
        again.send_text("b".repeat(64), "hi".into(), 0),
        Err(CoreError::NotAFriend)
    );
    again.lock();
    assert_eq!(
        again.history("a".repeat(64), None, 5),
        Err(CoreError::Locked)
    );
    assert_eq!(core_api_version(), hqchat_engine::CORE_API_VERSION);
}

/// What the Apple importer hands over, built here from a real session.
fn import_data() -> (ImportData, String) {
    use hqchat_protocol::HqcKem;
    use hqchat_protocol::ratchet::{self, PrekeyBundle};
    let me = hqc::keypair_from_seed(&hqc::Seed::from_bytes([1; 32])).unwrap();
    let friend = hqc::keypair_from_seed(&hqc::Seed::from_bytes([2; 32])).unwrap();
    let medium = hqc::generate_keypair().unwrap();
    let (s, _) = ratchet::start_as_initiator(
        &HqcKem,
        &PrekeyBundle {
            identity_pk: friend.public.clone(),
            medium_pk: medium.public.clone(),
            one_time: None,
        },
    )
    .unwrap();
    let init = s.pending_init.as_ref().unwrap();
    let friend_id = hqchat_protocol::PeerId::of(&friend.public).to_string();
    let session = ImportSessionData {
        root: s.root.0.to_vec(),
        ratchet_public_key: s.rk.public.as_bytes().to_vec(),
        ratchet_secret_key: s.rk.secret.as_bytes().to_vec(),
        peer_ratchet_public_key: None,
        send: s.send.as_ref().map(|c| ImportChain {
            key: c.ck.0.to_vec(),
            n: c.n,
        }),
        recv: None,
        previous_send_count: s.prev_send_n,
        skipped: vec![],
        pending_init: Some(ImportInit {
            ct_id: init.ct_id.as_bytes().to_vec(),
            ct_mt: init.ct_mt.as_bytes().to_vec(),
            ct_ot: None,
            one_time_id: None,
            ratchet_public_key: init.rk.as_bytes().to_vec(),
            chain: init.cid.to_vec(),
        }),
        seen_chains: s.seen_chains.iter().map(|c| c.to_vec()).collect(),
        sent_on_chain: s.sent_on_chain,
        chain_started_at: s.chain_started_at,
    };
    let data = ImportData {
        identity_public_key: me.public.as_bytes().to_vec(),
        identity_secret_key: me.secret.as_bytes().to_vec(),
        prekeys: None,
        peers: vec![ImportPeerData {
            id: friend_id.clone(),
            username: Some("friend".into()),
            convo_id: Some("c".repeat(64)),
            handshake_id: Some("d".repeat(64)),
            pinned_public_key: Some(friend.public.as_bytes().to_vec()),
            session: Some(session),
            blocked_at: None,
            vanished_at: None,
            verified: true,
        }],
        messages: vec![ImportMessageData {
            peer: friend_id.clone(),
            msg_id: "m1".into(),
            outgoing: true,
            text: "before the move".into(),
            at: 1_000,
            delivery: Some(Delivery::Delivered),
            read: true,
        }],
        pending: vec![],
        sent: vec![ImportSentData {
            to: "carol".into(),
            at: 1_000,
        }],
    };
    (data, friend_id)
}

#[test]
fn an_import_through_the_binding_brings_friends_sessions_and_history() {
    let engine = Engine::new(
        config(),
        Arc::new(Vault(SoftwareVault::default())),
        Arc::new(Blobs(MemoryStore::default())),
    )
    .unwrap();
    let (data, friend) = import_data();
    assert_eq!(
        engine.import_state(data, 0).unwrap(),
        vec![Effect::TierChanged {
            tier: Tier::Software
        }]
    );
    let friends = engine.friends();
    assert_eq!(friends.len(), 1);
    assert!(friends[0].has_session, "the session came across");
    assert!(
        friends[0].has_key && friends[0].verified,
        "the verification came across"
    );
    assert_eq!(engine.sent_invites()[0].to, "carol");
    let history = engine.history(friend, None, 10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text, "before the move");
    assert_eq!(history[0].delivery, Some(Delivery::Delivered));
}

#[test]
fn a_wrong_size_refuses_the_import_and_leaves_the_profile_empty() {
    let engine = Engine::new(
        config(),
        Arc::new(Vault(SoftwareVault::default())),
        Arc::new(Blobs(MemoryStore::default())),
    )
    .unwrap();
    let (mut data, _) = import_data();
    if let Some(s) = data.peers[0].session.as_mut() {
        s.root.truncate(31);
    }
    assert!(matches!(
        engine.import_state(data, 0),
        Err(CoreError::State { .. })
    ));
    let (good, _) = import_data();
    assert!(
        engine.import_state(good, 0).is_ok(),
        "nothing was kept; the import can be redone"
    );
}
