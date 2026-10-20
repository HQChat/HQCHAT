//! An import that fails after its first writes (a full disk, the app killed)
//! leaves nothing behind that a retry cannot read.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hqchat_engine::software::{MemoryStore, SoftwareVault};
use hqchat_engine::{Engine, Import, ImportIdentity, ImportMessage, ImportPeer, Store, StoreError};
use hqchat_protocol::PeerId;

mod support;

/// A store whose write of `state` fails while `fail_state` is set (a full
/// disk, or the app killed at that point).
#[derive(Default)]
struct FailingStore {
    inner: MemoryStore,
    fail_state: AtomicBool,
}

impl Store for FailingStore {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError> {
        if key == "state" && self.fail_state.load(Ordering::SeqCst) {
            return Err(StoreError::Write("the disk is full".into()));
        }
        self.inner.put(key, value)
    }
    fn delete(&self, key: String) {
        self.inner.delete(key)
    }
    fn list(&self, prefix: String) -> Vec<String> {
        self.inner.list(prefix)
    }
}

fn import(peer: &str, legacy_id: &str) -> Import {
    let msg = |id: &str, at: i64| ImportMessage {
        peer: peer.into(),
        msg_id: id.into(),
        outgoing: false,
        text: format!("text of {id}"),
        at,
        delivery: None,
        read: true,
    };
    Import {
        identity: ImportIdentity::Seed([9; 32]),
        prekeys: None,
        peers: vec![ImportPeer {
            id: peer.into(),
            username: Some("alice".into()),
            convo_id: None,
            handshake_id: None,
            pinned_pk: None,
            session: None,
            blocked_at: None,
            vanished_at: None,
            verified: false,
        }],
        messages: vec![msg("m1", 1_000), msg(legacy_id, 2_000)],
        pending: vec![],
        sent: vec![],
    }
}

#[test]
fn a_retried_import_leaves_nothing_unreadable_behind() {
    let peer = PeerId::of(
        &hqc::keypair_from_seed(&hqc::Seed::from_bytes([1; 32]))
            .unwrap()
            .public,
    )
    .to_string();
    let store = Arc::new(FailingStore::default());
    let engine = Engine::new(
        support::config("p"),
        Arc::new(SoftwareVault::default()),
        store.clone(),
    )
    .unwrap();

    store.fail_state.store(true, Ordering::SeqCst);
    assert!(engine.import(import(&peer, "legacy-aaaa"), 0).is_err());
    assert!(
        store.inner.snapshot().is_empty(),
        "a failed import writes nothing"
    );

    store.fail_state.store(false, Ordering::SeqCst);
    engine
        .import(import(&peer, "legacy-bbbb"), 0)
        .expect("the retry succeeds");
    let texts: Vec<String> = engine
        .history(peer, None, 50)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(texts, ["text of m1", "text of legacy-bbbb"]);
}
