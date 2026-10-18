//! An identity at rest, through the public API.

use std::sync::Arc;

use hqchat_engine::software::{MemoryStore, SoftwareVault};
use hqchat_engine::{CoreError, Effect, Engine, Tier, VaultError};

mod support;

fn config() -> hqchat_engine::Config {
    support::config("p1")
}

#[test]
fn an_identity_survives_a_restart_and_unlocking_needs_the_vault() {
    let vault = Arc::new(SoftwareVault::default());
    let store = Arc::new(MemoryStore::default());
    let engine = Engine::new(config(), vault.clone(), store.clone()).unwrap();
    let effects = engine.create_identity(0).unwrap();
    assert_eq!(effects, vec![Effect::TierChanged(Tier::Software)]);
    assert!(
        engine.create_identity(0).is_err(),
        "one identity per profile"
    );
    assert!(store.snapshot().contains_key("state"));

    let restarted = Engine::new(config(), vault.clone(), store.clone()).unwrap();
    let peer = "a".repeat(64);
    assert_eq!(
        restarted.history(peer.clone(), None, 10),
        Err(CoreError::Vault(VaultError::Locked))
    );
    vault.lock();
    assert_eq!(
        restarted.unlock(0),
        Err(CoreError::Vault(VaultError::Locked))
    );
    vault.unlock();
    assert_eq!(restarted.unlock(0).unwrap(), vec![Effect::FriendsChanged]);
    assert_eq!(restarted.history(peer.clone(), None, 10), Ok(vec![]));
    restarted.lock();
    assert!(restarted.history(peer, None, 10).is_err(), "locked again");
}

#[test]
fn a_profile_without_an_identity_cannot_unlock() {
    let engine = Engine::new(
        config(),
        Arc::new(SoftwareVault::default()),
        Arc::new(MemoryStore::default()),
    )
    .unwrap();
    assert_eq!(engine.unlock(0), Err(CoreError::NoIdentity));
}
