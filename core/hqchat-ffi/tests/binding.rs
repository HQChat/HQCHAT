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
