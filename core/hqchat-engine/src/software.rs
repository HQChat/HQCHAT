//! A vault and a store with no platform behind them: the TS bot on the
//! server (no hardware key) and the tests. The vault is the software tier
//! of docs/architecture/multiplatform.md, minus the passphrase a desktop
//! shell would seal it under.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use hqchat_protocol::kdf::hkdf_sha256;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::Zeroizing;

use crate::ports::{KeyVault, Store, StoreError, Tier, VaultError};

/// A P-256 device key held in memory. `lock` and `unlock` stand in for the
/// platform's user-presence check.
pub struct SoftwareVault {
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    locked: AtomicBool,
}

impl Default for SoftwareVault {
    fn default() -> Self {
        Self {
            key: Mutex::new(None),
            locked: AtomicBool::new(false),
        }
    }
}

impl SoftwareVault {
    /// A vault around an existing key (the bot's, restored from its own storage).
    pub fn with_key(secret: [u8; 32]) -> Self {
        Self {
            key: Mutex::new(Some(Zeroizing::new(secret))),
            locked: AtomicBool::new(false),
        }
    }

    /// The key, for a headless owner (the bot) to keep in its own storage.
    pub fn export_key(&self) -> Option<[u8; 32]> {
        self.key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|k| **k)
    }

    /// The user presence check fails until [`SoftwareVault::unlock`].
    pub fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
    }

    /// The user presence check passes again.
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::SeqCst);
    }

    fn secret(&self) -> Result<SecretKey, VaultError> {
        let guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = guard.as_ref().ok_or(VaultError::Missing)?;
        SecretKey::from_slice(bytes.as_ref()).map_err(|_| VaultError::Unavailable("bad key".into()))
    }
}

impl KeyVault for SoftwareVault {
    fn create(&self) -> Result<Tier, VaultError> {
        let mut guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            loop {
                let mut bytes = Zeroizing::new([0u8; 32]);
                getrandom::fill(bytes.as_mut())
                    .map_err(|_| VaultError::Unavailable("no entropy".into()))?;
                if SecretKey::from_slice(bytes.as_ref()).is_ok() {
                    *guard = Some(bytes);
                    break;
                }
            }
        }
        Ok(Tier::Software)
    }

    fn device_public_key(&self) -> Result<Vec<u8>, VaultError> {
        Ok(self
            .secret()?
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn agree(&self, ephemeral_public: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(VaultError::Locked);
        }
        let public = p256::PublicKey::from_sec1_bytes(&ephemeral_public)
            .map_err(|_| VaultError::Unavailable("not a P-256 point".into()))?;
        let shared =
            p256::ecdh::diffie_hellman(self.secret()?.to_nonzero_scalar(), public.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn state_secret(&self) -> Result<Vec<u8>, VaultError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(VaultError::Locked);
        }
        // The software tier keeps nothing apart from its key: derived from it.
        let guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let key = guard.as_ref().ok_or(VaultError::Missing)?;
        Ok(hkdf_sha256::<32>(
            b"hqchat/v2/software-vault",
            key.as_ref(),
            b"hqchat/v2/state-secret",
        )
        .to_vec())
    }

    fn tier(&self) -> Tier {
        Tier::Software
    }
}

/// Blobs in memory, sorted by key.
#[derive(Default)]
pub struct MemoryStore {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    full: AtomicBool,
}

impl MemoryStore {
    /// Refuses every write while `full`, as a full disk would.
    pub fn set_full(&self, full: bool) {
        self.full.store(full, Ordering::SeqCst);
    }

    /// A copy of every blob, for tests that inspect or tamper with storage.
    pub fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.blobs.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Store for MemoryStore {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        self.blobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
    }

    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError> {
        if self.full.load(Ordering::SeqCst) {
            return Err(StoreError::Write("the disk is full".into()));
        }
        self.blobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, value);
        Ok(())
    }

    fn delete(&self, key: String) {
        self.blobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    fn list(&self, prefix: String) -> Vec<String> {
        let blobs = self.blobs.lock().unwrap_or_else(|e| e.into_inner());
        blobs
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }
}
