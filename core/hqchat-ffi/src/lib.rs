//! The HQChat Engine for Swift and Kotlin, through uniffi. The apps
//! implement [`KeyVault`] (Secure Enclave, Android Keystore, TPM) and
//! [`Store`] (their own storage), create one [`Engine`] per profile, send it
//! commands and carry out the [`Effect`]s it returns.
//!
//! The types mirror `hqchat-engine`'s one for one, so this crate is the only
//! one that knows about bindings. No secret key, ratchet state or root key
//! crosses this API.

use std::sync::Arc;

use hqchat_engine as core;

mod import;
mod types;

pub use import::{
    ImportChain, ImportData, ImportInit, ImportMessageData, ImportOneTimeKey, ImportPeerData,
    ImportPendingData, ImportPrekeysData, ImportSentData, ImportSessionData, ImportSkippedKey,
};

pub use types::*;

uniffi::setup_scaffolding!();

/// The version of this API; shells check it against the bindings they ship.
#[uniffi::export]
pub fn core_api_version() -> u32 {
    core::CORE_API_VERSION
}

/// The device key: a P-256 key that never leaves the chip. Sealing needs
/// only the public key; opening needs one `agree`.
#[uniffi::export(with_foreign)]
pub trait KeyVault: Send + Sync {
    /// Creates the device key if there is none; returns the tier it got.
    fn create(&self) -> Result<Tier, VaultError>;
    /// The device public key, 65-byte uncompressed P-256.
    fn device_public_key(&self) -> Result<Vec<u8>, VaultError>;
    /// One ECDH with `ephemeral_public` (65 bytes), under the context the
    /// shell authenticated before `Engine::unlock`. Returns 32 bytes.
    fn agree(&self, ephemeral_public: Vec<u8>) -> Result<Vec<u8>, VaultError>;
    /// The device key's tier.
    fn tier(&self) -> Tier;
}

/// Opaque blobs by key; everything is already sealed.
#[uniffi::export(with_foreign)]
pub trait Store: Send + Sync {
    /// The blob under `key`.
    fn get(&self, key: String) -> Option<Vec<u8>>;
    /// Stores `value` under `key`, durably.
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError>;
    /// Removes the blob under `key`.
    fn delete(&self, key: String);
    /// Every key starting with `prefix`, sorted.
    fn list(&self, prefix: String) -> Vec<String>;
}

struct VaultAdapter(Arc<dyn KeyVault>);

impl core::KeyVault for VaultAdapter {
    fn create(&self) -> Result<core::Tier, core::VaultError> {
        self.0.create().map(Into::into).map_err(Into::into)
    }
    fn device_public_key(&self) -> Result<Vec<u8>, core::VaultError> {
        self.0.device_public_key().map_err(Into::into)
    }
    fn agree(&self, ephemeral_public: Vec<u8>) -> Result<Vec<u8>, core::VaultError> {
        self.0.agree(ephemeral_public).map_err(Into::into)
    }
    fn tier(&self) -> core::Tier {
        self.0.tier().into()
    }
}

struct StoreAdapter(Arc<dyn Store>);

impl core::Store for StoreAdapter {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        self.0.get(key)
    }
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), core::StoreError> {
        self.0
            .put(key, value)
            .map_err(|StoreError::Write { message }| core::StoreError::Write(message))
    }
    fn delete(&self, key: String) {
        self.0.delete(key)
    }
    fn list(&self, prefix: String) -> Vec<String> {
        self.0.list(prefix)
    }
}

/// The client, one per profile. Every call returns without blocking on I/O;
/// `now` is Unix milliseconds on the device clock.
#[derive(uniffi::Object)]
pub struct Engine {
    inner: core::Engine,
}

fn effects(e: Vec<core::Effect>) -> Vec<Effect> {
    e.into_iter().map(Into::into).collect()
}

#[uniffi::export]
impl Engine {
    /// An engine for one profile over the shell's vault and store.
    #[uniffi::constructor]
    pub fn new(
        config: Config,
        vault: Arc<dyn KeyVault>,
        store: Arc<dyn Store>,
    ) -> Result<Arc<Self>, CoreError> {
        let inner = core::Engine::new(
            config.into(),
            Arc::new(VaultAdapter(vault)),
            Arc::new(StoreAdapter(store)),
        )?;
        Ok(Arc::new(Self { inner }))
    }

    /// Creates the device key and a new identity.
    pub fn create_identity(&self) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.create_identity()?))
    }
    /// Brings another implementation's identity, prekeys, friends, sessions,
    /// history and unopened frames into this profile, which must have no
    /// identity yet; then opens those frames. All or nothing.
    pub fn import_state(&self, data: ImportData, now: i64) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.import(data.try_into()?, now)?))
    }
    /// Starts (and resumes): signs in, connects, re-reads what changed.
    pub fn start(&self, now: i64, network: NetworkInfo) -> Vec<Effect> {
        effects(self.inner.start(now, network.into()))
    }
    /// The shell authenticated the user.
    pub fn unlock(&self, now: i64) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.unlock(now)?))
    }
    /// Forget the opened secrets.
    pub fn lock(&self) -> Vec<Effect> {
        effects(self.inner.lock())
    }
    /// A timer fired, or the app resumed.
    pub fn tick(&self, now: i64) -> Vec<Effect> {
        effects(self.inner.tick(now))
    }
    /// Sends `text` to a friend.
    pub fn send_text(
        &self,
        peer: String,
        text: String,
        now: i64,
    ) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.send_text(peer, text, now)?))
    }
    /// Resends a failed message under its id.
    pub fn retry(&self, msg_id: String, now: i64) -> Vec<Effect> {
        effects(self.inner.retry(msg_id, now))
    }
    /// Sends a friend request.
    pub fn invite(&self, username: String) -> Vec<Effect> {
        effects(self.inner.invite(username))
    }
    /// Accepts a friend request.
    pub fn accept(&self, peer: String) -> Vec<Effect> {
        effects(self.inner.accept(peer))
    }
    /// Removes a friend.
    pub fn remove(&self, peer: String) -> Vec<Effect> {
        effects(self.inner.remove(peer))
    }
    /// Blocks a user.
    pub fn block(&self, peer: String) -> Vec<Effect> {
        effects(self.inner.block(peer))
    }
    /// Lifts a block; the friendship is not restored.
    pub fn unblock(&self, peer: String) -> Vec<Effect> {
        effects(self.inner.unblock(peer))
    }
    /// Forgets a vanished identity and its conversation, on this device.
    pub fn forget(&self, peer: String) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.forget(peer)?))
    }
    /// Steps the ratchet with `peer` on the next message sent.
    pub fn rotate_keys(&self, peer: String) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.rotate_keys(peer)?))
    }
    /// Marks the conversation with `peer` read.
    pub fn mark_read(&self, peer: String) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.mark_read(peer)?))
    }
    /// Reports a friend's messages.
    pub fn report(&self, report: ReportInput) -> Vec<Effect> {
        effects(self.inner.report(report.into()))
    }
    /// Claims a username.
    pub fn set_username(&self, username: String) -> Vec<Effect> {
        effects(self.inner.set_username(username))
    }
    /// Deletes the account, then this profile's data.
    pub fn delete_account(&self) -> Vec<Effect> {
        effects(self.inner.delete_account())
    }
    /// Registers for push wake-ups.
    pub fn register_push(&self, token: PushToken) -> Vec<Effect> {
        effects(self.inner.register_push(token.into()))
    }
    /// A page of a conversation, newest last.
    pub fn history(
        &self,
        peer: String,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Message>, CoreError> {
        Ok(self
            .inner
            .history(peer, before, limit)?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// The friends, sorted for display.
    pub fn friends(&self) -> Vec<FriendView> {
        self.inner.friends().into_iter().map(Into::into).collect()
    }
    /// Announces presence: offline on going to the background, online back.
    pub fn set_presence(&self, online: bool, now: i64) -> Vec<Effect> {
        effects(self.inner.set_presence(online, now))
    }
    /// This profile's client id, once unlocked.
    pub fn my_id(&self) -> Option<String> {
        self.inner.my_id()
    }
    /// Friend requests sent and not answered yet.
    pub fn sent_invites(&self) -> Vec<SentInviteView> {
        self.inner
            .sent_invites()
            .into_iter()
            .map(Into::into)
            .collect()
    }
    /// Withdraws a request sent, or declines one received.
    pub fn cancel(&self, peer: String) -> Vec<Effect> {
        effects(self.inner.cancel(peer))
    }
    /// Records whether the safety number was compared with `peer`.
    pub fn set_verified(&self, peer: String, verified: bool) -> Result<Vec<Effect>, CoreError> {
        Ok(effects(self.inner.set_verified(peer, verified)?))
    }
    /// Friend requests waiting for an answer.
    pub fn invites(&self) -> Vec<InviteView> {
        self.inner.invites().into_iter().map(Into::into).collect()
    }
    /// The safety number for a friend.
    pub fn fingerprint(&self, peer: String) -> Option<String> {
        self.inner.fingerprint(peer)
    }
    /// The answer to an `Effect::Http`.
    pub fn on_http(&self, req: u64, status: u16, body: Vec<u8>, now: i64) -> Vec<Effect> {
        effects(self.inner.on_http(req, status, body, now))
    }
    /// A connection from `Effect::Open` is up.
    pub fn on_opened(&self, conn: u64, now: i64) -> Vec<Effect> {
        effects(self.inner.on_opened(conn, now))
    }
    /// Bytes arrived on a connection.
    pub fn on_bytes(&self, conn: u64, bytes: Vec<u8>, now: i64) -> Vec<Effect> {
        effects(self.inner.on_bytes(conn, bytes, now))
    }
    /// A connection closed or failed to open.
    pub fn on_closed(&self, conn: u64, reason: CloseReason, now: i64) -> Vec<Effect> {
        effects(self.inner.on_closed(conn, reason.into(), now))
    }
    /// The device moved to another network.
    pub fn on_network_changed(&self, network: NetworkInfo, now: i64) -> Vec<Effect> {
        effects(self.inner.on_network_changed(network.into(), now))
    }
}
