//! The engine: one per profile.

use std::sync::{Arc, Mutex};

use crate::effect::{CloseReason, Effect};
use crate::ports::{KeyVault, Store};
use crate::types::{Config, CoreError, FriendView, Message, NetworkInfo, PushToken, ReportInput};

/// The client. `Send + Sync`: every call takes an internal lock and returns
/// without blocking on I/O, so a shell may call from any thread (Swift wraps
/// it in an actor, Kotlin in a single-thread dispatcher). `now` is Unix
/// milliseconds on the device clock; the engine applies the server offset.
pub struct Engine {
    config: Config,
    vault: Arc<dyn KeyVault>,
    store: Arc<dyn Store>,
    state: Mutex<State>,
}

/// Everything the engine holds between calls; loaded from the store.
struct State {}

impl Engine {
    /// An engine for one profile, loading what the store holds for it.
    pub fn new(
        config: Config,
        vault: Arc<dyn KeyVault>,
        store: Arc<dyn Store>,
    ) -> Result<Engine, CoreError> {
        todo!("lib/engine-at-rest")
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Creates the device key and a new HQC identity, sealed at rest.
    pub fn create_identity(&self, now: i64) -> Result<Vec<Effect>, CoreError> {
        todo!("lib/engine-auth")
    }

    /// Starts working: signs in when unlocked, otherwise asks for an unlock.
    pub fn start(&self, now: i64, network: NetworkInfo) -> Vec<Effect> {
        todo!("lib/engine-auth")
    }

    /// The shell authenticated the user: open the secrets, drain what
    /// arrived while locked, finish any send that waited.
    pub fn unlock(&self, now: i64) -> Result<Vec<Effect>, CoreError> {
        todo!("lib/engine-at-rest")
    }

    /// Forget the opened secrets; inbound frames queue as ciphertext.
    pub fn lock(&self) -> Vec<Effect> {
        todo!("lib/engine-at-rest")
    }

    /// A timer fired, or the shell resumed: keep-alive, refresh, retries.
    pub fn tick(&self, now: i64) -> Vec<Effect> {
        todo!("lib/engine-mqtt-session")
    }

    // ── User actions ─────────────────────────────────────────────────────

    /// Sends `text` to a friend, opening a session first if needed. The
    /// message is stored before anything leaves, so a failure stays visible.
    pub fn send_text(
        &self,
        peer: String,
        text: String,
        now: i64,
    ) -> Result<Vec<Effect>, CoreError> {
        todo!("lib/engine-conversations")
    }

    /// Resends a failed message under its id.
    pub fn retry(&self, msg_id: String, now: i64) -> Vec<Effect> {
        todo!("lib/engine-conversations")
    }

    /// Sends a friend request to a username.
    pub fn invite(&self, username: String) -> Vec<Effect> {
        todo!("lib/engine-prekeys-friends")
    }

    /// Accepts a friend request.
    pub fn accept(&self, peer: String) -> Vec<Effect> {
        todo!("lib/engine-prekeys-friends")
    }

    /// Removes a friend and forgets the session.
    pub fn remove(&self, peer: String) -> Vec<Effect> {
        todo!("lib/engine-prekeys-friends")
    }

    /// Blocks a user.
    pub fn block(&self, peer: String) -> Vec<Effect> {
        todo!("lib/engine-prekeys-friends")
    }

    /// Reports a friend's messages.
    pub fn report(&self, report: ReportInput) -> Vec<Effect> {
        todo!("lib/engine-prekeys-friends")
    }

    /// Claims a username.
    pub fn set_username(&self, username: String) -> Vec<Effect> {
        todo!("lib/engine-auth")
    }

    /// Deletes the account on the server, then this profile's data.
    pub fn delete_account(&self) -> Vec<Effect> {
        todo!("lib/engine-auth")
    }

    /// Registers this device for push wake-ups.
    pub fn register_push(&self, token: PushToken) -> Vec<Effect> {
        todo!("lib/engine-auth")
    }

    // ── Reads for the UI ─────────────────────────────────────────────────

    /// A page of a conversation, newest last, opened under the unlock.
    pub fn history(
        &self,
        peer: String,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Message>, CoreError> {
        todo!("lib/engine-at-rest")
    }

    /// The friends, sorted for display.
    pub fn friends(&self) -> Vec<FriendView> {
        todo!("lib/engine-prekeys-friends")
    }

    /// The safety number for a friend's pinned key, to compare in person.
    pub fn fingerprint(&self, peer: String) -> Option<String> {
        todo!("lib/engine-prekeys-friends")
    }

    // ── I/O results ──────────────────────────────────────────────────────

    /// The answer to an [`Effect::Http`].
    pub fn on_http(&self, req: u64, status: u16, body: Vec<u8>, now: i64) -> Vec<Effect> {
        todo!("lib/engine-auth")
    }

    /// A connection from [`Effect::Open`] is up.
    pub fn on_opened(&self, conn: u64, now: i64) -> Vec<Effect> {
        todo!("lib/engine-mqtt-session")
    }

    /// Bytes arrived on a connection.
    pub fn on_bytes(&self, conn: u64, bytes: Vec<u8>, now: i64) -> Vec<Effect> {
        todo!("lib/engine-mqtt-session")
    }

    /// A connection closed or failed to open.
    pub fn on_closed(&self, conn: u64, reason: CloseReason, now: i64) -> Vec<Effect> {
        todo!("lib/engine-mqtt-session")
    }

    /// The device moved to another network.
    pub fn on_network_changed(&self, network: NetworkInfo, now: i64) -> Vec<Effect> {
        todo!("lib/engine-mqtt-session")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn the_engine_can_be_shared_across_threads() {
        assert_send_sync::<Engine>();
    }
}
