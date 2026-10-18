//! The engine: one per profile.

use std::sync::{Arc, Mutex, MutexGuard};

use crate::core::Core;
use crate::effect::{CloseReason, Effect};
use crate::ports::{KeyVault, Store};
use crate::types::{Config, CoreError, FriendView, Message, NetworkInfo, PushToken, ReportInput};

/// The client. `Send + Sync`: every call takes an internal lock and returns
/// without blocking on I/O, so a shell may call from any thread (Swift wraps
/// it in an actor, Kotlin in a single-thread dispatcher). `now` is Unix
/// milliseconds on the device clock; the engine applies the server offset.
pub struct Engine {
    core: Mutex<Core>,
}

impl Engine {
    /// An engine for one profile, loading what the store holds for it.
    pub fn new(
        config: Config,
        vault: Arc<dyn KeyVault>,
        store: Arc<dyn Store>,
    ) -> Result<Engine, CoreError> {
        Ok(Engine {
            core: Mutex::new(Core::new(config, vault, store)),
        })
    }

    /// The core, even after a panic in another call: every call leaves it
    /// consistent before it can fail.
    fn core(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` and returns the effects it emitted, or its error.
    fn run(
        &self,
        f: impl FnOnce(&mut Core) -> Result<(), CoreError>,
    ) -> Result<Vec<Effect>, CoreError> {
        let mut core = self.core();
        let result = f(&mut core);
        let effects = std::mem::take(&mut core.out);
        result.map(|()| effects)
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Creates the device key and a new HQC identity, sealed at rest.
    pub fn create_identity(&self, now: i64) -> Result<Vec<Effect>, CoreError> {
        self.run(|c| c.create_identity())
    }

    /// Starts working: signs in when unlocked, otherwise asks for an unlock.
    pub fn start(&self, now: i64, network: NetworkInfo) -> Vec<Effect> {
        self.run(|c| {
            c.started = true;
            c.network = Some(network);
            if c.has_identity {
                if c.auth.fresh(now) {
                    // A resume: re-read what may have changed meanwhile.
                    c.sync_directory();
                } else {
                    c.ensure_signed_in(now);
                }
            }
            Ok(())
        })
        .unwrap_or_default()
    }

    /// The shell authenticated the user: open the secrets, drain what
    /// arrived while locked, finish any send that waited.
    pub fn unlock(&self, now: i64) -> Result<Vec<Effect>, CoreError> {
        self.run(|c| {
            c.open_state()?;
            c.emit(Effect::FriendsChanged);
            if c.started {
                c.ensure_signed_in(now);
            }
            Ok(())
        })
    }

    /// Forget the opened secrets; inbound frames queue as ciphertext.
    pub fn lock(&self) -> Vec<Effect> {
        self.core().unlocked = None;
        Vec::new()
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
        self.run(|c| {
            c.friendship(
                crate::Action::Invite,
                "/friends/invite",
                serde_json::json!({ "to": username }),
            );
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Accepts a friend request.
    pub fn accept(&self, peer: String) -> Vec<Effect> {
        self.run(|c| {
            c.friendship(
                crate::Action::Accept,
                "/friends/accept",
                serde_json::json!({ "from": peer }),
            );
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Removes a friend and forgets the session.
    pub fn remove(&self, peer: String) -> Vec<Effect> {
        self.run(|c| {
            c.friendship(
                crate::Action::Remove,
                "/friends/remove",
                serde_json::json!({ "peer": peer }),
            );
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Blocks a user.
    pub fn block(&self, peer: String) -> Vec<Effect> {
        self.run(|c| {
            c.friendship(
                crate::Action::Block,
                "/friends/block",
                serde_json::json!({ "peer": peer }),
            );
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Reports a friend's messages.
    pub fn report(&self, report: ReportInput) -> Vec<Effect> {
        self.run(|c| c.report(&report)).unwrap_or_default()
    }

    /// Claims a username.
    pub fn set_username(&self, username: String) -> Vec<Effect> {
        self.run(|c| {
            c.set_username(&username);
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Deletes the account on the server, then this profile's data.
    pub fn delete_account(&self) -> Vec<Effect> {
        self.run(|c| {
            c.delete_account();
            Ok(())
        })
        .unwrap_or_default()
    }

    /// Registers this device for push wake-ups.
    pub fn register_push(&self, token: PushToken) -> Vec<Effect> {
        self.run(|c| {
            c.register_push(&token);
            Ok(())
        })
        .unwrap_or_default()
    }

    // ── Reads for the UI ─────────────────────────────────────────────────

    /// A page of a conversation, newest last, opened under the unlock.
    pub fn history(
        &self,
        peer: String,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Message>, CoreError> {
        let peer = hqchat_protocol::PeerId::parse(&peer)?;
        self.core().history(&peer, before, limit)
    }

    /// The friends, sorted for display.
    pub fn friends(&self) -> Vec<FriendView> {
        self.core().friends()
    }

    /// Friend requests waiting for this user's answer.
    pub fn invites(&self) -> Vec<crate::InviteView> {
        self.core().invites.clone()
    }

    /// The safety number for a friend's pinned key, to compare in person.
    pub fn fingerprint(&self, peer: String) -> Option<String> {
        let peer = hqchat_protocol::PeerId::parse(&peer).ok()?;
        self.core().fingerprint(&peer)
    }

    // ── I/O results ──────────────────────────────────────────────────────

    /// The answer to an [`Effect::Http`].
    pub fn on_http(&self, req: u64, status: u16, body: Vec<u8>, now: i64) -> Vec<Effect> {
        self.run(|c| {
            c.on_http(req, status, &body, now);
            Ok(())
        })
        .unwrap_or_default()
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
