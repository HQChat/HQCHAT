//! The records that cross the API.

use crate::ports::{StoreError, VaultError};

/// How the engine is set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The home server's origin, e.g. `https://hqchat.app`.
    pub server_url: String,
    /// The local profile this engine belongs to; namespaces its store keys.
    pub profile_id: String,
    /// What the engine runs on: names the push platform.
    pub device: Device,
    /// Whether the broker may be reached over hqn/1 when the server offers
    /// it. The apps always allow it; a server-side client (the bot) that has
    /// a private path to the broker's WebSocket keeps to WSS.
    pub allow_hqn: bool,
}

/// The kind of device, as the server's push registration names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    /// iPhone and iPad.
    Ios,
    /// macOS.
    Macos,
    /// Android.
    Android,
    /// A Linux desktop.
    Linux,
    /// A Windows desktop.
    Windows,
    /// A process with no UI (the bot, tests).
    Headless,
}

/// The network the device is on, for the transport choice (hqn/1 blocked on
/// some networks, WSS always last).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    /// A stable key for the network (hashed SSID, cellular carrier).
    pub key: String,
    /// Whether the OS says the network is metered.
    pub expensive: bool,
}

/// An outgoing message's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Delivery {
    /// Sealing or waiting for the link.
    Sending,
    /// The broker queued it for an offline peer.
    Queued,
    /// The broker acknowledged it.
    Sent,
    /// The peer's receipt arrived.
    Delivered,
    /// It could not be sent; `Engine::retry` resends it under its id.
    Failed,
}

/// A message as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its id, shared by both sides.
    pub msg_id: String,
    /// The friend's id.
    pub peer: String,
    /// Sent by this user.
    pub outgoing: bool,
    /// The text.
    pub text: String,
    /// Unix milliseconds.
    pub at: i64,
    /// For outgoing messages.
    pub delivery: Option<Delivery>,
}

/// A friend as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendView {
    /// The friend's id.
    pub id: String,
    /// Their username, once claimed.
    pub username: Option<String>,
    /// Online now.
    pub online: bool,
    /// A session is open.
    pub has_session: bool,
    /// Unread messages, including those waiting for an unlock.
    pub unread: u32,
    /// When this user blocked them (Unix milliseconds): read-only until
    /// `Engine::unblock`.
    pub blocked_at: Option<i64>,
    /// When their identity was replaced by a new one under the same
    /// username: read-only until `Engine::forget`. Also what an
    /// impersonation looks like.
    pub vanished_at: Option<i64>,
    /// Their identity key is pinned (checked against their id).
    pub has_key: bool,
    /// The user compared the safety number with them.
    pub verified: bool,
}

/// A friend request this user sent, not answered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentInviteView {
    /// The username or id it was sent to, as typed.
    pub to: String,
    /// When, in Unix milliseconds.
    pub at: i64,
}

/// A friend request waiting for this user's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteView {
    /// Who sent it.
    pub id: String,
    /// Their username.
    pub username: String,
}

/// A report about a friend's message (moderation, docs/runbooks/moderation.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportInput {
    /// The reported friend.
    pub peer: String,
    /// The reason chosen.
    pub reason: String,
    /// The message ids whose text is sent as the excerpt.
    pub msg_ids: Vec<String>,
    /// Block them too.
    pub block: bool,
}

/// A push registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushToken {
    /// Apple Push Notification service.
    Apns {
        /// Device token, hex.
        token: String,
        /// Sandbox or production.
        sandbox: bool,
    },
    /// Firebase Cloud Messaging.
    Fcm {
        /// Registration token.
        token: String,
    },
    /// A UnifiedPush distributor endpoint.
    UnifiedPush {
        /// The endpoint URL.
        endpoint: String,
    },
}

/// Why a command failed. Stable codes the UI maps to words; never a string
/// to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// There is no identity on this profile yet.
    NoIdentity,
    /// The peer is not a synced friend.
    NotAFriend,
    /// The peer has published no prekeys yet.
    NoPrekeys,
    /// The vault refused.
    Vault(VaultError),
    /// The store refused.
    Store(StoreError),
    /// Stored state could not be read (corrupt, or from a newer version).
    State(String),
    /// A protocol operation failed.
    Protocol(String),
}

impl From<VaultError> for CoreError {
    fn from(e: VaultError) -> Self {
        CoreError::Vault(e)
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        CoreError::Store(e)
    }
}

impl From<hqc::Error> for CoreError {
    fn from(e: hqc::Error) -> Self {
        CoreError::Protocol(e.to_string())
    }
}

impl From<hqchat_protocol::Error> for CoreError {
    fn from(e: hqchat_protocol::Error) -> Self {
        CoreError::Protocol(e.to_string())
    }
}
