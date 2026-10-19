//! The records, enums and errors that cross the boundary, mirroring
//! `hqchat-engine`'s, with conversions both ways.

use hqchat_engine as core;

/// How strongly the device key is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Tier {
    /// In hardware behind biometrics.
    Hardware,
    /// In hardware behind the device passcode only.
    HardwarePasscode,
    /// No hardware: sealed under a passphrase. Warned, not penalised.
    Software,
}

impl From<core::Tier> for Tier {
    fn from(t: core::Tier) -> Self {
        match t {
            core::Tier::Hardware => Tier::Hardware,
            core::Tier::HardwarePasscode => Tier::HardwarePasscode,
            core::Tier::Software => Tier::Software,
        }
    }
}

impl From<Tier> for core::Tier {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Hardware => core::Tier::Hardware,
            Tier::HardwarePasscode => core::Tier::HardwarePasscode,
            Tier::Software => core::Tier::Software,
        }
    }
}

/// Why a vault call failed (thrown by the shell's `KeyVault`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    /// The user has not unlocked, or dismissed the prompt.
    #[error("locked")]
    Locked,
    /// There is no device key yet.
    #[error("no device key")]
    Missing,
    /// The platform refused the key.
    #[error("unavailable: {message}")]
    Unavailable {
        /// Why, for logs.
        message: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for VaultError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        VaultError::Unavailable { message: e.reason }
    }
}

impl From<VaultError> for core::VaultError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => core::VaultError::Locked,
            VaultError::Missing => core::VaultError::Missing,
            VaultError::Unavailable { message } => core::VaultError::Unavailable(message),
        }
    }
}

/// Why a store call failed (thrown by the shell's `Store`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StoreError {
    /// The write did not happen.
    #[error("write failed: {message}")]
    Write {
        /// Why.
        message: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        StoreError::Write { message: e.reason }
    }
}

/// Why a command failed: stable cases the UI maps to words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    /// There is no identity on this profile yet.
    #[error("no identity")]
    NoIdentity,
    /// The peer is not a synced friend.
    #[error("not a friend")]
    NotAFriend,
    /// The peer has published no prekeys yet.
    #[error("no prekeys")]
    NoPrekeys,
    /// Locked: prompt, then `unlock`, then try again.
    #[error("locked")]
    Locked,
    /// The vault refused for another reason.
    #[error("vault: {message}")]
    Vault {
        /// Why.
        message: String,
    },
    /// The store refused.
    #[error("store: {message}")]
    Store {
        /// Why.
        message: String,
    },
    /// Stored state could not be read.
    #[error("state: {message}")]
    State {
        /// Why.
        message: String,
    },
    /// A protocol operation failed.
    #[error("protocol: {message}")]
    Protocol {
        /// Why.
        message: String,
    },
}

impl From<core::CoreError> for CoreError {
    fn from(e: core::CoreError) -> Self {
        match e {
            core::CoreError::NoIdentity => CoreError::NoIdentity,
            core::CoreError::NotAFriend => CoreError::NotAFriend,
            core::CoreError::NoPrekeys => CoreError::NoPrekeys,
            core::CoreError::Vault(core::VaultError::Locked) => CoreError::Locked,
            core::CoreError::Vault(v) => CoreError::Vault {
                message: format!("{v:?}"),
            },
            core::CoreError::Store(core::StoreError::Write(message)) => {
                CoreError::Store { message }
            }
            core::CoreError::State(message) => CoreError::State { message },
            core::CoreError::Protocol(message) => CoreError::Protocol { message },
        }
    }
}

/// The kind of device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Device {
    /// iPhone and iPad.
    Ios,
    /// macOS.
    Macos,
    /// Android.
    Android,
    /// Linux desktop.
    Linux,
    /// Windows desktop.
    Windows,
    /// No UI.
    Headless,
}

/// How the engine is set up.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Config {
    /// The home server's origin.
    pub server_url: String,
    /// The local profile.
    pub profile_id: String,
    /// What the engine runs on.
    pub device: Device,
}

impl From<Config> for core::Config {
    fn from(c: Config) -> Self {
        core::Config {
            server_url: c.server_url,
            profile_id: c.profile_id,
            // The apps take hqn/1 whenever the server offers it.
            allow_hqn: true,
            device: match c.device {
                Device::Ios => core::Device::Ios,
                Device::Macos => core::Device::Macos,
                Device::Android => core::Device::Android,
                Device::Linux => core::Device::Linux,
                Device::Windows => core::Device::Windows,
                Device::Headless => core::Device::Headless,
            },
        }
    }
}

/// The network the device is on.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkInfo {
    /// A stable key for the network.
    pub key: String,
    /// Metered.
    pub expensive: bool,
}

impl From<NetworkInfo> for core::NetworkInfo {
    fn from(n: NetworkInfo) -> Self {
        core::NetworkInfo {
            key: n.key,
            expensive: n.expensive,
        }
    }
}

/// An HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
}

/// Where to open a connection.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Endpoint {
    /// Raw TCP for hqn/1.
    Tcp {
        /// Host.
        host: String,
        /// Port.
        port: u16,
    },
    /// A WebSocket opened with the platform TLS and SPKI pinning.
    Wss {
        /// URL.
        url: String,
    },
}

/// Why a connection closed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CloseReason {
    /// The engine asked for it.
    Requested,
    /// The peer closed it.
    Remote,
    /// The network failed.
    Failed {
        /// For logs.
        message: String,
    },
}

impl From<CloseReason> for core::CloseReason {
    fn from(r: CloseReason) -> Self {
        match r {
            CloseReason::Requested => core::CloseReason::Requested,
            CloseReason::Remote => core::CloseReason::Remote,
            CloseReason::Failed { message } => core::CloseReason::Failed(message),
        }
    }
}

/// Why the engine needs an unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnlockReason {
    /// To sign in.
    SignIn,
    /// To send.
    Send,
    /// To read.
    Read,
}

/// The link to the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnState {
    /// No link.
    Offline,
    /// Signing in.
    Authenticating,
    /// Dialling.
    Connecting,
    /// Messages flow.
    Connected,
}

/// An outgoing message's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Delivery {
    /// Sealing or waiting for the link.
    Sending,
    /// The broker queued it for an offline friend.
    Queued,
    /// The broker acknowledged it.
    Sent,
    /// The friend's receipt arrived.
    Delivered,
    /// It could not be sent; `retry` sends it again.
    Failed,
}

/// A user action that goes to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Action {
    /// Sign-in or refresh.
    SignIn,
    /// Claiming a username.
    SetUsername,
    /// A friend request.
    Invite,
    /// Accepting one.
    Accept,
    /// Removing a friend.
    Remove,
    /// Blocking.
    Block,
    /// Lifting a block.
    Unblock,
    /// A report.
    Report,
    /// Deleting the account.
    DeleteAccount,
    /// Registering for push.
    RegisterPush,
    /// Publishing prekeys.
    PublishPrekeys,
}

/// A message as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Message {
    /// Shared by both sides.
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
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FriendView {
    /// Their id.
    pub id: String,
    /// Their username.
    pub username: Option<String>,
    /// Online now.
    pub online: bool,
    /// A session is open.
    pub has_session: bool,
    /// Unread, including those waiting for an unlock.
    pub unread: u32,
    /// When this user blocked them (Unix milliseconds): read-only.
    pub blocked_at: Option<i64>,
    /// When their identity was replaced under the same username: read-only.
    pub vanished_at: Option<i64>,
}

/// A friend request waiting for an answer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InviteView {
    /// Who sent it.
    pub id: String,
    /// Their username.
    pub username: String,
}

/// A report about a friend's messages.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReportInput {
    /// The reported friend.
    pub peer: String,
    /// The reason chosen.
    pub reason: String,
    /// Messages whose text is the excerpt.
    pub msg_ids: Vec<String>,
    /// Block them too.
    pub block: bool,
}

impl From<ReportInput> for core::ReportInput {
    fn from(r: ReportInput) -> Self {
        core::ReportInput {
            peer: r.peer,
            reason: r.reason,
            msg_ids: r.msg_ids,
            block: r.block,
        }
    }
}

/// A push registration.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PushToken {
    /// APNs.
    Apns {
        /// Device token, hex.
        token: String,
        /// Sandbox or production.
        sandbox: bool,
    },
    /// FCM.
    Fcm {
        /// Registration token.
        token: String,
    },
    /// UnifiedPush.
    UnifiedPush {
        /// Endpoint URL.
        endpoint: String,
    },
}

impl From<PushToken> for core::PushToken {
    fn from(p: PushToken) -> Self {
        match p {
            PushToken::Apns { token, sandbox } => core::PushToken::Apns { token, sandbox },
            PushToken::Fcm { token } => core::PushToken::Fcm { token },
            PushToken::UnifiedPush { endpoint } => core::PushToken::UnifiedPush { endpoint },
        }
    }
}

/// One thing for the shell to do, in order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Effect {
    /// One HTTPS request; answer with `on_http`.
    Http {
        /// Correlates the answer.
        req: u64,
        /// Method.
        method: Method,
        /// Path on the home server.
        path: String,
        /// Bearer token.
        authorization: Option<String>,
        /// JSON body.
        body: Vec<u8>,
    },
    /// Open a connection; answer with `on_opened` or `on_closed`.
    Open {
        /// The connection.
        conn: u64,
        /// Where.
        endpoint: Endpoint,
    },
    /// Write bytes.
    Write {
        /// The connection.
        conn: u64,
        /// Already framed and encrypted.
        bytes: Vec<u8>,
    },
    /// Close a connection.
    Close {
        /// The connection.
        conn: u64,
    },
    /// Call `tick` at or after this time.
    Timer {
        /// Unix milliseconds.
        at: i64,
    },
    /// Prompt the user, then `unlock`.
    NeedUnlock {
        /// What for.
        reason: UnlockReason,
    },
    /// A message to show.
    MessageAdded {
        /// The message.
        message: Message,
    },
    /// An outgoing message moved forward.
    MessageStatus {
        /// Which.
        msg_id: String,
        /// Its new status.
        status: Delivery,
    },
    /// Read `friends`.
    FriendsChanged,
    /// Read `invites`.
    InvitesChanged,
    /// A friend came online or left.
    PresenceChanged {
        /// The friend.
        peer: String,
        /// Online.
        online: bool,
    },
    /// The link's state.
    Connection {
        /// The state.
        state: ConnState,
    },
    /// The device key's tier changed.
    TierChanged {
        /// The tier.
        tier: Tier,
    },
    /// Show a notification for a friend; never content.
    Notify {
        /// The friend.
        peer: String,
    },
    /// The server refused an action.
    ActionFailed {
        /// Which.
        action: Action,
        /// HTTP status; 0 when unreachable.
        status: u16,
        /// The server's code.
        code: String,
    },
    /// The account and this profile's data are gone.
    AccountDeleted,
    /// An inbound frame was dropped, for the protocol log.
    Dropped {
        /// Why.
        reason: String,
    },
    /// The store refused a write; warn the user.
    StorageFailed {
        /// What, and why.
        reason: String,
    },
}

impl From<Delivery> for core::Delivery {
    fn from(d: Delivery) -> Self {
        match d {
            Delivery::Sending => core::Delivery::Sending,
            Delivery::Queued => core::Delivery::Queued,
            Delivery::Sent => core::Delivery::Sent,
            Delivery::Delivered => core::Delivery::Delivered,
            Delivery::Failed => core::Delivery::Failed,
        }
    }
}

fn delivery(d: core::Delivery) -> Delivery {
    match d {
        core::Delivery::Sending => Delivery::Sending,
        core::Delivery::Queued => Delivery::Queued,
        core::Delivery::Sent => Delivery::Sent,
        core::Delivery::Delivered => Delivery::Delivered,
        core::Delivery::Failed => Delivery::Failed,
    }
}

impl From<core::Message> for Message {
    fn from(m: core::Message) -> Self {
        Message {
            msg_id: m.msg_id,
            peer: m.peer,
            outgoing: m.outgoing,
            text: m.text,
            at: m.at,
            delivery: m.delivery.map(delivery),
        }
    }
}

impl From<core::FriendView> for FriendView {
    fn from(f: core::FriendView) -> Self {
        FriendView {
            id: f.id,
            username: f.username,
            online: f.online,
            has_session: f.has_session,
            unread: f.unread,
            blocked_at: f.blocked_at,
            vanished_at: f.vanished_at,
        }
    }
}

impl From<core::InviteView> for InviteView {
    fn from(i: core::InviteView) -> Self {
        InviteView {
            id: i.id,
            username: i.username,
        }
    }
}

impl From<core::Effect> for Effect {
    fn from(e: core::Effect) -> Self {
        match e {
            core::Effect::Http {
                req,
                method,
                path,
                authorization,
                body,
            } => Effect::Http {
                req,
                method: match method {
                    core::Method::Get => Method::Get,
                    core::Method::Post => Method::Post,
                },
                path,
                authorization,
                body,
            },
            core::Effect::Open { conn, endpoint } => Effect::Open {
                conn,
                endpoint: match endpoint {
                    core::Endpoint::Tcp { host, port } => Endpoint::Tcp { host, port },
                    core::Endpoint::Wss { url } => Endpoint::Wss { url },
                },
            },
            core::Effect::Write { conn, bytes } => Effect::Write { conn, bytes },
            core::Effect::Close { conn } => Effect::Close { conn },
            core::Effect::Timer { at } => Effect::Timer { at },
            core::Effect::NeedUnlock { reason } => Effect::NeedUnlock {
                reason: match reason {
                    core::UnlockReason::SignIn => UnlockReason::SignIn,
                    core::UnlockReason::Send => UnlockReason::Send,
                    core::UnlockReason::Read => UnlockReason::Read,
                },
            },
            core::Effect::MessageAdded(m) => Effect::MessageAdded { message: m.into() },
            core::Effect::MessageStatus { msg_id, status } => Effect::MessageStatus {
                msg_id,
                status: delivery(status),
            },
            core::Effect::FriendsChanged => Effect::FriendsChanged,
            core::Effect::InvitesChanged => Effect::InvitesChanged,
            core::Effect::PresenceChanged { peer, online } => {
                Effect::PresenceChanged { peer, online }
            }
            core::Effect::Connection(s) => Effect::Connection {
                state: match s {
                    core::ConnState::Offline => ConnState::Offline,
                    core::ConnState::Authenticating => ConnState::Authenticating,
                    core::ConnState::Connecting => ConnState::Connecting,
                    core::ConnState::Connected => ConnState::Connected,
                },
            },
            core::Effect::TierChanged(t) => Effect::TierChanged { tier: t.into() },
            core::Effect::Notify { peer } => Effect::Notify { peer },
            core::Effect::ActionFailed {
                action,
                status,
                code,
            } => Effect::ActionFailed {
                action: match action {
                    core::Action::SignIn => Action::SignIn,
                    core::Action::SetUsername => Action::SetUsername,
                    core::Action::Invite => Action::Invite,
                    core::Action::Accept => Action::Accept,
                    core::Action::Remove => Action::Remove,
                    core::Action::Block => Action::Block,
                    core::Action::Unblock => Action::Unblock,
                    core::Action::Report => Action::Report,
                    core::Action::DeleteAccount => Action::DeleteAccount,
                    core::Action::RegisterPush => Action::RegisterPush,
                    core::Action::PublishPrekeys => Action::PublishPrekeys,
                },
                status,
                code,
            },
            core::Effect::AccountDeleted => Effect::AccountDeleted,
            core::Effect::Dropped { reason } => Effect::Dropped { reason },
            core::Effect::StorageFailed { reason } => Effect::StorageFailed { reason },
        }
    }
}
