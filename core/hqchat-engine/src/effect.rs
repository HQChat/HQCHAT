//! What a command asks the shell to do.

use crate::ports::Tier;
use crate::types::{Delivery, Message};

/// An HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
}

/// Where to open a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Raw TCP for hqn/1: the engine runs Noise and MQTT inside it.
    Tcp {
        /// Host.
        host: String,
        /// Port.
        port: u16,
    },
    /// A WebSocket the shell opens with the platform TLS and its SPKI
    /// pinning; the engine runs MQTT inside it.
    Wss {
        /// `wss://<domain>/mqtt`.
        url: String,
    },
}

/// Why a connection closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// The engine asked for it.
    Requested,
    /// The peer closed it.
    Remote,
    /// The network failed; the message is for logs.
    Failed(String),
}

/// Why the engine needs the user to unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockReason {
    /// To sign in.
    SignIn,
    /// To send a message.
    Send,
    /// To read messages that arrived while locked.
    Read,
}

/// The link to the broker, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// No link.
    Offline,
    /// Signing in over REST.
    Authenticating,
    /// Dialling the broker.
    Connecting,
    /// CONNACK received; messages flow.
    Connected,
}

/// One thing for the shell to do. Effects are returned in order and carried
/// out in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Make one HTTPS request to the home server; answer with `Engine::on_http`.
    Http {
        /// Correlates the answer.
        req: u64,
        /// Method.
        method: Method,
        /// Path on the home server, e.g. `/auth/init`.
        path: String,
        /// Attach the session bearer.
        bearer: bool,
        /// JSON body, empty for GET.
        body: Vec<u8>,
    },
    /// Open a connection; answer with `Engine::on_opened` or `on_closed`.
    Open {
        /// Names the connection in later effects and commands.
        conn: u64,
        /// Where.
        endpoint: Endpoint,
    },
    /// Write bytes to an open connection.
    Write {
        /// Which connection.
        conn: u64,
        /// The bytes, already framed and encrypted.
        bytes: Vec<u8>,
    },
    /// Close a connection.
    Close {
        /// Which connection.
        conn: u64,
    },
    /// Call `Engine::tick` at (or after) this time, in milliseconds.
    Timer {
        /// Unix milliseconds.
        at: i64,
    },
    /// Prompt the user, then call `Engine::unlock`.
    NeedUnlock {
        /// What for, to word the prompt.
        reason: UnlockReason,
    },
    /// A message to show: sent by the user or received.
    MessageAdded(Message),
    /// An outgoing message's delivery moved forward.
    MessageStatus {
        /// The message.
        msg_id: String,
        /// Its new status.
        status: Delivery,
    },
    /// The friend list changed; read `Engine::friends`.
    FriendsChanged,
    /// A friend came online or went offline.
    PresenceChanged {
        /// The friend's id.
        peer: String,
        /// Online.
        online: bool,
    },
    /// The link's state changed.
    Connection(ConnState),
    /// The device key's tier changed (a TPM appeared, biometrics removed).
    TierChanged(Tier),
    /// Show a notification for `peer`. Never carries content.
    Notify {
        /// The friend's id.
        peer: String,
    },
    /// An inbound frame was dropped, for the protocol log.
    Dropped {
        /// Why, as the TS and Swift clients word it.
        reason: String,
    },
}
