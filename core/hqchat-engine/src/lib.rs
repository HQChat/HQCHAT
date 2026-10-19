//! The HQChat client as a sans-IO engine (docs/architecture/core-wiring.md).
//!
//! A shell (Swift, Kotlin, the TS bot) owns one [`Engine`] per profile. It
//! sends commands — user actions and I/O results — and carries out the
//! [`Effect`]s each returns: HTTP requests, socket opens and writes, timers,
//! UI updates. The engine never touches a socket, a file or the clock; it
//! reaches the hardware key and storage through two synchronous callbacks,
//! [`KeyVault`] and [`Store`]. No secret key, ratchet state or root key
//! crosses this API.

mod auth;
mod convo;
mod core;
mod directory;
mod effect;
mod engine;
mod http;
mod import;
mod net;
mod persist;
mod ports;
pub mod software;
mod types;

pub use directory::safety_number;
pub use effect::{Action, CloseReason, ConnState, Effect, Endpoint, Method, UnlockReason};
pub use engine::Engine;
pub use import::{Import, ImportIdentity, ImportMessage, ImportPeer, ImportPending, ImportPrekeys};
pub use ports::{KeyVault, Store, StoreError, Tier, VaultError};
pub use types::{
    Config, CoreError, Delivery, Device, FriendView, InviteView, Message, NetworkInfo, PushToken,
    ReportInput,
};

/// The version of this API; shells check it at startup against the bindings
/// they were generated with.
pub const CORE_API_VERSION: u32 = 1;
