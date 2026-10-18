//! The HQChat client as a sans-IO engine (docs/architecture/core-wiring.md).
//!
//! A shell (Swift, Kotlin, the TS bot) owns one [`Engine`] per profile. It
//! sends commands — user actions and I/O results — and carries out the
//! [`Effect`]s each returns: HTTP requests, socket opens and writes, timers,
//! UI updates. The engine never touches a socket, a file or the clock; it
//! reaches the hardware key and storage through two synchronous callbacks,
//! [`KeyVault`] and [`Store`]. No secret key, ratchet state or root key
//! crosses this API.
//!
//! **API surface only**: every body is `todo!()` naming the feature branch
//! that implements it.

// The bodies are todo!() until each feature branch lands: parameters are
// named for the reader and private fields are placeholders, not used yet.
#![allow(unused_variables, dead_code)]

mod core;
mod effect;
mod engine;
mod persist;
mod ports;
pub mod software;
mod types;

pub use effect::{CloseReason, ConnState, Effect, Endpoint, Method, UnlockReason};
pub use engine::Engine;
pub use ports::{KeyVault, Store, StoreError, Tier, VaultError};
pub use types::{
    Config, CoreError, Delivery, FriendView, Message, NetworkInfo, PushToken, ReportInput,
};

/// The version of this API; shells check it at startup against the bindings
/// they were generated with.
pub const CORE_API_VERSION: u32 = 1;
