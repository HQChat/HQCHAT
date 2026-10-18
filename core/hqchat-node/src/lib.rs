//! The HQChat core as a Node addon (`hqchat_node.node`), for
//! `services/server`:
//!
//! - the stateless checks the server and gateway run: HQC-256, the sign-in
//!   proof, the CONNECT proof, ids and topics ([`server`]);
//! - the hqn/1 responder for the gateway ([`gateway`]);
//! - the `Engine` the bot and the reference client run, with a vault and a
//!   file store implemented here ([`engine`]).
//!
//! Byte strings are `Buffer`s; ids are lowercase hex strings.

pub mod engine;
pub mod gateway;
pub mod server;
mod store;

pub(crate) fn err(e: impl std::fmt::Debug) -> napi::Error {
    napi::Error::from_reason(format!("{e:?}"))
}
