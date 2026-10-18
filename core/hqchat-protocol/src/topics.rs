//! The MQTT topic layout (docs/architecture/emqx-acl.md). Conversation and
//! handshake topic ids are random 64-hex values the server assigns per
//! friendship; inbox, presence and graph are per client.

use crate::{Error, PeerId};

/// A server-assigned conversation or handshake topic id: 64 lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicId(String);

impl TopicId {
    /// Reads a topic id; refuses anything but 64 lowercase hex characters.
    pub fn parse(value: &str) -> Result<TopicId, Error> {
        todo!("lib/protocol-identity-topics")
    }
}

/// `cv/{convoId}`: a friendship's messages and receipts.
pub fn conversation_topic(convo: &TopicId) -> String {
    todo!("lib/protocol-identity-topics")
}

/// `hs/{handshakeId}`: a friendship's handshake challenges and proofs.
pub fn handshake_topic(handshake: &TopicId) -> String {
    todo!("lib/protocol-identity-topics")
}

/// `u/{id}/inbox`: `init` frames, queued while the client is offline.
pub fn inbox_topic(id: &PeerId) -> String {
    todo!("lib/protocol-identity-topics")
}

/// `u/{id}/presence`: retained online/offline.
pub fn presence_topic(id: &PeerId) -> String {
    todo!("lib/protocol-identity-topics")
}

/// `u/{id}/graph`: the server's nudge that the friend list changed.
pub fn graph_topic(id: &PeerId) -> String {
    todo!("lib/protocol-identity-topics")
}

/// Which kind of topic an inbound publish arrived on, and for whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `cv/{id}`.
    Conversation(TopicId),
    /// `hs/{id}`.
    Handshake(TopicId),
    /// `u/{id}/inbox`.
    Inbox(PeerId),
    /// `u/{id}/presence`.
    Presence(PeerId),
    /// `u/{id}/graph`.
    Graph(PeerId),
}

/// Parses a topic name; `None` for anything outside the layout.
pub fn route(topic: &str) -> Option<Route> {
    todo!("lib/protocol-identity-topics")
}
