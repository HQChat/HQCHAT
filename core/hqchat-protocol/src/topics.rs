//! The MQTT topic layout (infra/emqx/acl.conf, docs/architecture/emqx-acl.md).
//!
//! `cv/{convoId}` and `hs/{handshakeId}` are capabilities: random ids minted
//! per friendship and given only to its two members. `u/{id}/…` topics are
//! addressed by client id: presence is owner-publish, inbox and graph
//! owner-subscribe.

use crate::identity::is_lower_hex;
use crate::{Error, PeerId};

/// A server-assigned conversation or handshake topic id: 64 lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicId(String);

impl TopicId {
    /// Reads a topic id; refuses anything but 64 lowercase hex characters.
    pub fn parse(value: &str) -> Result<TopicId, Error> {
        if is_lower_hex(value, 64) {
            Ok(TopicId(value.to_owned()))
        } else {
            Err(Error::Malformed(
                "a topic id is 64 lowercase hex characters",
            ))
        }
    }

    /// The id as hex.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `cv/{convoId}`: a friendship's messages and receipts.
pub fn conversation_topic(convo: &TopicId) -> String {
    format!("cv/{}", convo.0)
}

/// `hs/{handshakeId}`: a friendship's handshake challenges and proofs.
pub fn handshake_topic(handshake: &TopicId) -> String {
    format!("hs/{}", handshake.0)
}

/// `u/{id}/inbox`: `init` frames, queued while the client is offline.
pub fn inbox_topic(id: &PeerId) -> String {
    format!("u/{id}/inbox")
}

/// `u/{id}/presence`: retained online/offline.
pub fn presence_topic(id: &PeerId) -> String {
    format!("u/{id}/presence")
}

/// `u/{id}/graph`: the server's nudge that the friend list changed.
pub fn graph_topic(id: &PeerId) -> String {
    format!("u/{id}/graph")
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

/// Parses a topic name; `None` for anything outside the layout, wildcards
/// and uppercase ids included.
pub fn route(topic: &str) -> Option<Route> {
    let parts: Vec<&str> = topic.split('/').collect();
    match parts.as_slice() {
        ["cv", id] => TopicId::parse(id).ok().map(Route::Conversation),
        ["hs", id] => TopicId::parse(id).ok().map(Route::Handshake),
        ["u", id, kind] => {
            let id = PeerId::parse(id).ok()?;
            match *kind {
                "inbox" => Some(Route::Inbox(id)),
                "presence" => Some(Route::Presence(id)),
                "graph" => Some(Route::Graph(id)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// A topic as logs and diagnostics may show it. A conversation or handshake
/// id is the permission to read that topic, so none of it is shown; a client
/// id is public and is cut to its first 8 characters.
pub fn redacted(topic: &str) -> String {
    match route(topic) {
        Some(Route::Conversation(_)) => "cv/…".into(),
        Some(Route::Handshake(_)) => "hs/…".into(),
        Some(Route::Inbox(id)) => format!("u/{}…/inbox", short(&id)),
        Some(Route::Presence(id)) => format!("u/{}…/presence", short(&id)),
        Some(Route::Graph(id)) => format!("u/{}…/graph", short(&id)),
        None => "a topic outside the layout".into(),
    }
}

/// The first 8 characters of a client id, for logs.
pub fn short(id: &PeerId) -> &str {
    id.as_str().get(..8).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redacted_topic_shows_no_topic_id() {
        let t = TopicId::parse(T).unwrap();
        let id = PeerId::parse(A).unwrap();
        for topic in [conversation_topic(&t), handshake_topic(&t)] {
            assert!(!redacted(&topic).contains(&T[..4]), "{topic}");
        }
        assert_eq!(redacted(&inbox_topic(&id)), "u/f25f3361…/inbox");
        assert_eq!(redacted("cv/not-an-id"), "a topic outside the layout");
    }

    const A: &str = "f25f33617a50eb83c2d695798e186e0ef2fb91018220e8383cf8577cc905e231";
    const T: &str = "8006188126a94e92a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";

    #[test]
    fn topics_have_the_broker_layout() {
        let id = PeerId::parse(A).unwrap();
        let t = TopicId::parse(T).unwrap();
        assert_eq!(conversation_topic(&t), format!("cv/{T}"));
        assert_eq!(handshake_topic(&t), format!("hs/{T}"));
        assert_eq!(inbox_topic(&id), format!("u/{A}/inbox"));
        assert_eq!(presence_topic(&id), format!("u/{A}/presence"));
        assert_eq!(graph_topic(&id), format!("u/{A}/graph"));
    }

    #[test]
    fn every_topic_routes_back_to_what_built_it() {
        let id = PeerId::parse(A).unwrap();
        let t = TopicId::parse(T).unwrap();
        assert_eq!(
            route(&conversation_topic(&t)),
            Some(Route::Conversation(t.clone()))
        );
        assert_eq!(route(&handshake_topic(&t)), Some(Route::Handshake(t)));
        assert_eq!(route(&inbox_topic(&id)), Some(Route::Inbox(id.clone())));
        assert_eq!(
            route(&presence_topic(&id)),
            Some(Route::Presence(id.clone()))
        );
        assert_eq!(route(&graph_topic(&id)), Some(Route::Graph(id)));
    }

    #[test]
    fn anything_off_the_layout_does_not_route() {
        for topic in [
            "#",
            "cv/+",
            "cv/#",
            "u/+/presence",
            &format!("cv/{}", T.to_uppercase()),
            &format!("cv/{T}/extra"),
            &format!("u/{A}/other"),
            &format!("u/{A}"),
            &format!("x/{T}"),
            "",
        ] {
            assert_eq!(route(topic), None, "{topic} routed");
        }
    }
}
