//! Requests to the home server: each [`Effect::Http`] is remembered by its
//! id with what its answer is for, and `Engine::on_http` routes the answer.

use serde_json::Value;

use crate::core::Core;
use crate::effect::{Action, Effect, Method};

/// What an outstanding request is for.
#[derive(Debug)]
pub(crate) enum Pending {
    AuthInit,
    AuthVerify {
        signing: hqchat_protocol::mqtt_proof::SigningKey,
    },
    AuthRefresh {
        signing: hqchat_protocol::mqtt_proof::SigningKey,
    },
    /// A user action whose only answer is success or failure.
    Action(Action),
    /// A friendship action: on success, re-read the directory.
    ThenSync(Action),
    Friends,
    Invites,
    PrekeyCount,
    Transport,
    PeerKey(hqchat_protocol::PeerId),
    Claim(hqchat_protocol::PeerId),
    DeleteAccount,
}

/// An answer: the status and the body parsed as JSON (`Null` when not JSON).
pub(crate) struct Answer {
    pub status: u16,
    pub body: Value,
}

impl Answer {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The server's `error` code.
    pub fn code(&self) -> String {
        self.body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    pub fn str(&self, field: &str) -> Option<&str> {
        self.body.get(field).and_then(Value::as_str)
    }
}

impl Core {
    /// Emits a request and remembers what it is for.
    pub fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
        with_session: bool,
        pending: Pending,
    ) {
        self.http_next = self.http_next.wrapping_add(1);
        let req = self.http_next;
        self.http_pending.insert(req, pending);
        let authorization = if with_session {
            self.auth.token.clone()
        } else {
            None
        };
        let body = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        self.emit(Effect::Http {
            req,
            method,
            path: path.to_owned(),
            authorization,
            body,
        });
    }

    /// Routes the answer to request `req`; an unknown id is ignored.
    pub fn on_http(&mut self, req: u64, status: u16, body: &[u8], now: i64) {
        let Some(pending) = self.http_pending.remove(&req) else {
            return;
        };
        let answer = Answer {
            status,
            body: serde_json::from_slice(body).unwrap_or(Value::Null),
        };
        match pending {
            Pending::AuthInit => self.on_auth_init(answer, now),
            Pending::AuthVerify { signing } => self.on_auth_verify(answer, signing, now),
            Pending::AuthRefresh { signing } => self.on_auth_refresh(answer, signing, now),
            Pending::Action(action) => {
                if !answer.ok() {
                    self.fail(action, &answer);
                }
            }
            Pending::DeleteAccount => self.on_account_deleted(answer),
            Pending::ThenSync(action) => self.on_then_sync(action, answer),
            Pending::Friends => self.on_friends(answer),
            Pending::Invites => self.on_invites(answer),
            Pending::PrekeyCount => self.on_prekey_count(answer, now),
            Pending::Transport => self.on_transport(answer, now),
            Pending::PeerKey(peer) => self.on_peer_key(peer, answer, now),
            Pending::Claim(peer) => self.on_claim(peer, answer, now),
        }
    }

    pub fn fail(&mut self, action: Action, answer: &Answer) {
        self.emit(Effect::ActionFailed {
            action,
            status: answer.status,
            code: answer.code(),
        });
    }
}
