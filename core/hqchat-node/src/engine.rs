//! The `Engine` for the bot and the reference client: commands in, effects
//! out, exactly as the apps use it, with a software vault (the bot has no
//! hardware key) and a directory store. Effects are plain objects with a
//! `kind` and the fields that kind carries.

use std::sync::Arc;

use hqchat_engine::software::SoftwareVault;
use hqchat_engine::{
    CloseReason, Config, Delivery, Device, Effect, Endpoint, Engine, Message, Method, NetworkInfo,
    PushToken, ReportInput,
};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::err;
use crate::store::DirStore;

/// How a Node engine is set up.
#[napi(object)]
pub struct EngineOptions {
    /// The home server's origin.
    pub server_url: String,
    /// The profile; names nothing on disk but namespaces nothing either.
    pub profile_id: String,
    /// Directory the engine's sealed blobs live in.
    pub dir: String,
    /// The device key from a previous run (`deviceKey`), if any.
    pub device_key: Option<Buffer>,
    /// Whether to reach the broker over hqn/1 when the server offers it
    /// (default true); false keeps to WSS.
    pub hqn: Option<bool>,
}

/// A message as the UI shows it.
#[napi(object)]
pub struct JsMessage {
    /// Shared by both sides.
    pub msg_id: String,
    /// The friend's id.
    pub peer: String,
    /// Sent by this client.
    pub outgoing: bool,
    /// The text.
    pub text: String,
    /// Unix milliseconds.
    pub at: i64,
    /// `sending`, `queued`, `sent`, `delivered`, `failed`; outgoing only.
    pub delivery: Option<String>,
}

/// One effect. `kind` names it; the other fields are set when it has them.
#[napi(object)]
#[derive(Default)]
pub struct JsEffect {
    /// `http`, `open`, `write`, `close`, `timer`, `needUnlock`, `messageAdded`,
    /// `messageStatus`, `friendsChanged`, `invitesChanged`, `presenceChanged`,
    /// `connection`, `tierChanged`, `notify`, `actionFailed`, `accountDeleted`,
    /// `dropped`.
    pub kind: String,
    /// http: correlates `onHttp`.
    pub req: Option<i64>,
    /// http: `GET` or `POST`.
    pub method: Option<String>,
    /// http: the path on the home server.
    pub path: Option<String>,
    /// http: the bearer token.
    pub authorization: Option<String>,
    /// http: the JSON body; write: the bytes.
    pub body: Option<Buffer>,
    /// open, write, close: the connection.
    pub conn: Option<i64>,
    /// open: `tcp` (hqn/1) or `wss`.
    pub transport: Option<String>,
    /// open tcp: host.
    pub host: Option<String>,
    /// open tcp: port.
    pub port: Option<u32>,
    /// open wss: URL.
    pub url: Option<String>,
    /// timer: when to call `tick`.
    pub at: Option<i64>,
    /// needUnlock, dropped: why.
    pub reason: Option<String>,
    /// messageAdded.
    pub message: Option<JsMessage>,
    /// messageStatus.
    pub msg_id: Option<String>,
    /// messageStatus: the new status; connection: the state; tierChanged: the tier.
    pub state: Option<String>,
    /// presenceChanged, notify: the friend.
    pub peer: Option<String>,
    /// presenceChanged.
    pub online: Option<bool>,
    /// actionFailed: which action.
    pub action: Option<String>,
    /// actionFailed: HTTP status.
    pub status: Option<u32>,
    /// actionFailed: the server's code.
    pub code: Option<String>,
}

fn delivery(d: Delivery) -> String {
    format!("{d:?}").to_lowercase()
}

fn message(m: Message) -> JsMessage {
    JsMessage {
        msg_id: m.msg_id,
        peer: m.peer,
        outgoing: m.outgoing,
        text: m.text,
        at: m.at,
        delivery: m.delivery.map(delivery),
    }
}

fn camel(s: impl std::fmt::Debug) -> String {
    let s = format!("{s:?}");
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_lowercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

fn js(effect: Effect) -> JsEffect {
    let k = |kind: &str| JsEffect {
        kind: kind.into(),
        ..Default::default()
    };
    match effect {
        Effect::Http {
            req,
            method,
            path,
            authorization,
            body,
        } => JsEffect {
            req: Some(to_js(req)),
            method: Some(if method == Method::Get { "GET" } else { "POST" }.into()),
            path: Some(path),
            authorization,
            body: Some(body.into()),
            ..k("http")
        },
        Effect::Open { conn, endpoint } => {
            let base = JsEffect {
                conn: Some(to_js(conn)),
                ..k("open")
            };
            match endpoint {
                Endpoint::Tcp { host, port } => JsEffect {
                    transport: Some("tcp".into()),
                    host: Some(host),
                    port: Some(port.into()),
                    ..base
                },
                Endpoint::Wss { url } => JsEffect {
                    transport: Some("wss".into()),
                    url: Some(url),
                    ..base
                },
            }
        }
        Effect::Write { conn, bytes } => JsEffect {
            conn: Some(to_js(conn)),
            body: Some(bytes.into()),
            ..k("write")
        },
        Effect::Close { conn } => JsEffect {
            conn: Some(to_js(conn)),
            ..k("close")
        },
        Effect::Timer { at } => JsEffect {
            at: Some(at),
            ..k("timer")
        },
        Effect::NeedUnlock { reason } => JsEffect {
            reason: Some(camel(reason)),
            ..k("needUnlock")
        },
        Effect::MessageAdded(m) => JsEffect {
            message: Some(message(m)),
            ..k("messageAdded")
        },
        Effect::MessageStatus { msg_id, status } => JsEffect {
            msg_id: Some(msg_id),
            state: Some(delivery(status)),
            ..k("messageStatus")
        },
        Effect::FriendsChanged => k("friendsChanged"),
        Effect::InvitesChanged => k("invitesChanged"),
        Effect::ActionDone { action } => JsEffect {
            action: Some(camel(action)),
            ..k("actionDone")
        },
        Effect::PresenceChanged { peer, online } => JsEffect {
            peer: Some(peer),
            online: Some(online),
            ..k("presenceChanged")
        },
        Effect::Connection(s) => JsEffect {
            state: Some(camel(s)),
            ..k("connection")
        },
        Effect::TierChanged(t) => JsEffect {
            state: Some(camel(t)),
            ..k("tierChanged")
        },
        Effect::Notify { peer } => JsEffect {
            peer: Some(peer),
            ..k("notify")
        },
        Effect::ActionFailed {
            action,
            status,
            code,
        } => JsEffect {
            action: Some(camel(action)),
            status: Some(status.into()),
            code: Some(code),
            ..k("actionFailed")
        },
        Effect::AccountDeleted => k("accountDeleted"),
        Effect::Dropped { reason } => JsEffect {
            reason: Some(reason),
            ..k("dropped")
        },
        Effect::StorageFailed { reason } => JsEffect {
            reason: Some(reason),
            ..k("storageFailed")
        },
    }
}

/// An engine id (a counter from 1) as a JS number. Ids never get near
/// 2^53, past which JS numbers lose precision anyway.
fn to_js(id: u64) -> i64 {
    i64::try_from(id).unwrap_or(i64::MAX)
}

/// An id JS hands back; a negative one was never issued, so it is refused
/// rather than reinterpreted as a huge unsigned one.
fn from_js(id: i64) -> napi::Result<u64> {
    u64::try_from(id).map_err(|_| napi::Error::from_reason(format!("{id} is not an engine id")))
}

fn all(effects: Vec<Effect>) -> Vec<JsEffect> {
    effects.into_iter().map(js).collect()
}

fn net(key: String) -> NetworkInfo {
    NetworkInfo {
        key,
        expensive: false,
    }
}

/// A friend as the UI shows it.
#[napi(object)]
pub struct JsFriend {
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
    /// When this user blocked them (Unix milliseconds).
    pub blocked_at: Option<i64>,
    /// When their identity was replaced under the same username.
    pub vanished_at: Option<i64>,
    /// Their identity key is pinned.
    pub has_key: bool,
    /// The safety number was compared.
    pub verified: bool,
}

/// A friend request sent and not answered yet.
#[napi(object)]
pub struct JsSentInvite {
    /// The username or id, as typed.
    pub to: String,
    /// When, in Unix milliseconds.
    pub at: i64,
}

/// A friend request waiting for an answer.
#[napi(object)]
pub struct JsInvite {
    /// Who sent it.
    pub id: String,
    /// Their username.
    pub username: String,
}

/// What `importLegacy` did.
#[napi(object)]
pub struct JsImport {
    /// The effects of the import (the tier).
    pub effects: Vec<JsEffect>,
    /// Friends whose session could not be read: imported without one.
    pub unreadable: Vec<String>,
}

/// The engine, headless.
#[napi(js_name = "Engine")]
pub struct JsEngine {
    engine: Engine,
    vault: Arc<SoftwareVault>,
}

#[napi]
#[allow(missing_docs)]
impl JsEngine {
    /// An engine over `dir`, with the device key of a previous run if given.
    #[napi(constructor)]
    pub fn new(o: EngineOptions) -> napi::Result<Self> {
        let vault = Arc::new(match &o.device_key {
            Some(k) => SoftwareVault::with_key(
                k.as_ref()
                    .try_into()
                    .map_err(|_| err("a device key is 32 bytes"))?,
            ),
            None => SoftwareVault::default(),
        });
        let store = Arc::new(DirStore::new(&o.dir).map_err(err)?);
        let config = Config {
            server_url: o.server_url,
            profile_id: o.profile_id,
            device: Device::Headless,
            allow_hqn: o.hqn.unwrap_or(true),
        };
        Ok(Self {
            engine: Engine::new(config, vault.clone(), store).map_err(err)?,
            vault,
        })
    }

    /// The device key, to keep for the next run; null before `createIdentity`.
    #[napi(getter)]
    pub fn device_key(&self) -> Option<Buffer> {
        self.vault.export_key().map(|k| k.to_vec().into())
    }

    #[napi]
    pub fn create_identity(&self) -> napi::Result<Vec<JsEffect>> {
        self.engine.create_identity().map(all).map_err(err)
    }

    /// Brings the bot's identity into a profile that has none: the 32-byte
    /// seed it always derived from, and the TS reference client's state file
    /// (`stateJson`, null when there was none) with its friends' sessions and
    /// its prekey secrets.
    #[napi]
    pub fn import_legacy(
        &self,
        seed: Buffer,
        state_json: Option<String>,
        now: i64,
    ) -> napi::Result<JsImport> {
        let seed: [u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| err("a seed is 32 bytes"))?;
        let (import, unreadable) =
            crate::legacy::import_of(seed, state_json.as_deref()).map_err(err)?;
        Ok(JsImport {
            effects: all(self.engine.import(import, now).map_err(err)?),
            unreadable,
        })
    }

    #[napi]
    pub fn start(&self, now: i64, network: String) -> Vec<JsEffect> {
        all(self.engine.start(now, net(network)))
    }

    #[napi]
    pub fn unlock(&self, now: i64) -> napi::Result<Vec<JsEffect>> {
        self.engine.unlock(now).map(all).map_err(err)
    }

    #[napi]
    pub fn lock(&self) -> Vec<JsEffect> {
        all(self.engine.lock())
    }

    #[napi]
    pub fn tick(&self, now: i64) -> Vec<JsEffect> {
        all(self.engine.tick(now))
    }

    #[napi]
    pub fn send_text(&self, peer: String, text: String, now: i64) -> napi::Result<Vec<JsEffect>> {
        self.engine.send_text(peer, text, now).map(all).map_err(err)
    }

    #[napi]
    pub fn retry(&self, msg_id: String, now: i64) -> Vec<JsEffect> {
        all(self.engine.retry(msg_id, now))
    }

    #[napi]
    pub fn invite(&self, username: String) -> Vec<JsEffect> {
        all(self.engine.invite(username))
    }

    #[napi]
    pub fn accept(&self, peer: String) -> Vec<JsEffect> {
        all(self.engine.accept(peer))
    }

    #[napi]
    pub fn remove(&self, peer: String) -> Vec<JsEffect> {
        all(self.engine.remove(peer))
    }

    #[napi]
    pub fn block(&self, peer: String) -> Vec<JsEffect> {
        all(self.engine.block(peer))
    }

    #[napi]
    pub fn cancel(&self, peer: String) -> Vec<JsEffect> {
        all(self.engine.cancel(peer))
    }

    #[napi]
    pub fn set_verified(&self, peer: String, verified: bool) -> napi::Result<Vec<JsEffect>> {
        self.engine
            .set_verified(peer, verified)
            .map(all)
            .map_err(err)
    }

    #[napi]
    pub fn sent_invites(&self) -> Vec<JsSentInvite> {
        self.engine
            .sent_invites()
            .into_iter()
            .map(|s| JsSentInvite { to: s.to, at: s.at })
            .collect()
    }

    #[napi]
    pub fn unblock(&self, peer: String) -> Vec<JsEffect> {
        all(self.engine.unblock(peer))
    }

    #[napi]
    pub fn forget(&self, peer: String) -> napi::Result<Vec<JsEffect>> {
        self.engine.forget(peer).map(all).map_err(err)
    }

    #[napi]
    pub fn mark_read(&self, peer: String) -> napi::Result<Vec<JsEffect>> {
        self.engine.mark_read(peer).map(all).map_err(err)
    }

    #[napi]
    pub fn report(
        &self,
        peer: String,
        reason: String,
        msg_ids: Vec<String>,
        block: bool,
    ) -> Vec<JsEffect> {
        all(self.engine.report(ReportInput {
            peer,
            reason,
            msg_ids,
            block,
        }))
    }

    #[napi]
    pub fn set_username(&self, username: String) -> Vec<JsEffect> {
        all(self.engine.set_username(username))
    }

    #[napi]
    pub fn delete_account(&self) -> Vec<JsEffect> {
        all(self.engine.delete_account())
    }

    /// Registers an APNs token (the only push the server bridges today).
    #[napi]
    pub fn register_apns(&self, token: String, sandbox: bool) -> Vec<JsEffect> {
        all(self
            .engine
            .register_push(PushToken::Apns { token, sandbox }))
    }

    #[napi]
    pub fn history(
        &self,
        peer: String,
        before: Option<i64>,
        limit: u32,
    ) -> napi::Result<Vec<JsMessage>> {
        Ok(self
            .engine
            .history(peer, before, limit)
            .map_err(err)?
            .into_iter()
            .map(message)
            .collect())
    }

    #[napi]
    pub fn friends(&self) -> Vec<JsFriend> {
        self.engine
            .friends()
            .into_iter()
            .map(|f| JsFriend {
                id: f.id,
                username: f.username,
                online: f.online,
                has_session: f.has_session,
                unread: f.unread,
                blocked_at: f.blocked_at,
                vanished_at: f.vanished_at,
                has_key: f.has_key,
                verified: f.verified,
            })
            .collect()
    }

    #[napi]
    pub fn invites(&self) -> Vec<JsInvite> {
        self.engine
            .invites()
            .into_iter()
            .map(|i| JsInvite {
                id: i.id,
                username: i.username,
            })
            .collect()
    }

    #[napi]
    pub fn fingerprint(&self, peer: String) -> Option<String> {
        self.engine.fingerprint(peer)
    }

    #[napi]
    pub fn on_http(
        &self,
        req: i64,
        status: u32,
        body: Buffer,
        now: i64,
    ) -> napi::Result<Vec<JsEffect>> {
        let status = u16::try_from(status)
            .map_err(|_| napi::Error::from_reason(format!("{status} is not an HTTP status")))?;
        Ok(all(self.engine.on_http(
            from_js(req)?,
            status,
            body.to_vec(),
            now,
        )))
    }

    #[napi]
    pub fn on_opened(&self, conn: i64, now: i64) -> napi::Result<Vec<JsEffect>> {
        Ok(all(self.engine.on_opened(from_js(conn)?, now)))
    }

    #[napi]
    pub fn on_bytes(&self, conn: i64, bytes: Buffer, now: i64) -> napi::Result<Vec<JsEffect>> {
        Ok(all(self.engine.on_bytes(
            from_js(conn)?,
            bytes.to_vec(),
            now,
        )))
    }

    /// `reason`: `requested`, `remote`, or anything else for a failure.
    #[napi]
    pub fn on_closed(&self, conn: i64, reason: String, now: i64) -> napi::Result<Vec<JsEffect>> {
        let reason = match reason.as_str() {
            "requested" => CloseReason::Requested,
            "remote" => CloseReason::Remote,
            other => CloseReason::Failed(other.into()),
        };
        Ok(all(self.engine.on_closed(from_js(conn)?, reason, now)))
    }

    #[napi]
    pub fn on_network_changed(&self, network: String, now: i64) -> Vec<JsEffect> {
        all(self.engine.on_network_changed(net(network), now))
    }
}
