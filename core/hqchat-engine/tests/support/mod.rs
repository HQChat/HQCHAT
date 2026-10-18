//! A fake home server for the engine's tests: the REST endpoints with the
//! real protocol behind them (HQC challenge, proof check, signing-key
//! registration), and `pump`, which plays the shell.

#![allow(dead_code)]

pub mod broker;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hqchat_engine::software::{MemoryStore, SoftwareVault};
use hqchat_engine::{Config, Device, Effect, Engine, Method};
use hqchat_protocol::{PeerId, auth_proof};
use serde_json::{Value, json};
use sha2::Digest as _;

pub const NOW: i64 = 1_790_000_000_000;

pub fn config(profile: &str) -> Config {
    Config {
        server_url: "https://hqchat.test".into(),
        profile_id: profile.into(),
        device: Device::Headless,
    }
}

#[derive(Default)]
pub struct User {
    pub pk_hex: String,
    pub username: Option<String>,
    pub signing_keys: Vec<(String, [u8; 32])>,
    pub push: Option<Value>,
    pub medium: Option<String>,
    pub one_time: Vec<(u64, String)>,
    pub blocked: Vec<String>,
}

/// A friendship's two topic ids.
#[derive(Clone)]
pub struct Friendship {
    pub convo: String,
    pub handshake: String,
}

/// The server's state. Shared by every client in a test.
#[derive(Default)]
pub struct FakeServer {
    pub users: HashMap<String, User>,
    challenges: HashMap<String, [u8; 32]>,
    tokens: HashMap<String, String>,
    next: u64,
    /// Seconds the server clock is ahead of the clients'.
    pub skew_sec: i64,
    /// Every request, for assertions: (method, path).
    pub log: Vec<(Method, String)>,
    /// Refuse `/auth/refresh` as if the session lapsed.
    pub expire_sessions: bool,
    /// (from, to) invites waiting for an answer.
    pub invites: Vec<(String, String)>,
    /// Friendships by the sorted pair of ids.
    pub friendships: HashMap<(String, String), Friendship>,
    pub reports: Vec<Value>,
    pub broker: broker::Broker,
}

type Reply = (u16, Value);

fn err(status: u16, code: &str) -> Reply {
    (status, json!({ "error": code }))
}

impl FakeServer {
    pub fn shared() -> Rc<RefCell<FakeServer>> {
        Rc::new(RefCell::new(FakeServer::default()))
    }

    fn mint(&mut self) -> String {
        self.next += 1;
        format!("{:032x}", self.next)
    }

    fn topic_id(&mut self) -> String {
        self.next += 1;
        hex::encode(sha2::Sha256::digest(self.next.to_be_bytes()))
    }

    pub fn pair_of(a: &str, b: &str) -> (String, String) {
        Self::pair(a, b)
    }

    /// Turns the hqn/1 gateway on, with fresh keys, and advertises it.
    pub fn enable_hqn(&mut self) {
        use hqchat_protocol::noise::{ServerStatic, X25519Secret};
        self.broker.gateway = Some(ServerStatic {
            key_id: 1,
            x25519: X25519Secret::generate(&mut hqchat_protocol::OsEntropy).unwrap(),
            hqc: hqc::generate_keypair().unwrap(),
        });
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        if a < b {
            (a.into(), b.into())
        } else {
            (b.into(), a.into())
        }
    }

    pub fn friends_of(&self, id: &str) -> Vec<(String, Friendship)> {
        self.friendships
            .iter()
            .filter_map(|((a, b), f)| {
                if a == id {
                    Some((b.clone(), f.clone()))
                } else if b == id {
                    Some((a.clone(), f.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    fn resolve(&self, to: &str) -> Option<String> {
        if self.users.contains_key(to) {
            return Some(to.to_owned());
        }
        self.users
            .iter()
            .find(|(_, u)| u.username.as_deref() == Some(to))
            .map(|(id, _)| id.clone())
    }

    fn session(&self, authorization: &Option<String>) -> Option<String> {
        self.tokens.get(authorization.as_ref()?).cloned()
    }

    fn grant(&mut self, id: &str, body: &Value) -> Value {
        let key: [u8; 32] = STANDARD
            .decode(body["mqttSigningKey"].as_str().unwrap_or(""))
            .unwrap()
            .try_into()
            .unwrap();
        let key_id = self.mint();
        self.users
            .get_mut(id)
            .unwrap()
            .signing_keys
            .push((key_id.clone(), key));
        let server_now = NOW / 1000 + self.skew_sec;
        json!({ "serverTime": server_now, "mqttKeyId": key_id, "mqttKeyExpiresAt": server_now + 12 * 3600 })
    }

    pub fn http(
        &mut self,
        method: Method,
        path: &str,
        authorization: &Option<String>,
        body: &[u8],
    ) -> Reply {
        self.log.push((method, path.to_owned()));
        let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        match (method, path) {
            (Method::Post, "/auth/init") => {
                let pk_hex = body["pk"].as_str().unwrap_or("").to_owned();
                let Ok(pk) = hqc::PublicKey::from_bytes(&hex::decode(&pk_hex).unwrap_or_default())
                else {
                    return err(400, "bad public key");
                };
                let (ct, ss) = hqc::encapsulate(&pk).unwrap();
                self.challenges.insert(
                    PeerId::of_hex(&pk_hex).to_string(),
                    auth_proof::auth_proof(&ss),
                );
                (200, json!({ "ct": STANDARD.encode(ct.as_bytes()) }))
            }
            (Method::Post, "/auth/verify") => {
                let pk_hex = body["pk"].as_str().unwrap_or("").to_owned();
                let id = PeerId::of_hex(&pk_hex).to_string();
                let solution = STANDARD
                    .decode(body["solution"].as_str().unwrap_or(""))
                    .unwrap_or_default();
                match self.challenges.remove(&id) {
                    Some(expected) if auth_proof::proof_matches(&expected, &solution) => {}
                    _ => return err(401, "auth failed"),
                }
                self.users.entry(id.clone()).or_insert_with(|| User {
                    pk_hex,
                    ..Default::default()
                });
                let token = self.mint();
                self.tokens.insert(token.clone(), id.clone());
                let mut grant = self.grant(&id, &body);
                grant["id"] = json!(id);
                grant["sessionToken"] = json!(token);
                (200, grant)
            }
            (Method::Post, "/auth/refresh") => match self.session(authorization) {
                Some(id) if !self.expire_sessions => (200, self.grant(&id, &body)),
                _ => err(401, "session expired"),
            },
            (Method::Post, "/username") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let name = body["username"].as_str().unwrap_or("").to_owned();
                if self
                    .users
                    .values()
                    .any(|u| u.username.as_deref() == Some(&name))
                {
                    return err(409, "USERNAME_TAKEN");
                }
                self.users.get_mut(&id).unwrap().username = Some(name);
                (200, json!({ "ok": true }))
            }
            (Method::Post, "/push/token") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                self.users.get_mut(&id).unwrap().push = Some(body);
                (200, json!({ "ok": true }))
            }
            (Method::Post, "/account/delete") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                self.users.remove(&id);
                self.tokens.retain(|_, v| *v != id);
                (200, json!({ "ok": true }))
            }
            (Method::Get, "/auth/transport") => match &self.broker.gateway {
                Some(g) => {
                    let p = g.public();
                    (
                        200,
                        json!({ "hqn": { "enabled": true, "host": "gw.hqchat.test", "port": 443, "keys": [{
                        "keyId": p.key_id, "x25519": STANDARD.encode(p.x25519), "hqc": STANDARD.encode(p.hqc.as_bytes())
                    }] } }),
                    )
                }
                None => (200, json!({ "hqn": null })),
            },
            (Method::Get, "/friends") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let friends: Vec<Value> = self
                    .friends_of(&id)
                    .into_iter()
                    .map(|(peer, f)| {
                        let username = self.users.get(&peer).and_then(|u| u.username.clone()).unwrap_or_default();
                        json!({ "id": peer, "username": username, "convo_id": f.convo, "handshake_id": f.handshake })
                    })
                    .collect();
                (200, json!({ "friends": friends }))
            }
            (Method::Get, "/friends/invites") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let invites: Vec<Value> = self
                    .invites
                    .iter()
                    .filter(|(_, to)| *to == id)
                    .map(|(from, _)| {
                        let username = self
                            .users
                            .get(from)
                            .and_then(|u| u.username.clone())
                            .unwrap_or_default();
                        json!({ "id": from, "username": username })
                    })
                    .collect();
                (200, json!({ "invites": invites }))
            }
            (Method::Post, "/friends/invite") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let Some(to) = self.resolve(body["to"].as_str().unwrap_or("")) else {
                    return err(404, "USER_NOT_FOUND");
                };
                self.invites.push((id, to));
                (200, json!({ "ok": true }))
            }
            (Method::Post, "/friends/accept") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let from = body["from"].as_str().unwrap_or("").to_owned();
                let Some(i) = self
                    .invites
                    .iter()
                    .position(|(f, t)| *f == from && *t == id)
                else {
                    return err(404, "NO_INVITE");
                };
                self.invites.remove(i);
                let f = Friendship {
                    convo: self.topic_id(),
                    handshake: self.topic_id(),
                };
                self.friendships.insert(Self::pair(&id, &from), f);
                self.nudge(&id, &from);
                (200, json!({ "ok": true }))
            }
            (Method::Post, "/friends/remove") | (Method::Post, "/friends/block") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let peer = body["peer"].as_str().unwrap_or("").to_owned();
                self.friendships.remove(&Self::pair(&id, &peer));
                self.nudge(&id, &peer);
                if path.ends_with("block") {
                    self.users.get_mut(&id).unwrap().blocked.push(peer);
                }
                (200, json!({ "ok": true }))
            }
            (Method::Post, "/report") => {
                if self.session(authorization).is_none() {
                    return err(401, "");
                }
                self.reports.push(body);
                (200, json!({ "id": "r1" }))
            }
            (Method::Post, "/prekeys") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let user = self.users.get_mut(&id).unwrap();
                user.medium = body["medium"].as_str().map(str::to_owned);
                for k in body["oneTime"].as_array().cloned().unwrap_or_default() {
                    user.one_time.push((
                        k["id"].as_u64().unwrap(),
                        k["prekey"].as_str().unwrap().to_owned(),
                    ));
                }
                (200, json!({ "ok": true }))
            }
            (Method::Get, "/prekeys/count") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                (200, json!({ "remaining": self.users[&id].one_time.len() }))
            }
            (Method::Post, "/prekeys/claim") => {
                let Some(id) = self.session(authorization) else {
                    return err(401, "");
                };
                let peer = body["peer"].as_str().unwrap_or("").to_owned();
                if !self.friendships.contains_key(&Self::pair(&id, &peer)) {
                    return err(403, "NOT_FRIENDS");
                }
                let Some(user) = self.users.get_mut(&peer) else {
                    return err(404, "NO_PREKEYS");
                };
                let Some(medium) = user.medium.clone() else {
                    return err(404, "NO_PREKEYS");
                };
                let one_time = if user.one_time.is_empty() {
                    Value::Null
                } else {
                    let (id, prekey) = user.one_time.remove(0);
                    json!({ "id": id, "prekey": prekey })
                };
                (200, json!({ "medium": medium, "oneTime": one_time }))
            }
            (Method::Get, p) if p.starts_with("/peer/") && p.ends_with("/key") => {
                let id = &p["/peer/".len()..p.len() - "/key".len()];
                match self.users.get(id) {
                    Some(u) => (200, json!({ "publicKey": u.pk_hex })),
                    None => err(404, "NOT_FOUND"),
                }
            }
            _ => err(404, "NOT_FOUND"),
        }
    }
}

/// One client: an engine with its own vault and store.
pub struct Client {
    pub engine: Engine,
    pub vault: Arc<SoftwareVault>,
    pub store: Arc<MemoryStore>,
    pub server: Rc<RefCell<FakeServer>>,
    pub profile: String,
    /// Every effect that reached the "UI", in order.
    pub seen: Vec<Effect>,
    pub engine_id: String,
    /// The device clock this client's shell reports.
    pub now: i64,
}

impl Client {
    pub fn new(server: &Rc<RefCell<FakeServer>>, profile: &str) -> Client {
        let vault = Arc::new(SoftwareVault::default());
        let store = Arc::new(MemoryStore::default());
        let engine = Engine::new(config(profile), vault.clone(), store.clone()).unwrap();
        Client {
            engine,
            vault,
            store,
            server: server.clone(),
            profile: profile.into(),
            seen: Vec::new(),
            engine_id: String::new(),
            now: NOW,
        }
    }

    /// A client with an identity, started and signed in.
    pub fn signed_in(server: &Rc<RefCell<FakeServer>>, profile: &str) -> Client {
        let mut c = Client::new(server, profile);
        let e = c.engine.create_identity().unwrap();
        c.pump(e);
        let before: Vec<String> = server.borrow().users.keys().cloned().collect();
        c.start(NOW);
        c.engine_id = server
            .borrow()
            .users
            .keys()
            .find(|k| !before.contains(k))
            .cloned()
            .unwrap_or_default();
        c
    }

    /// `start` at `now`, as a shell does on launch and on every resume.
    pub fn start(&mut self, now: i64) {
        self.now = now;
        let e = self.engine.start(
            now,
            hqchat_engine::NetworkInfo {
                key: "test".into(),
                expensive: false,
            },
        );
        self.pump(e);
    }

    /// A timer fired at `now`.
    pub fn tick(&mut self, now: i64) {
        self.now = now;
        let e = self.engine.tick(now);
        self.pump(e);
    }

    /// Makes `a` and `b` friends through the API, as two users would.
    pub fn befriend(a: &mut Client, b: &mut Client) {
        let e = a.engine.invite(b.id());
        a.pump(e);
        b.start(b.now);
        let e = b.engine.accept(a.id());
        b.pump(e);
        a.start(a.now);
        settle(&mut [a, b]);
    }

    fn has_delivery(&self) -> bool {
        self.server
            .borrow()
            .broker
            .outbox
            .iter()
            .any(|(p, _, _)| *p == self.profile)
    }

    /// Plays the shell: carries out every effect, answers requests, moves
    /// bytes to and from the broker, until nothing is left for this client.
    pub fn pump(&mut self, effects: Vec<Effect>) {
        let mut queue: std::collections::VecDeque<Effect> = effects.into();
        loop {
            while let Some(effect) = queue.pop_front() {
                let now = self.now;
                match effect {
                    Effect::Http {
                        req,
                        method,
                        path,
                        authorization,
                        body,
                    } => {
                        let (status, reply) =
                            self.server
                                .borrow_mut()
                                .http(method, &path, &authorization, &body);
                        queue.extend(self.engine.on_http(
                            req,
                            status,
                            reply.to_string().into_bytes(),
                            now,
                        ));
                    }
                    Effect::Open { conn, endpoint } => {
                        let tcp = matches!(endpoint, hqchat_engine::Endpoint::Tcp { .. });
                        self.seen.push(Effect::Open { conn, endpoint });
                        if self.server.borrow_mut().mqtt_open(&self.profile, conn, tcp) {
                            queue.extend(self.engine.on_opened(conn, now));
                        } else {
                            let reason = hqchat_engine::CloseReason::Failed("refused".into());
                            queue.extend(self.engine.on_closed(conn, reason, now));
                        }
                    }
                    Effect::Write { conn, bytes } => {
                        self.server
                            .borrow_mut()
                            .mqtt_bytes(&self.profile, conn, &bytes);
                    }
                    Effect::Close { conn } => {
                        self.server.borrow_mut().mqtt_closed(&self.profile, conn);
                    }
                    other => self.seen.push(other),
                }
            }
            let deliveries: Vec<(u64, broker::Out)> = {
                let mut s = self.server.borrow_mut();
                let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut s.broker.outbox)
                    .into_iter()
                    .partition(|(p, _, _)| *p == self.profile);
                s.broker.outbox = rest;
                mine.into_iter().map(|(_, c, o)| (c, o)).collect()
            };
            if deliveries.is_empty() {
                break;
            }
            for (conn, out) in deliveries {
                let now = self.now;
                match out {
                    broker::Out::Bytes(b) => queue.extend(self.engine.on_bytes(conn, b, now)),
                    broker::Out::Close => {
                        let reason = hqchat_engine::CloseReason::Remote;
                        queue.extend(self.engine.on_closed(conn, reason, now));
                    }
                }
            }
        }
    }

    /// This client's id, as the server registered it.
    pub fn id(&self) -> String {
        self.engine_id.clone()
    }
}

/// Pumps every client until the broker has nothing left for any of them.
pub fn settle(clients: &mut [&mut Client]) {
    loop {
        let mut moved = false;
        for c in clients.iter_mut() {
            if c.has_delivery() {
                c.pump(Vec::new());
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
}
