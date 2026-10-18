//! A fake home server for the engine's tests: the REST endpoints with the
//! real protocol behind them (HQC challenge, proof check, signing-key
//! registration), and `pump`, which plays the shell.

#![allow(dead_code)]

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
    /// Every effect that reached the "UI", in order.
    pub seen: Vec<Effect>,
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
            seen: Vec::new(),
        }
    }

    /// A client with an identity, started and signed in.
    pub fn signed_in(server: &Rc<RefCell<FakeServer>>, profile: &str) -> Client {
        let mut c = Client::new(server, profile);
        let e = c.engine.create_identity(NOW).unwrap();
        c.pump(e);
        let e = c.engine.start(
            NOW,
            hqchat_engine::NetworkInfo {
                key: "test".into(),
                expensive: false,
            },
        );
        c.pump(e);
        c
    }

    /// Plays the shell: answers every request until none is left; keeps the rest.
    pub fn pump(&mut self, effects: Vec<Effect>) {
        let mut queue: std::collections::VecDeque<Effect> = effects.into();
        while let Some(effect) = queue.pop_front() {
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
                        NOW,
                    ));
                }
                other => self.seen.push(other),
            }
        }
    }

    pub fn id(&self) -> String {
        let server = self.server.borrow();
        server
            .users
            .keys()
            .find(|_| true)
            .cloned()
            .unwrap_or_default()
    }
}
