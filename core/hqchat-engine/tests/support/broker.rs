//! The broker side of the fake server: what EMQX and the hqn/1 gateway do
//! for HQChat. CONNECT is authenticated with the real proof against the
//! registered signing keys; the topic policy is infra/emqx/acl.conf's;
//! sessions are persistent (QoS 1 queued while offline), presence is
//! retained, and an abrupt close publishes the will.

use std::collections::HashMap;

use hqchat_protocol::mqtt::{self, Decoder, Packet, QoS, Will};
use hqchat_protocol::noise::{self, FrameReader, HqnResponder, ServerStatic, Transport};
use hqchat_protocol::topics::{self, Route};
use hqchat_protocol::{HqcKem, OsEntropy, PeerId, mqtt_proof};

use super::{FakeServer, NOW};

/// Bytes or a close for one client's connection.
pub enum Out {
    Bytes(Vec<u8>),
    Close,
}

struct Gateway {
    opening: Vec<u8>,
    frames: FrameReader,
    transport: Option<Transport>,
}

struct BConn {
    gateway: Option<Gateway>,
    mqtt: Decoder,
    client: Option<String>,
}

#[derive(Default)]
struct Session {
    subs: Vec<(String, QoS)>,
    queue: Vec<(String, Vec<u8>)>,
    conn: Option<(String, u64)>,
    will: Option<Will>,
}

#[derive(Default)]
pub struct Broker {
    conns: HashMap<(String, u64), BConn>,
    sessions: HashMap<String, Session>,
    retained: HashMap<String, Vec<u8>>,
    pub outbox: Vec<(String, u64, Out)>,
    next_pid: u16,
    /// The gateway's keys, when hqn/1 is enabled.
    pub gateway: Option<ServerStatic>,
    /// Every network refuses raw TCP to the gateway.
    pub block_hqn: bool,
    /// Publishes the broker routed: (topic, payload).
    pub routed: Vec<(String, Vec<u8>)>,
}

impl FakeServer {
    fn friends(&self, a: &str, b: &str) -> bool {
        self.friendships.contains_key(&Self::pair_of(a, b))
    }

    fn member_of(&self, me: &str, topic_id: &str) -> bool {
        self.friends_of(me)
            .iter()
            .any(|(_, f)| f.convo == topic_id || f.handshake == topic_id)
    }

    fn may_subscribe(&self, me: &str, topic: &str) -> bool {
        match topics::route(topic) {
            Some(Route::Inbox(id) | Route::Graph(id)) => id.as_str() == me,
            Some(Route::Presence(id)) => self.friends(me, id.as_str()),
            Some(Route::Conversation(t) | Route::Handshake(t)) => self.member_of(me, t.as_str()),
            None => false,
        }
    }

    fn may_publish(&self, me: &str, topic: &str) -> bool {
        match topics::route(topic) {
            Some(Route::Presence(id)) => id.as_str() == me,
            Some(Route::Inbox(id)) => self.friends(me, id.as_str()),
            Some(Route::Conversation(t) | Route::Handshake(t)) => self.member_of(me, t.as_str()),
            _ => false,
        }
    }

    /// A client's shell opened a connection; false when the network refuses it.
    pub fn mqtt_open(&mut self, profile: &str, conn: u64, tcp: bool) -> bool {
        if tcp && (self.broker.block_hqn || self.broker.gateway.is_none()) {
            return false;
        }
        let gateway = tcp.then(|| Gateway {
            opening: Vec::new(),
            frames: FrameReader::default(),
            transport: None,
        });
        self.broker.conns.insert(
            (profile.into(), conn),
            BConn {
                gateway,
                mqtt: Decoder::default(),
                client: None,
            },
        );
        true
    }

    pub fn mqtt_bytes(&mut self, profile: &str, conn: u64, bytes: &[u8]) {
        let key = (profile.to_owned(), conn);
        let mut plain = Vec::new();
        let mut to_send = Vec::new();
        let mut broken = false;
        {
            let gateway_keys = self.broker.gateway.clone();
            let Some(c) = self.broker.conns.get_mut(&key) else {
                return;
            };
            match &mut c.gateway {
                None => plain.extend_from_slice(bytes),
                Some(g) => {
                    let mut rest = bytes;
                    if g.opening.len() < 2 {
                        let take = (2 - g.opening.len()).min(rest.len());
                        g.opening.extend_from_slice(&rest[..take]);
                        rest = &rest[take..];
                    }
                    g.frames.push(rest);
                    while let Some(frame) = g.frames.next_frame() {
                        match &mut g.transport {
                            None => {
                                let keys = gateway_keys.clone().unwrap();
                                if g.opening != [noise::HQN_VERSION, keys.key_id] {
                                    broken = true;
                                    break;
                                }
                                let mut responder = HqnResponder::new(keys);
                                let Ok(connect) = responder.read_message1(&HqcKem, &frame) else {
                                    broken = true;
                                    break;
                                };
                                let (msg2, transport) =
                                    responder.write_message2(&[], &mut OsEntropy).unwrap();
                                to_send.push(noise::frame(&msg2).unwrap());
                                g.transport = Some(transport);
                                plain.extend_from_slice(&connect);
                            }
                            Some(t) => match t.recv.decrypt(&frame) {
                                Ok(p) => plain.extend_from_slice(&p),
                                Err(_) => {
                                    broken = true;
                                    break;
                                }
                            },
                        }
                    }
                }
            }
            c.mqtt.push(&plain);
        }
        for raw in to_send {
            self.broker
                .outbox
                .push((key.0.clone(), conn, Out::Bytes(raw)));
        }
        if broken {
            return self.mqtt_kill(&key, true);
        }
        loop {
            let next = self
                .broker
                .conns
                .get_mut(&key)
                .map(|c| c.mqtt.next_packet());
            match next {
                Some(Ok(Some(p))) => self.on_packet(&key, p),
                Some(Ok(None)) | None => break,
                Some(Err(_)) => return self.mqtt_kill(&key, true),
            }
        }
    }

    /// The client closed its connection (or its shell did).
    pub fn mqtt_closed(&mut self, profile: &str, conn: u64) {
        self.mqtt_kill(&(profile.to_owned(), conn), false);
    }

    /// Ends a connection; the broker tells the client when it is the one closing.
    fn mqtt_kill(&mut self, key: &(String, u64), tell: bool) {
        let Some(c) = self.broker.conns.remove(key) else {
            return;
        };
        if tell {
            self.broker.outbox.push((key.0.clone(), key.1, Out::Close));
        }
        if let Some(id) = c.client
            && let Some(s) = self.broker.sessions.get_mut(&id)
            && s.conn.as_ref() == Some(key)
        {
            s.conn = None;
            if let Some(w) = s.will.take() {
                self.route(&w.topic, w.payload, w.retain);
            }
        }
    }

    fn send(&mut self, key: &(String, u64), packet: &Packet) {
        let mut bytes = mqtt::encode(packet).unwrap();
        if let Some(c) = self.broker.conns.get_mut(key)
            && let Some(Gateway {
                transport: Some(t), ..
            }) = &mut c.gateway
        {
            bytes = noise::seal_frames(&mut t.send, &bytes).unwrap();
        }
        self.broker
            .outbox
            .push((key.0.clone(), key.1, Out::Bytes(bytes)));
    }

    fn authorized(
        &self,
        client_id: &str,
        username: &Option<String>,
        password: &Option<Vec<u8>>,
    ) -> bool {
        if username.as_deref() != Some(client_id) {
            return false;
        }
        let Some(proof) = password
            .as_deref()
            .and_then(|p| std::str::from_utf8(p).ok())
            .and_then(mqtt_proof::parse_password)
        else {
            return false;
        };
        let (Some(user), Ok(id)) = (self.users.get(client_id), PeerId::parse(client_id)) else {
            return false;
        };
        let Some((_, key)) = user.signing_keys.iter().find(|(k, _)| *k == proof.key_id) else {
            return false;
        };
        let server_now = NOW / 1000 + self.skew_sec;
        mqtt_proof::is_fresh_timestamp(proof.ts, server_now)
            && mqtt_proof::verify_signature(
                key,
                &mqtt_proof::proof_message(&id, &proof.key_id, proof.ts, &proof.nonce),
                &proof.signature,
            )
    }

    fn on_packet(&mut self, key: &(String, u64), packet: Packet) {
        let client = self.broker.conns.get(key).and_then(|c| c.client.clone());
        match (packet, client) {
            (
                Packet::Connect {
                    client_id,
                    username,
                    password,
                    will,
                    ..
                },
                None,
            ) => {
                if !self.authorized(&client_id, &username, &password) {
                    self.send(
                        key,
                        &Packet::Connack {
                            session_present: false,
                            code: 5,
                        },
                    );
                    return self.mqtt_kill(key, true);
                }
                // A second connection for the same id takes the session over.
                let previous = self
                    .broker
                    .sessions
                    .get(&client_id)
                    .and_then(|s| s.conn.clone());
                if let Some(old) = previous.filter(|old| old != key) {
                    self.broker.conns.remove(&old);
                    self.broker.outbox.push((old.0, old.1, Out::Close));
                }
                self.broker.conns.get_mut(key).unwrap().client = Some(client_id.clone());
                let present = self.broker.sessions.contains_key(&client_id);
                let session = self.broker.sessions.entry(client_id.clone()).or_default();
                session.conn = Some(key.clone());
                session.will = will;
                let queued = std::mem::take(&mut session.queue);
                self.send(
                    key,
                    &Packet::Connack {
                        session_present: present,
                        code: 0,
                    },
                );
                for (topic, payload) in queued {
                    self.deliver_to(key, &topic, payload, QoS::AtLeastOnce);
                }
            }
            (
                Packet::Publish {
                    topic,
                    payload,
                    retain,
                    packet_id,
                    ..
                },
                Some(me),
            ) => {
                if self.may_publish(&me, &topic) {
                    self.route(&topic, payload, retain);
                }
                if let Some(packet_id) = packet_id {
                    self.send(key, &Packet::Puback { packet_id });
                }
            }
            (Packet::Subscribe { packet_id, filters }, Some(me)) => {
                let mut codes = Vec::new();
                let mut granted = Vec::new();
                for (filter, qos) in filters {
                    if self.may_subscribe(&me, &filter) {
                        codes.push(if qos == QoS::AtLeastOnce { 1 } else { 0 });
                        granted.push((filter, qos));
                    } else {
                        codes.push(0x80);
                    }
                }
                let session = self.broker.sessions.get_mut(&me).unwrap();
                for (filter, qos) in &granted {
                    session.subs.retain(|(f, _)| f != filter);
                    session.subs.push((filter.clone(), *qos));
                }
                self.send(key, &Packet::Suback { packet_id, codes });
                for (filter, qos) in granted {
                    if let Some(payload) = self.broker.retained.get(&filter).cloned() {
                        self.deliver_to(key, &filter, payload, qos);
                    }
                }
            }
            (Packet::Unsubscribe { packet_id, filters }, Some(me)) => {
                self.broker
                    .sessions
                    .get_mut(&me)
                    .unwrap()
                    .subs
                    .retain(|(f, _)| !filters.contains(f));
                self.send(key, &Packet::Unsuback { packet_id });
            }
            (Packet::Pingreq, Some(_)) => self.send(key, &Packet::Pingresp),
            (Packet::Disconnect, Some(me)) => {
                if let Some(s) = self.broker.sessions.get_mut(&me) {
                    s.will = None;
                }
                self.mqtt_kill(key, false);
            }
            (Packet::Puback { .. }, Some(_)) => {}
            _ => self.mqtt_kill(key, true),
        }
    }

    fn deliver_to(&mut self, key: &(String, u64), topic: &str, payload: Vec<u8>, qos: QoS) {
        let packet_id = (qos == QoS::AtLeastOnce).then(|| {
            self.broker.next_pid = self.broker.next_pid.wrapping_add(1).max(1);
            self.broker.next_pid
        });
        self.send(
            key,
            &Packet::Publish {
                topic: topic.into(),
                payload,
                qos,
                retain: false,
                packet_id,
                dup: false,
            },
        );
    }

    /// Publishes on behalf of the server (graph nudges) or a client.
    pub fn route(&mut self, topic: &str, payload: Vec<u8>, retain: bool) {
        self.broker.routed.push((topic.to_owned(), payload.clone()));
        if retain {
            self.broker
                .retained
                .insert(topic.to_owned(), payload.clone());
        }
        let targets: Vec<(String, QoS)> = self
            .broker
            .sessions
            .iter()
            .filter_map(|(id, s)| {
                s.subs
                    .iter()
                    .find(|(f, _)| f == topic)
                    .map(|(_, q)| (id.clone(), *q))
            })
            .collect();
        for (id, qos) in targets {
            let conn = self.broker.sessions[&id].conn.clone();
            match conn {
                Some(key) => self.deliver_to(&key, topic, payload.clone(), qos),
                None if qos == QoS::AtLeastOnce => {
                    self.broker
                        .sessions
                        .get_mut(&id)
                        .unwrap()
                        .queue
                        .push((topic.to_owned(), payload.clone()));
                }
                None => {}
            }
        }
    }

    /// Nudges both users of a friendship change, as the server does.
    pub fn nudge(&mut self, a: &str, b: &str) {
        for id in [a, b] {
            if let Ok(id) = PeerId::parse(id) {
                self.route(&topics::graph_topic(&id), b"{}".to_vec(), false);
            }
        }
    }
}
