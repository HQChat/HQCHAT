//! The broker connection: one MQTT 3.1.1 session with a persistent session
//! (the broker's queue is the offline inbox), over hqn/1 when the server
//! advertises a gateway and this network has not been seen to block it,
//! else over WSS. The shell only moves bytes: the engine runs Noise and MQTT.
//!
//! Subscriptions follow MQTTService.swift: the client's own inbox and graph
//! nudge, and per friend the conversation and handshake topics (QoS 1) and
//! their presence (QoS 0). Presence is published retained, with a last will
//! saying offline. Keep-alive 60 s, a directory poll every 60 s while up,
//! reconnect with backoff (2 s doubling to 30 s), and a failed hqn/1 attempt
//! falls back to WSS at once and is not retried on that network.

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hqchat_protocol::mqtt::{self, Decoder, Packet, QoS, Will};
use hqchat_protocol::noise::{self, FrameReader, HqnInitiator, ServerStaticPublic, Transport};
use hqchat_protocol::topics::{self, Route};
use hqchat_protocol::{OsEntropy, PeerId};
use serde_json::Value;

use crate::core::Core;
use crate::effect::{CloseReason, ConnState, Effect, Endpoint, Method};
use crate::http::{Answer, Pending};

pub(crate) const KEEP_ALIVE_SECS: u16 = 60;
/// [`KEEP_ALIVE_SECS`] in milliseconds; a test keeps the two equal.
const KEEP_ALIVE_MS: i64 = 60_000;
const CONNACK_TIMEOUT_MS: i64 = 15_000;
/// No byte for this long on a live connection means it is dead.
const READ_TIMEOUT_MS: i64 = 2 * KEEP_ALIVE_MS;
const BACKOFF_START_MS: i64 = 2_000;
const BACKOFF_MAX_MS: i64 = 30_000;
pub(crate) const DIRECTORY_POLL_MS: i64 = 60_000;
/// QoS 1 publishes awaiting a PUBACK at once. Past it, messages wait in the
/// outbox for the next PUBACK, so a broker that stops acknowledging (or a
/// flood of challenges to answer) cannot exhaust the 16-bit packet ids.
const MAX_IN_FLIGHT: usize = 128;

/// What a QoS 1 publish of ours stands for, settled by its PUBACK.
#[derive(Debug, Clone)]
pub(crate) enum InFlight {
    /// A message frame (or receipt) for `peer`.
    Message {
        peer: PeerId,
        msg_id: String,
    },
    Other,
}

/// The gateway, as `/auth/transport` advertises it.
#[derive(Debug, Clone)]
pub(crate) struct HqnInfo {
    host: String,
    port: u16,
    server: ServerStaticPublic,
}

enum Noise {
    /// Over WSS: no Noise layer.
    None,
    /// msg1 sent, waiting for msg2.
    Waiting(Box<HqnInitiator>),
    Open(Box<Transport>),
}

pub(crate) struct Conn {
    pub id: u64,
    hqn: bool,
    noise: Noise,
    frames: FrameReader,
    mqtt: Decoder,
    opened: bool,
    pub up: bool,
    opened_at: i64,
    last_write: i64,
    last_read: i64,
    next_packet_id: u16,
    pub inflight: HashMap<u16, InFlight>,
}

#[derive(Default)]
pub(crate) struct Net {
    pub conn: Option<Conn>,
    next_conn: u64,
    hqn: Option<HqnInfo>,
    transport_fetched: bool,
    hqn_failed: HashSet<String>,
    backoff_ms: i64,
    retry_at: Option<i64>,
    next_poll: Option<i64>,
    scheduled: Option<i64>,
    /// The app went to the background: presence says offline, so the push
    /// bridge wakes this device for what arrives.
    away: bool,
}

fn presence_payload(online: bool) -> Vec<u8> {
    serde_json::json!({ "s": if online { "online" } else { "offline" } })
        .to_string()
        .into_bytes()
}

fn wss_url(server_url: &str) -> String {
    let base = server_url.trim_end_matches('/');
    let base = base.strip_prefix("https://").map_or_else(
        || base.replacen("http://", "ws://", 1),
        |r| format!("wss://{r}"),
    );
    format!("{base}/mqtt")
}

impl Core {
    pub fn network_key(&self) -> String {
        self.network
            .as_ref()
            .map(|n| n.key.clone())
            .unwrap_or_default()
    }

    /// Connects when started, signed in and not connected yet.
    pub fn connect(&mut self, now: i64) {
        if !self.started || self.net.conn.is_some() || self.me.is_none() {
            return;
        }
        if !self.auth.fresh(now) {
            return self.ensure_signed_in(now);
        }
        if !self.net.transport_fetched {
            self.net.transport_fetched = true;
            return self.request(
                Method::Get,
                "/auth/transport",
                None,
                false,
                Pending::Transport,
            );
        }
        self.open(now);
    }

    pub fn on_transport(&mut self, a: Answer, now: i64) {
        self.net.hqn = parse_hqn(&a);
        self.open(now);
    }

    fn open(&mut self, now: i64) {
        if self.net.conn.is_some() {
            return;
        }
        self.net.retry_at = None;
        self.net.next_conn = self.net.next_conn.wrapping_add(1);
        let id = self.net.next_conn;
        let use_hqn = self.config.allow_hqn
            && self.net.hqn.is_some()
            && !self.net.hqn_failed.contains(&self.network_key());
        let endpoint = match (&self.net.hqn, use_hqn) {
            (Some(h), true) => Endpoint::Tcp {
                host: h.host.clone(),
                port: h.port,
            },
            _ => Endpoint::Wss {
                url: wss_url(&self.config.server_url),
            },
        };
        self.net.conn = Some(Conn {
            id,
            hqn: use_hqn,
            noise: Noise::None,
            frames: FrameReader::default(),
            mqtt: Decoder::default(),
            opened: false,
            up: false,
            opened_at: now,
            last_write: now,
            last_read: now,
            next_packet_id: 0,
            inflight: HashMap::new(),
        });
        self.emit(Effect::Connection(ConnState::Connecting));
        self.emit(Effect::Open { conn: id, endpoint });
        self.schedule(now);
    }

    fn current(&mut self, conn: u64) -> Option<&mut Conn> {
        self.net.conn.as_mut().filter(|c| c.id == conn)
    }

    /// The connection is up: send the CONNECT (inside msg1 over hqn/1).
    pub fn on_opened(&mut self, conn: u64, now: i64) {
        let Some(password) = self.connect_password(now) else {
            return self.drop_conn(conn, now, true);
        };
        let Some(me) = self.me.clone() else {
            return self.drop_conn(conn, now, false);
        };
        let connect = Packet::Connect {
            client_id: me.to_string(),
            username: Some(me.to_string()),
            password: Some(password.into_bytes()),
            keep_alive: KEEP_ALIVE_SECS,
            clean_session: false,
            will: Some(Will {
                topic: topics::presence_topic(&me),
                payload: presence_payload(false),
                qos: QoS::AtLeastOnce,
                retain: true,
            }),
        };
        let Ok(connect) = mqtt::encode(&connect) else {
            return;
        };
        let server = self.net.hqn.as_ref().map(|h| h.server.clone());
        let kem = self.kem;
        let Some(c) = self.current(conn) else { return };
        c.opened = true;
        c.last_write = now;
        let bytes = if c.hqn {
            let Some(server) = server else { return };
            let Ok(mut initiator) = HqnInitiator::new(server, &mut OsEntropy) else {
                return;
            };
            let Ok(msg1) = initiator.write_message1(&kem, &connect) else {
                return;
            };
            let Ok(framed) = noise::frame(&msg1) else {
                return;
            };
            let mut out = initiator.opening().to_vec();
            out.extend_from_slice(&framed);
            c.noise = Noise::Waiting(Box::new(initiator));
            out
        } else {
            connect
        };
        self.emit(Effect::Write { conn, bytes });
    }

    pub fn on_bytes(&mut self, conn: u64, bytes: &[u8], now: i64) {
        let mut packets = Vec::new();
        let mut broken = false;
        {
            let Some(c) = self.current(conn) else { return };
            c.last_read = now;
            if c.hqn {
                c.frames.push(bytes);
                while let Some(frame) = c.frames.next_frame() {
                    match std::mem::replace(&mut c.noise, Noise::None) {
                        Noise::Waiting(initiator) => match initiator.read_message2(&frame) {
                            Ok((_, transport)) => c.noise = Noise::Open(Box::new(transport)),
                            Err(_) => broken = true,
                        },
                        Noise::Open(mut transport) => {
                            match transport.recv.decrypt(&frame) {
                                Ok(plain) => c.mqtt.push(&plain),
                                Err(_) => broken = true,
                            }
                            c.noise = Noise::Open(transport);
                        }
                        Noise::None => broken = true,
                    }
                    if broken {
                        break;
                    }
                }
            } else {
                c.mqtt.push(bytes);
            }
            while !broken {
                match c.mqtt.next_packet() {
                    Ok(Some(p)) => packets.push(p),
                    Ok(None) => break,
                    Err(_) => broken = true,
                }
            }
        }
        for p in packets {
            self.on_packet(conn, p, now);
        }
        if broken {
            self.emit(Effect::Dropped {
                reason: "the broker stream is malformed".into(),
            });
            self.drop_conn(conn, now, true);
        }
        self.schedule(now);
    }

    fn on_packet(&mut self, conn: u64, packet: Packet, now: i64) {
        match packet {
            Packet::Connack { code: 0, .. } => self.on_connected(conn, now),
            Packet::Connack { code, .. } => {
                if code == 4 || code == 5 {
                    // Refused credentials: the next attempt gets fresh ones.
                    self.auth.key_expires_at = 0;
                }
                self.emit(Effect::Dropped {
                    reason: format!("the broker refused the connection ({code})"),
                });
                self.drop_conn(conn, now, true);
            }
            Packet::Publish {
                topic,
                payload,
                qos,
                packet_id,
                ..
            } => {
                if let (QoS::AtLeastOnce, Some(packet_id)) = (qos, packet_id) {
                    self.send_packet(&Packet::Puback { packet_id }, now);
                }
                self.on_publish(&topic, payload, now);
            }
            Packet::Oversized { qos, packet_id } => {
                if let (QoS::AtLeastOnce, Some(packet_id)) = (qos, packet_id) {
                    self.send_packet(&Packet::Puback { packet_id }, now);
                }
                self.emit(Effect::Dropped {
                    reason: "a publish over the packet size limit".into(),
                });
            }
            Packet::Puback { packet_id } => {
                let settled = self
                    .net
                    .conn
                    .as_mut()
                    .and_then(|c| c.inflight.remove(&packet_id));
                if let Some(InFlight::Message { peer, msg_id }) = settled {
                    self.on_puback(&peer, &msg_id, now);
                }
            }
            Packet::Suback { codes, .. } if codes.contains(&0x80) => {
                self.emit(Effect::Dropped {
                    reason: "the broker refused a subscription".into(),
                });
            }
            _ => {}
        }
    }

    fn on_connected(&mut self, conn: u64, now: i64) {
        let Some(me) = self.me.clone() else { return };
        let Some(c) = self.current(conn) else { return };
        c.up = true;
        self.net.backoff_ms = 0;
        self.net.next_poll = Some(now.saturating_add(DIRECTORY_POLL_MS));
        self.emit(Effect::Connection(ConnState::Connected));
        let mut filters = vec![
            (topics::inbox_topic(&me), QoS::AtLeastOnce),
            (topics::graph_topic(&me), QoS::AtLeastOnce),
        ];
        for p in self.peers.values() {
            filters.extend(crate::directory::peer_filters(p));
        }
        self.subscribe(filters, now);
        let online = !self.net.away;
        self.publish(
            topics::presence_topic(&me),
            presence_payload(online),
            true,
            InFlight::Other,
            now,
        );
        self.on_link_up(now);
    }

    /// Routes an inbound publish by its topic.
    fn on_publish(&mut self, topic: &str, payload: Vec<u8>, now: i64) {
        match topics::route(topic) {
            Some(Route::Presence(id)) => {
                let online = serde_json::from_slice::<Value>(&payload)
                    .ok()
                    .and_then(|v| v.get("s").and_then(Value::as_str).map(|s| s == "online"))
                    .unwrap_or(false);
                if let Some(p) = self.peers.get_mut(&id)
                    && p.online != online
                {
                    p.online = online;
                    self.emit(Effect::PresenceChanged {
                        peer: id.to_string(),
                        online,
                    });
                }
            }
            Some(Route::Graph(_)) => self.sync_directory(),
            Some(Route::Inbox(_) | Route::Conversation(_) | Route::Handshake(_)) => {
                self.on_frame(topic, payload, now);
            }
            None => self.emit(Effect::Dropped {
                reason: format!("publish on {topic}, outside the layout"),
            }),
        }
    }

    // ── Sending ────────────────────────────────────────────────────────────

    fn send_packet(&mut self, packet: &Packet, now: i64) -> bool {
        let Ok(bytes) = mqtt::encode(packet) else {
            return false;
        };
        let Some(c) = self.net.conn.as_mut().filter(|c| c.opened) else {
            return false;
        };
        let bytes = match &mut c.noise {
            Noise::None if !c.hqn => bytes,
            Noise::Open(t) => match noise::seal_frames(&mut t.send, &bytes) {
                Ok(b) => b,
                Err(_) => return false,
            },
            _ => return false,
        };
        c.last_write = now;
        let conn = c.id;
        self.emit(Effect::Write { conn, bytes });
        true
    }

    /// A packet id not in flight, or `None` when `MAX_IN_FLIGHT` publishes
    /// already wait for their PUBACK: the caller keeps the message queued.
    fn packet_id(&mut self) -> Option<u16> {
        let c = self.net.conn.as_mut()?;
        if c.inflight.len() >= MAX_IN_FLIGHT {
            return None;
        }
        // Fewer than MAX_IN_FLIGHT ids are taken, so a free one is near.
        for _ in 0..=MAX_IN_FLIGHT {
            c.next_packet_id = c.next_packet_id.wrapping_add(1);
            if c.next_packet_id != 0 && !c.inflight.contains_key(&c.next_packet_id) {
                return Some(c.next_packet_id);
            }
        }
        None
    }

    /// Publishes at QoS 1 on a live link; false when there is none.
    pub fn publish(
        &mut self,
        topic: String,
        payload: Vec<u8>,
        retain: bool,
        what: InFlight,
        now: i64,
    ) -> bool {
        if !self.net.conn.as_ref().is_some_and(|c| c.up) {
            return false;
        }
        let Some(packet_id) = self.packet_id() else {
            return false;
        };
        let packet = Packet::Publish {
            topic,
            payload,
            qos: QoS::AtLeastOnce,
            retain,
            packet_id: Some(packet_id),
            dup: false,
        };
        if !self.send_packet(&packet, now) {
            return false;
        }
        if let Some(c) = self.net.conn.as_mut() {
            c.inflight.insert(packet_id, what);
        }
        true
    }

    /// Announces presence (retained). Offline when the app goes to the
    /// background, where the OS freezes the link and the broker would keep
    /// this client online until the keep-alive lapses; online on return.
    /// True when the announcement was written to a live link.
    pub fn set_presence(&mut self, online: bool, now: i64) -> bool {
        self.net.away = !online;
        let Some(me) = self.me.clone() else {
            return false;
        };
        self.publish(
            topics::presence_topic(&me),
            presence_payload(online),
            true,
            InFlight::Other,
            now,
        )
    }

    pub fn link_up(&self) -> bool {
        self.net.conn.as_ref().is_some_and(|c| c.up)
    }

    fn subscribe(&mut self, filters: Vec<(String, QoS)>, now: i64) {
        if filters.is_empty() {
            return;
        }
        if let Some(packet_id) = self.packet_id() {
            self.send_packet(&Packet::Subscribe { packet_id, filters }, now);
        }
    }

    /// Friend topics changed: follow them on a live link (a reconnect
    /// subscribes to everything anyway).
    pub fn on_topics_changed(&mut self, subscribe: Vec<(String, QoS)>, unsubscribe: Vec<String>) {
        if !self.link_up() {
            return;
        }
        let now = self.net.conn.as_ref().map_or(0, |c| c.last_write);
        if !unsubscribe.is_empty()
            && let Some(packet_id) = self.packet_id()
        {
            self.send_packet(
                &Packet::Unsubscribe {
                    packet_id,
                    filters: unsubscribe,
                },
                now,
            );
        }
        self.subscribe(subscribe, now);
    }

    // ── Closing and reconnecting ───────────────────────────────────────────

    /// The engine gives up on `conn`: asks the shell to close it, then
    /// treats it as closed.
    fn drop_conn(&mut self, conn: u64, now: i64, retry: bool) {
        if self.current(conn).is_none() {
            return;
        }
        self.emit(Effect::Close { conn });
        self.closed(conn, now, retry);
    }

    pub fn on_closed(&mut self, conn: u64, _reason: &CloseReason, now: i64) {
        self.closed(conn, now, true);
    }

    fn closed(&mut self, conn: u64, now: i64, retry: bool) {
        let Some(c) = self.net.conn.take_if(|c| c.id == conn) else {
            return;
        };
        if c.hqn && !c.up {
            // This network blocks or breaks hqn/1: WSS from now on, at once.
            let key = self.network_key();
            self.net.hqn_failed.insert(key);
            self.net.retry_at = Some(now);
        } else if retry {
            self.net.backoff_ms = self
                .net
                .backoff_ms
                .saturating_mul(2)
                .clamp(BACKOFF_START_MS, BACKOFF_MAX_MS);
            self.net.retry_at = Some(now.saturating_add(self.net.backoff_ms));
        }
        self.net.next_poll = None;
        self.emit(Effect::Connection(ConnState::Offline));
        let online: Vec<PeerId> = self
            .peers
            .values()
            .filter(|p| p.online)
            .map(|p| p.id.clone())
            .collect();
        for id in online {
            if let Some(p) = self.peers.get_mut(&id) {
                p.online = false;
            }
            self.emit(Effect::PresenceChanged {
                peer: id.to_string(),
                online: false,
            });
        }
        self.on_link_down(c.inflight, now);
        if self.net.retry_at == Some(now) {
            self.connect(now);
        }
        self.schedule(now);
    }

    pub fn on_network_changed(&mut self, network: crate::types::NetworkInfo, now: i64) {
        let changed = self.network.as_ref().is_none_or(|n| n.key != network.key);
        self.network = Some(network);
        if !changed {
            return;
        }
        self.net.backoff_ms = 0;
        if let Some(conn) = self.net.conn.as_ref().map(|c| c.id) {
            self.emit(Effect::Close { conn });
            self.closed(conn, now, false);
        }
        self.connect(now);
    }

    /// A timer fired or the shell resumed.
    pub fn tick(&mut self, now: i64) {
        if let Some(c) = self.net.conn.as_ref() {
            let id = c.id;
            let connack_late = !c.up && now.saturating_sub(c.opened_at) >= CONNACK_TIMEOUT_MS;
            let silent = c.up && now.saturating_sub(c.last_read) >= READ_TIMEOUT_MS;
            if connack_late || silent {
                self.drop_conn(id, now, true);
            } else if c.up && now.saturating_sub(c.last_write) >= KEEP_ALIVE_MS {
                self.send_packet(&Packet::Pingreq, now);
            }
        }
        if self.link_up() && self.net.next_poll.is_some_and(|t| now >= t) {
            self.net.next_poll = Some(now.saturating_add(DIRECTORY_POLL_MS));
            self.sync_directory();
        }
        if self.net.conn.is_none() && self.net.retry_at.is_some_and(|t| now >= t) {
            self.net.retry_at = None;
            self.connect(now);
        }
        self.resend_unanswered(now);
        self.schedule(now);
    }

    /// Asks the shell for a tick at the next deadline, when it moved.
    pub fn schedule(&mut self, _now: i64) {
        let mut next: Option<i64> = None;
        let mut at = |t: i64| next = Some(next.map_or(t, |n: i64| n.min(t)));
        if let Some(c) = self.net.conn.as_ref() {
            if c.up {
                at(c.last_write.saturating_add(KEEP_ALIVE_MS));
                at(c.last_read.saturating_add(READ_TIMEOUT_MS));
            } else {
                at(c.opened_at.saturating_add(CONNACK_TIMEOUT_MS));
            }
        }
        if let Some(t) = self.net.retry_at {
            at(t);
        }
        if let Some(t) = self.net.next_poll {
            at(t);
        }
        for (t, _) in self.convo.unanswered.values() {
            at(*t);
        }
        if let Some(at) = next
            && next != self.net.scheduled
        {
            self.net.scheduled = next;
            self.emit(Effect::Timer { at });
        }
    }
}

/// The gateway from `/auth/transport`, when enabled and well-formed.
fn parse_hqn(a: &Answer) -> Option<HqnInfo> {
    let h = a.body.get("hqn")?;
    if !a.ok() || h.get("enabled").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let host = h.get("host")?.as_str()?.to_owned();
    let port = u16::try_from(h.get("port")?.as_u64()?).ok()?;
    let key = h.get("keys")?.as_array()?.first()?;
    let x25519: [u8; 32] = STANDARD
        .decode(key.get("x25519")?.as_str()?)
        .ok()?
        .try_into()
        .ok()?;
    let hqc = hqc::PublicKey::from_bytes(&STANDARD.decode(key.get("hqc")?.as_str()?).ok()?).ok()?;
    let key_id = u8::try_from(key.get("keyId")?.as_u64()?).ok()?;
    Some(HqnInfo {
        host,
        port,
        server: ServerStaticPublic {
            key_id,
            x25519,
            hqc,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keep_alive_is_the_same_in_both_units() {
        assert_eq!(i64::from(KEEP_ALIVE_SECS) * 1000, KEEP_ALIVE_MS);
    }

    #[test]
    fn the_wss_url_follows_the_server_url() {
        assert_eq!(wss_url("https://hqchat.app"), "wss://hqchat.app/mqtt");
        assert_eq!(wss_url("https://hqchat.app/"), "wss://hqchat.app/mqtt");
        assert_eq!(wss_url("http://127.0.0.1:8090"), "ws://127.0.0.1:8090/mqtt");
    }
}
