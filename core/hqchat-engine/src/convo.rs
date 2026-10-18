//! Conversations: `services/server/src/client/conversation.ts` on the
//! protocol crate, with what the Apple app adds around it.
//!
//! - **Sending.** A message is stored, sealed, before anything leaves, and
//!   waits in the outbox until the broker acknowledges it. The first send to
//!   a friend fetches and checks their identity key, claims their prekeys and
//!   starts a session; the init header rides on every frame until they
//!   answer. A link that drops before the PUBACK sends again under the same
//!   id (the receiver keeps the first copy).
//! - **Receiving.** A frame must come from a friend, be addressed to us and
//!   arrive on the topic its kind belongs to. An unproven init is held and
//!   its sender challenged on the friendship's handshake topic; the proof
//!   releases the frames of that one init. Messages are stored and
//!   acknowledged with a receipt; a receipt marks ours delivered.
//! - **Locked.** Frames that arrive while locked are sealed to the device
//!   key as they came and opened, in order, by the next unlock; the shell
//!   gets a notification without content meanwhile.
//! - **Both sides at once.** When an init crosses ours, the lower id keeps
//!   its session and the higher one yields, adopts the other's and sends
//!   its unconfirmed messages again (`InitCollision` in the Apple app).

use std::collections::{HashMap, HashSet};

use hqc::{Ciphertext, PublicKey};
use hqchat_protocol::envelope::{self, Frame, Header, InitFields, Kind, OneTime};
use hqchat_protocol::handshake::{self, HandshakeFrame};
use hqchat_protocol::ratchet::{self, InitHeader, MessageHeader, PrekeyBundle, SessionState};
use hqchat_protocol::topics;
use hqchat_protocol::{Kem, OsEntropy, PeerId, aead};
use serde_json::json;

use crate::core::Core;
use crate::effect::{Effect, Method};
use crate::http::{Answer, Pending};
use crate::net::InFlight;
use crate::persist::{self, StoredMessage, StoredPending};
use crate::types::{CoreError, Delivery, Message};

/// How long an issued challenge stands.
const CHALLENGE_TTL_MS: i64 = 60_000;
/// Open challenges per peer: bounds what forged inits can cost.
const MAX_CHALLENGES_PER_PEER: usize = 4;

/// An outgoing message the broker has not acknowledged yet.
#[derive(Debug, Clone)]
pub(crate) struct Outgoing {
    pub peer: PeerId,
    pub msg_id: String,
    /// Published on the current link, waiting for its PUBACK.
    pub in_flight: bool,
}

/// A challenge about one init, keyed by that init's transcript.
struct Challenge {
    peer: PeerId,
    nonce: [u8; 32],
    expected: [u8; 32],
    /// The frames of that init, held until the proof, in arrival order.
    held: Vec<(Frame, Vec<u8>)>,
    expires_at: i64,
}

#[derive(Default)]
pub(crate) struct Convo {
    pub outbox: Vec<Outgoing>,
    /// Friends whose key or prekeys are being fetched.
    starting: HashSet<PeerId>,
    challenges: HashMap<[u8; 32], Challenge>,
    /// Transcripts of inits whose sender proved its key.
    proven: HashSet<[u8; 32]>,
    /// Friends whose simultaneous init we yielded to: resend once theirs opens.
    yielded: HashSet<PeerId>,
    pending_seq: u64,
}

fn new_msg_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn message_header(h: &Header) -> Option<MessageHeader> {
    Some(MessageHeader {
        cid: h.cid,
        rk: h
            .rk
            .as_deref()
            .map(PublicKey::from_bytes)
            .transpose()
            .ok()?,
        kem_ct: h
            .kem_ct
            .as_deref()
            .map(Ciphertext::from_bytes)
            .transpose()
            .ok()?,
        n: h.n,
        pn: h.pn,
    })
}

fn init_header(h: &Header) -> Option<InitHeader> {
    let init = h.init.as_ref()?;
    Some(InitHeader {
        ct_id: Ciphertext::from_bytes(&init.ct_id).ok()?,
        ct_mt: Ciphertext::from_bytes(&init.ct_mt).ok()?,
        one_time: match &h.one_time {
            Some(o) => Some((Ciphertext::from_bytes(&o.ct_ot).ok()?, o.ot_id)),
            None => None,
        },
        rk: PublicKey::from_bytes(h.rk.as_deref()?).ok()?,
        cid: h.cid,
    })
}

impl Core {
    fn drop_frame(&mut self, reason: impl Into<String>) {
        self.emit(Effect::Dropped {
            reason: reason.into(),
        });
    }

    fn me_or_err(&self) -> Result<PeerId, CoreError> {
        self.me.clone().ok_or(CoreError::NoIdentity)
    }

    // ── Sending ────────────────────────────────────────────────────────────

    pub fn send_text(&mut self, peer: &PeerId, text: &str, now: i64) -> Result<(), CoreError> {
        self.unlocked()?;
        if self
            .peers
            .get(peer)
            .and_then(|p| p.convo.as_ref())
            .is_none()
        {
            return Err(CoreError::NotAFriend);
        }
        let msg_id = new_msg_id();
        let at = self.stamp(now);
        let record = StoredMessage {
            format: persist::FORMAT,
            msg_id: msg_id.clone(),
            outgoing: true,
            text: text.to_owned(),
            at,
            delivery: Some(persist::delivery_byte(Delivery::Sending)),
        };
        self.put_message(peer, &record)?;
        self.convo.outbox.push(Outgoing {
            peer: peer.clone(),
            msg_id: msg_id.clone(),
            in_flight: false,
        });
        self.save_state()?;
        self.emit(Effect::MessageAdded(Message {
            msg_id,
            peer: peer.to_string(),
            outgoing: true,
            text: text.to_owned(),
            at,
            delivery: Some(Delivery::Sending),
        }));
        self.flush(peer, now);
        Ok(())
    }

    pub fn retry(&mut self, msg_id: &str, now: i64) -> Result<(), CoreError> {
        self.unlocked()?;
        let peer = self
            .peers
            .keys()
            .find(|p| self.message_slot_of(p, msg_id).is_some())
            .cloned()
            .ok_or(CoreError::State("no such message".into()))?;
        if !self.convo.outbox.iter().any(|o| o.msg_id == msg_id) {
            self.convo.outbox.push(Outgoing {
                peer: peer.clone(),
                msg_id: msg_id.to_owned(),
                in_flight: false,
            });
            self.save_state()?;
        }
        self.set_status(&peer, msg_id, Delivery::Sending);
        self.flush(&peer, now);
        Ok(())
    }

    /// Sends what waits for `peer`, starting a session first if needed.
    pub fn flush(&mut self, peer: &PeerId, now: i64) {
        if self.unlocked.is_none() || !self.link_up() {
            return;
        }
        if !self
            .convo
            .outbox
            .iter()
            .any(|o| o.peer == *peer && !o.in_flight)
        {
            return;
        }
        match self.session(peer) {
            Ok(Some(_)) => {}
            Ok(None) => return self.start_session(peer),
            Err(_) => return,
        }
        let waiting: Vec<String> = self
            .convo
            .outbox
            .iter()
            .filter(|o| o.peer == *peer && !o.in_flight)
            .map(|o| o.msg_id.clone())
            .collect();
        for msg_id in waiting {
            let Some(text) = self
                .message_slot_of(peer, &msg_id)
                .and_then(|s| self.get_message(&s).ok().flatten())
                .map(|m| m.text)
            else {
                self.convo.outbox.retain(|o| o.msg_id != msg_id);
                continue;
            };
            match self.seal_frame(peer, Kind::Msg, &msg_id, &text, now) {
                Ok((topic, bytes)) => {
                    let what = InFlight::Message {
                        peer: peer.clone(),
                        msg_id: msg_id.clone(),
                    };
                    if !self.publish(topic, bytes, false, what, now) {
                        break;
                    }
                    if let Some(o) = self.convo.outbox.iter_mut().find(|o| o.msg_id == msg_id) {
                        o.in_flight = true;
                    }
                }
                Err(e) => {
                    self.drop_frame(format!("could not seal for {peer}: {e:?}"));
                    break;
                }
            }
        }
    }

    pub fn flush_all(&mut self, now: i64) {
        let peers: HashSet<PeerId> = self.convo.outbox.iter().map(|o| o.peer.clone()).collect();
        for peer in peers {
            self.flush(&peer, now);
        }
    }

    /// Seals one frame for `peer` on the session, which advances and is saved.
    fn seal_frame(
        &mut self,
        peer: &PeerId,
        kind: Kind,
        msg_id: &str,
        text: &str,
        now: i64,
    ) -> Result<(String, Vec<u8>), CoreError> {
        let me = self.me_or_err()?;
        let my_pk = self.unlocked()?.identity.public.as_bytes().to_vec();
        let convo = self
            .peers
            .get(peer)
            .and_then(|p| p.convo.clone())
            .ok_or(CoreError::NotAFriend)?;
        let kem = self.kem;
        let session = self
            .session(peer)?
            .ok_or(CoreError::State("no session".into()))?;
        let sealed = ratchet::seal(&kem, session, now)?;
        let init = sealed.init;
        let header = Header {
            kind: if init.is_some() { Kind::Init } else { kind },
            sender: me,
            to: peer.clone(),
            msg_id: msg_id.to_owned(),
            cid: sealed.header.cid,
            n: sealed.header.n,
            pn: sealed.header.pn,
            rk: match &init {
                Some(i) => Some(i.rk.as_bytes().to_vec()),
                None => sealed.header.rk.as_ref().map(|k| k.as_bytes().to_vec()),
            },
            kem_ct: if init.is_some() {
                None
            } else {
                sealed.header.kem_ct.as_ref().map(|c| c.as_bytes().to_vec())
            },
            init: init.as_ref().map(|i| InitFields {
                sender_pk: my_pk.clone(),
                ct_id: i.ct_id.as_bytes().to_vec(),
                ct_mt: i.ct_mt.as_bytes().to_vec(),
            }),
            one_time: init
                .as_ref()
                .and_then(|i| i.one_time.as_ref())
                .map(|(ct, id)| OneTime {
                    ct_ot: ct.as_bytes().to_vec(),
                    ot_id: *id,
                }),
        };
        let aad = envelope::header_bytes(&header)?;
        let payload = aead::seal_payload(text.as_bytes(), &sealed.key.0, &aad, &mut OsEntropy)?;
        let bytes = envelope::encode(&Frame { header, payload })?;
        self.save_session(peer)?;
        let topic = if init.is_some() {
            topics::inbox_topic(peer)
        } else {
            topics::conversation_topic(&convo)
        };
        Ok((topic, bytes))
    }

    /// Fetches the friend's key (if not pinned yet), then claims their prekeys.
    fn start_session(&mut self, peer: &PeerId) {
        if !self.convo.starting.insert(peer.clone()) {
            return;
        }
        if self.peers.get(peer).is_some_and(|p| p.pinned.is_some()) {
            self.claim(peer);
        } else {
            self.request(
                Method::Get,
                &format!("/peer/{peer}/key"),
                None,
                false,
                Pending::PeerKey(peer.clone()),
            );
        }
    }

    fn claim(&mut self, peer: &PeerId) {
        let body = json!({ "peer": peer.as_str() });
        self.request(
            Method::Post,
            "/prekeys/claim",
            Some(body),
            true,
            Pending::Claim(peer.clone()),
        );
    }

    pub fn on_peer_key(&mut self, peer: PeerId, a: Answer, now: i64) {
        let key = a
            .str("publicKey")
            .and_then(|h| hex::decode(h.to_lowercase()).ok())
            .and_then(|b| PublicKey::from_bytes(&b).ok())
            .filter(|k| peer.matches(k) && a.ok());
        match key {
            Some(key) => {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.pinned = Some(key);
                }
                let _ = self.save_state();
                self.claim(&peer);
            }
            None => {
                self.convo.starting.remove(&peer);
                self.drop_frame(format!(
                    "the key served for {peer} does not hash to that id"
                ));
                self.fail_outbox(&peer);
            }
        }
        let _ = now;
    }

    pub fn on_claim(&mut self, peer: PeerId, a: Answer, now: i64) {
        self.convo.starting.remove(&peer);
        let medium = a
            .str("medium")
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| PublicKey::from_bytes(&b).ok());
        let (Some(medium), true, Some(identity)) = (
            medium,
            a.ok(),
            self.peers.get(&peer).and_then(|p| p.pinned.clone()),
        ) else {
            return self.fail_outbox(&peer);
        };
        let one_time = a
            .body
            .get("oneTime")
            .filter(|v| !v.is_null())
            .and_then(|o| {
                let id = u32::try_from(o.get("id")?.as_u64()?).ok()?;
                let pk =
                    PublicKey::from_bytes(&hex::decode(o.get("prekey")?.as_str()?).ok()?).ok()?;
                Some((pk, id))
            });
        let bundle = PrekeyBundle {
            identity_pk: identity,
            medium_pk: medium,
            one_time,
        };
        let kem = self.kem;
        match ratchet::start_as_initiator(&kem, &bundle, now) {
            Ok((session, _)) => {
                if self.put_session(&peer, session).is_ok() {
                    self.flush(&peer, now);
                }
            }
            Err(_) => self.fail_outbox(&peer),
        }
    }

    /// The friend cannot be reached (no prekeys, a bad key): what waits for
    /// them fails, and `retry` sends it again later.
    fn fail_outbox(&mut self, peer: &PeerId) {
        let failed: Vec<String> = self
            .convo
            .outbox
            .iter()
            .filter(|o| o.peer == *peer)
            .map(|o| o.msg_id.clone())
            .collect();
        self.convo.outbox.retain(|o| o.peer != *peer);
        let _ = self.save_state();
        for msg_id in failed {
            self.set_status(peer, &msg_id, Delivery::Failed);
        }
    }

    fn set_status(&mut self, peer: &PeerId, msg_id: &str, status: Delivery) {
        let Some(slot) = self.message_slot_of(peer, msg_id) else {
            return;
        };
        let Ok(Some(mut m)) = self.get_message(&slot) else {
            return;
        };
        let current = m.delivery.map(persist::delivery_of);
        // Delivery only moves forward, except a retry out of Failed.
        let allowed = match (current, status) {
            (Some(Delivery::Failed), Delivery::Sending) => true,
            (Some(c), s) => s > c,
            (None, _) => false,
        };
        if !allowed {
            return;
        }
        m.delivery = Some(persist::delivery_byte(status));
        if self.put_message(peer, &m).is_ok() {
            self.emit(Effect::MessageStatus {
                msg_id: msg_id.to_owned(),
                status,
            });
        }
    }

    // ── Link events (hooks of net.rs) ──────────────────────────────────────

    pub fn on_puback(&mut self, peer: &PeerId, msg_id: &str, _now: i64) {
        let before = self.convo.outbox.len();
        self.convo.outbox.retain(|o| o.msg_id != msg_id);
        if self.convo.outbox.len() != before && self.unlocked.is_some() {
            let _ = self.save_state();
        }
        let online = self.peers.get(peer).is_some_and(|p| p.online);
        self.set_status(
            peer,
            msg_id,
            if online {
                Delivery::Sent
            } else {
                Delivery::Queued
            },
        );
    }

    pub fn on_link_up(&mut self, now: i64) {
        self.flush_all(now);
    }

    pub fn on_link_down(&mut self, _unacked: HashMap<u16, InFlight>, _now: i64) {
        for o in &mut self.convo.outbox {
            o.in_flight = false;
        }
    }

    // ── Receiving ──────────────────────────────────────────────────────────

    /// An inbound frame: opened now, or kept for the unlock.
    pub fn on_frame(&mut self, topic: &str, payload: Vec<u8>, now: i64) {
        if self.unlocked.is_none() {
            return self.keep_for_unlock(topic, payload, now);
        }
        if topic.starts_with("hs/") {
            return self.on_handshake(topic, &payload, now);
        }
        let (frame, aad) = match envelope::decode(&payload) {
            Ok(d) => d,
            Err(_) => return self.drop_frame(format!("not a frame on {topic}")),
        };
        let Some(me) = self.me.clone() else { return };
        let sender = frame.header.sender.clone();
        if sender == me {
            return self.drop_frame("own frame");
        }
        let Some(peer) = self.peers.get(&sender).cloned() else {
            return self.drop_frame(format!("frame from {sender}, not a friend"));
        };
        if frame.header.to != me {
            return self.drop_frame("frame addressed to someone else");
        }
        let expected = if frame.header.kind == Kind::Init {
            Some(topics::inbox_topic(&me))
        } else {
            peer.convo.as_ref().map(topics::conversation_topic)
        };
        if expected.as_deref() != Some(topic) {
            return self.drop_frame(format!(
                "{:?} on {topic}, expected {expected:?}",
                frame.header.kind
            ));
        }
        if frame.header.kind == Kind::Init {
            return self.on_init(&sender, frame, aad, now);
        }
        self.open_message(&sender, &frame, &aad, now);
    }

    /// Seals the frame to the device key as it came: opened by the unlock.
    fn keep_for_unlock(&mut self, topic: &str, payload: Vec<u8>, now: i64) {
        let notify = match envelope::decode(&payload) {
            Ok((f, _)) if f.header.kind != Kind::Receipt => Some(f.header.sender),
            _ => None,
        };
        self.convo.pending_seq += 1;
        let slot = persist::pending_slot(now, self.convo.pending_seq);
        let record = StoredPending {
            format: persist::FORMAT,
            topic: topic.to_owned(),
            payload,
        };
        let sealed = persist::encode(&record).and_then(|plain| {
            persist::seal_device(&self.vault.device_public_key()?, &slot, &plain)
        });
        match sealed {
            Ok(blob) => {
                let _ = self.store.put(slot, blob);
            }
            Err(e) => {
                return self.drop_frame(format!("could not keep a frame for the unlock: {e:?}"));
            }
        }
        if let Some(sender) = notify
            && let Some(p) = self.peers.get_mut(&sender)
        {
            p.unread += 1;
            self.emit(Effect::Notify {
                peer: sender.to_string(),
            });
        }
    }

    /// Opens, in arrival order, the frames that came while locked.
    pub fn drain_pending(&mut self, now: i64) {
        let slots = self.store.list(persist::PENDING_PREFIX.into());
        for slot in slots {
            let opened = self
                .store
                .get(slot.clone())
                .ok_or(CoreError::State("gone".into()))
                .and_then(|blob| persist::open_device(self.vault.as_ref(), &slot, &blob))
                .and_then(|plain| persist::decode::<StoredPending>(&slot, &plain));
            match opened {
                Ok(p) => {
                    self.store.delete(slot);
                    self.on_frame(&p.topic, p.payload, now);
                }
                // Locked again mid-drain: the rest waits for the next unlock.
                Err(CoreError::Vault(_)) => break,
                Err(_) => self.store.delete(slot),
            }
        }
        let mut changed = false;
        for p in self.peers.values_mut() {
            changed |= p.unread != 0;
            p.unread = 0;
        }
        if changed {
            self.emit(Effect::FriendsChanged);
        }
    }

    fn on_init(&mut self, sender: &PeerId, frame: Frame, aad: Vec<u8>, now: i64) {
        let Some(init) = init_header(&frame.header) else {
            return self.drop_frame("init missing handshake fields or of the wrong sizes");
        };
        let has_session = matches!(self.session(sender), Ok(Some(_)));
        if has_session {
            let heard = matches!(self.session(sender), Ok(Some(s)) if s.pending_init.is_none());
            let me = self.me.clone().expect("checked by on_frame");
            if heard {
                // An initiator repeats its init until answered: the payload is a message.
                return self.open_message(sender, &frame, &aad, now);
            }
            if me < *sender {
                return self.drop_frame("simultaneous init: keeping ours (lower id)");
            }
            // Yield: theirs wins; ours was never answered.
            self.forget_session(sender);
            self.convo.yielded.insert(sender.clone());
        }
        let me = self.me.clone().expect("checked by on_frame");
        let transcript = handshake::init_transcript(sender, &me, &init);
        if self.convo.proven.contains(&transcript) {
            self.open_init(sender, &frame, &aad, now);
        } else {
            self.challenge(sender, frame, aad, transcript, &init, now);
        }
    }

    fn challenge(
        &mut self,
        peer: &PeerId,
        frame: Frame,
        aad: Vec<u8>,
        transcript: [u8; 32],
        _init: &InitHeader,
        now: i64,
    ) {
        self.convo.challenges.retain(|_, c| c.expires_at > now);
        if let Some(open) = self.convo.challenges.get_mut(&transcript) {
            open.held.push((frame, aad));
            return;
        }
        let Some(handshake_id) = self.peers.get(peer).and_then(|p| p.handshake.clone()) else {
            return self.drop_frame("init without a handshake topic");
        };
        let Some(sender_pk) = frame
            .header
            .init
            .as_ref()
            .and_then(|i| PublicKey::from_bytes(&i.sender_pk).ok())
        else {
            return self.drop_frame("init without a sender key");
        };
        let mut for_peer: Vec<([u8; 32], i64)> = self
            .convo
            .challenges
            .iter()
            .filter(|(_, c)| c.peer == *peer)
            .map(|(t, c)| (*t, c.expires_at))
            .collect();
        if for_peer.len() >= MAX_CHALLENGES_PER_PEER {
            // The oldest goes: the real initiator re-sends, so its newest init always gets one.
            for_peer.sort_by_key(|(_, at)| *at);
            self.convo.challenges.remove(&for_peer[0].0);
        }
        let Ok(nonce) = handshake::handshake_nonce(&mut OsEntropy) else {
            return;
        };
        let kem = self.kem;
        let Ok((ct, ss)) = kem.encapsulate(&sender_pk) else {
            return;
        };
        let me = self.me.clone().expect("checked by on_frame");
        let expected = handshake::handshake_proof(&ss, &nonce, &me, peer, &transcript);
        self.convo.challenges.insert(
            transcript,
            Challenge {
                peer: peer.clone(),
                nonce,
                expected,
                held: vec![(frame, aad)],
                expires_at: now + CHALLENGE_TTL_MS,
            },
        );
        let chal = HandshakeFrame::Challenge {
            from: me,
            to: peer.clone(),
            nonce,
            ct: ct.as_bytes().to_vec(),
        };
        if let Ok(bytes) = handshake::encode(&chal) {
            self.publish(
                topics::handshake_topic(&handshake_id),
                bytes,
                false,
                InFlight::Other,
                now,
            );
        }
    }

    fn on_handshake(&mut self, topic: &str, raw: &[u8], now: i64) {
        let Ok(h) = handshake::decode(raw) else {
            return self.drop_frame("not a handshake frame");
        };
        let Some(me) = self.me.clone() else { return };
        let (from, to) = match &h {
            HandshakeFrame::Challenge { from, to, .. } | HandshakeFrame::Proof { from, to, .. } => {
                (from.clone(), to.clone())
            }
        };
        if from == me {
            return self.drop_frame("own handshake frame");
        }
        if to != me {
            return self.drop_frame("handshake frame for someone else");
        }
        let expected = self
            .peers
            .get(&from)
            .and_then(|p| p.handshake.as_ref())
            .map(topics::handshake_topic);
        if expected.as_deref() != Some(topic) {
            return self.drop_frame(format!("handshake frame on {topic}"));
        }
        match h {
            HandshakeFrame::Challenge { nonce, ct, .. } => {
                let pending = match self.session(&from) {
                    Ok(Some(s)) => s.pending_init.clone(),
                    _ => None,
                };
                let Some(pending) = pending else {
                    return self.drop_frame("challenge for a handshake this client did not start");
                };
                let Ok(ct) = Ciphertext::from_bytes(&ct) else {
                    return self.drop_frame("challenge of the wrong size");
                };
                let Ok(u) = self.unlocked() else { return };
                let Ok(ss) = hqc::decapsulate(&u.identity.secret, &ct) else {
                    return;
                };
                // Bound to the init WE sent: a challenge about a forged init gets a proof that does not match it.
                let transcript = handshake::init_transcript(&me, &from, &pending);
                let proof = handshake::handshake_proof(&ss, &nonce, &from, &me, &transcript);
                let frame = HandshakeFrame::Proof {
                    from: me,
                    to: from,
                    nonce,
                    proof,
                };
                if let Ok(bytes) = handshake::encode(&frame) {
                    self.publish(topic.to_owned(), bytes, false, InFlight::Other, now);
                }
            }
            HandshakeFrame::Proof { nonce, proof, .. } => {
                self.convo.challenges.retain(|_, c| c.expires_at > now);
                let Some(transcript) = self
                    .convo
                    .challenges
                    .iter()
                    .find(|(_, c)| c.peer == from && c.nonce == nonce)
                    .map(|(t, _)| *t)
                else {
                    return self.drop_frame("proof for no open challenge");
                };
                let challenge = self
                    .convo
                    .challenges
                    .remove(&transcript)
                    .expect("found above");
                if !handshake::proof_matches(&challenge.expected, &proof) {
                    return self.drop_frame("handshake proof did not match");
                }
                // The peer proved THIS init; its other open challenges are about inits it did not build.
                self.convo.proven.insert(transcript);
                self.convo.challenges.retain(|_, c| c.peer != from);
                for (frame, aad) in challenge.held {
                    if matches!(self.session(&from), Ok(Some(_))) {
                        self.open_message(&from, &frame, &aad, now);
                    } else {
                        self.open_init(&from, &frame, &aad, now);
                    }
                }
            }
        }
    }

    fn open_init(&mut self, sender: &PeerId, frame: &Frame, aad: &[u8], now: i64) {
        let Some(init) = init_header(&frame.header) else {
            return;
        };
        let kem = self.kem;
        let Some(session) = self
            .unlocked
            .as_ref()
            .and_then(|u| u.prekeys.as_ref())
            .and_then(|secrets| ratchet::start_as_responder(&kem, secrets, &init, now))
        else {
            return self.drop_frame(
                "init did not open a session (no prekeys, or a consumed one-time key)",
            );
        };
        let mut session = session;
        let Some(text) = open_with(&kem, &mut session, frame, aad) else {
            return self.drop_frame("init payload did not authenticate");
        };
        let sender_pk = frame
            .header
            .init
            .as_ref()
            .and_then(|i| PublicKey::from_bytes(&i.sender_pk).ok());
        if let Some(p) = self.peers.get_mut(sender)
            && p.pinned.is_none()
        {
            p.pinned = sender_pk;
        }
        if let Some(o) = &frame.header.one_time
            && let Some(prekeys) = self.unlocked.as_mut().and_then(|u| u.prekeys.as_mut())
        {
            prekeys.one_time.remove(&o.ot_id);
        }
        if self.put_session(sender, session).is_err() || self.save_state().is_err() {
            return;
        }
        self.deliver(sender, &frame.header.msg_id, text, now);
        if self.convo.yielded.remove(sender) {
            self.resend_unconfirmed(sender, now);
        }
        self.flush(sender, now);
    }

    fn open_message(&mut self, sender: &PeerId, frame: &Frame, aad: &[u8], now: i64) {
        let kem = self.kem;
        let opened = match self.session(sender) {
            Ok(Some(session)) => open_with(&kem, session, frame, aad),
            _ => {
                return self.drop_frame(format!(
                    "{:?} from {sender} with no session",
                    frame.header.kind
                ));
            }
        };
        let Some(text) = opened else {
            return self.drop_frame(format!(
                "{:?} n={} did not authenticate",
                frame.header.kind, frame.header.n
            ));
        };
        if self.save_session(sender).is_err() {
            return;
        }
        if frame.header.kind == Kind::Receipt {
            self.set_status(sender, &frame.header.msg_id, Delivery::Delivered);
        } else {
            self.deliver(sender, &frame.header.msg_id, text, now);
        }
        // Their answer may have opened our session for what waits.
        self.flush(sender, now);
    }

    /// Stores a received message once, tells the UI, and acknowledges it.
    fn deliver(&mut self, sender: &PeerId, msg_id: &str, text: String, now: i64) {
        if self.message_slot_of(sender, msg_id).is_none() {
            let at = self.stamp(now);
            let record = StoredMessage {
                format: persist::FORMAT,
                msg_id: msg_id.to_owned(),
                outgoing: false,
                text: text.clone(),
                at,
                delivery: None,
            };
            if self.put_message(sender, &record).is_err() {
                return;
            }
            self.emit(Effect::MessageAdded(Message {
                msg_id: msg_id.to_owned(),
                peer: sender.to_string(),
                outgoing: false,
                text,
                at,
                delivery: None,
            }));
            self.emit(Effect::Notify {
                peer: sender.to_string(),
            });
        }
        self.send_receipt(sender, msg_id, now);
    }

    /// A receipt never opens a session and is sent only inside an answered one.
    fn send_receipt(&mut self, peer: &PeerId, msg_id: &str, now: i64) {
        let answered = matches!(self.session(peer), Ok(Some(s)) if s.pending_init.is_none());
        if !answered {
            return;
        }
        if let Ok((topic, bytes)) = self.seal_frame(peer, Kind::Receipt, msg_id, "", now) {
            self.publish(topic, bytes, false, InFlight::Other, now);
        }
    }

    /// After yielding a simultaneous start: every outgoing message to `peer`
    /// not yet delivered goes again, in order, under its id.
    fn resend_unconfirmed(&mut self, peer: &PeerId, now: i64) {
        let slots = self.store.list(persist::messages_prefix(peer));
        for slot in slots {
            let Ok(Some(m)) = self.get_message(&slot) else {
                continue;
            };
            let delivered = m.delivery.map(persist::delivery_of) == Some(Delivery::Delivered);
            if m.outgoing && !delivered && !self.convo.outbox.iter().any(|o| o.msg_id == m.msg_id) {
                self.convo.outbox.push(Outgoing {
                    peer: peer.clone(),
                    msg_id: m.msg_id,
                    in_flight: false,
                });
            }
        }
        let _ = self.save_state();
        self.flush(peer, now);
    }
}

/// Opens a frame's payload on `session`; the AEAD tag decides whether the
/// ratchet commits.
fn open_with(
    kem: &dyn Kem,
    session: &mut SessionState,
    frame: &Frame,
    aad: &[u8],
) -> Option<String> {
    let header = message_header(&frame.header)?;
    let mut text = None;
    ratchet::open(kem, session, &header, &mut |key| match aead::open_payload(
        &frame.payload,
        &key.0,
        aad,
    ) {
        Ok(plain) => {
            text = String::from_utf8(plain).ok();
            text.is_some()
        }
        Err(_) => false,
    })?;
    text
}
