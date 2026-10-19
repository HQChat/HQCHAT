//! Friends and prekeys: the directory synced from `/friends/blocked`,
//! `/friends` and `/friends/invites`, the friendship actions, read state,
//! the safety number, and the
//! prekey bundle kept published (a medium-term key rotated weekly and a
//! pool of one-time keys topped up to 8 when it falls to 4, as the TS and
//! Swift clients do).

use std::collections::{BTreeMap, BTreeSet};

use hqc::KeyPair;
use hqchat_protocol::PeerId;
use hqchat_protocol::mqtt::QoS;
use hqchat_protocol::topics::TopicId;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::core::{Core, Peer, Prekeys};
use crate::effect::{Action, Effect, Method};
use crate::http::{Answer, Pending};
use crate::persist;
use crate::types::{CoreError, InviteView, ReportInput};

/// One-time prekeys kept published.
pub(crate) const PREKEY_POOL: u32 = 8;
/// Replenish once the published pool falls to this.
pub(crate) const PREKEY_REPLENISH_AT: u32 = 4;
/// The medium-term prekey's lifetime: the forward-secrecy window of a
/// session that misses the one-time pool.
pub(crate) const MEDIUM_TERM_LIFETIME_MS: i64 = 7 * 24 * 3600 * 1000;

/// The safety number of two identity keys: SHA-256 of the two keys sorted
/// and concatenated, as 12 groups of 5 digits in 3 rows. Both sides compute
/// the same, as in Swift's `KeyFingerprint`.
pub fn safety_number(mine: &[u8], theirs: &[u8]) -> String {
    let (first, second) = if mine < theirs {
        (mine, theirs)
    } else {
        (theirs, mine)
    };
    let mut h = Sha256::new();
    h.update(first);
    h.update(second);
    let hash = h.finalize();
    let groups: Vec<String> = hash
        .chunks_exact(2)
        .take(12)
        .filter_map(|p| match *p {
            [a, b] => Some(format!("{:05}", u16::from_be_bytes([a, b]))),
            _ => None,
        })
        .collect();
    groups
        .chunks(4)
        .map(|row| row.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Core {
    // ── Directory ──────────────────────────────────────────────────────────

    /// Re-reads the block list, then invites, then friends.
    pub fn sync_directory(&mut self) {
        self.request(
            Method::Get,
            "/friends/blocked",
            None,
            true,
            Pending::Blocked,
        );
    }

    /// Adopts the block list, in both directions (the user may have blocked
    /// or unblocked from another device), then reads invites. A blocked
    /// peer is absent from `/friends` by construction, so this has to land
    /// first or their conversation would be removed with them.
    pub fn on_blocked(&mut self, a: Answer, now: i64) {
        let blocked: Option<BTreeSet<PeerId>> = a
            .body
            .get("blocked")
            .and_then(Value::as_array)
            .filter(|_| a.ok())
            .map(|ids| {
                ids.iter()
                    .filter_map(|v| PeerId::parse(&v.as_str()?.to_lowercase()).ok())
                    .collect()
            });
        if let Some(blocked) = &blocked {
            let mut unsubscribe = Vec::new();
            let mut changed = false;
            let ids: Vec<PeerId> = self.peers.keys().cloned().collect();
            for id in ids {
                let Some(peer) = self.peers.get_mut(&id) else {
                    continue;
                };
                match (blocked.contains(&id), peer.blocked_at.is_some()) {
                    (true, false) => {
                        if !peer.is_read_only() {
                            unsubscribe.extend(peer_topics(peer));
                        }
                        peer.blocked_at = Some(now);
                        self.forget_session(&id);
                        changed = true;
                    }
                    // Unblocked: an ordinary row again, which `/friends` no
                    // longer lists, so the next pass removes it.
                    (false, true) => {
                        peer.blocked_at = None;
                        changed = true;
                    }
                    _ => {}
                }
            }
            if changed {
                self.persist_state();
                self.emit(Effect::FriendsChanged);
                self.on_topics_changed(Vec::new(), unsubscribe);
            }
        }
        self.request(
            Method::Get,
            "/friends/invites",
            None,
            true,
            Pending::Invites {
                can_remove: blocked.is_some(),
            },
        );
    }

    /// Makes the directory match `/friends`: new friends added, names and
    /// topic ids updated. A friend no longer listed is kept read-only when
    /// blocked, marked vanished when their username now belongs to another
    /// id (a friend's or an invite's), and otherwise removed with their
    /// session and history.
    pub fn on_friends(&mut self, a: Answer, can_remove: bool, now: i64) {
        let Some(rows) = a
            .body
            .get("friends")
            .and_then(Value::as_array)
            .filter(|_| a.ok())
        else {
            return;
        };
        let me = self.me.clone();
        let mut live = BTreeMap::new();
        for row in rows {
            let text = |k: &str| {
                row.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_lowercase()
            };
            let (Ok(id), Ok(convo), Ok(handshake)) = (
                PeerId::parse(&text("id")),
                TopicId::parse(&text("convo_id")),
                TopicId::parse(&text("handshake_id")),
            ) else {
                continue;
            };
            if Some(&id) == me.as_ref() {
                continue;
            }
            let username = row
                .get("username")
                .and_then(Value::as_str)
                .filter(|u| !u.is_empty())
                .map(str::to_owned);
            live.insert(id, (username, convo, handshake));
        }

        let mut subscribe: Vec<(String, QoS)> = Vec::new();
        let mut unsubscribe: Vec<String> = Vec::new();
        let mut changed = false;
        let live_names: BTreeSet<String> = live
            .values()
            .filter_map(|(username, _, _)| username.clone())
            .chain(self.invites.iter().map(|i| i.username.clone()))
            .filter(|u| !u.is_empty())
            .collect();
        let gone: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(id, p)| !live.contains_key(*id) && !p.is_read_only())
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            // Same handle, another id, and this one is no longer listed: the
            // person reset or moved device and this identity is gone. Kept,
            // never merged into the new one (that would carry over a
            // verification the new key never earned).
            if peer
                .username
                .as_deref()
                .is_some_and(|u| live_names.contains(u))
            {
                unsubscribe.extend(peer_topics(peer));
                peer.vanished_at = Some(now);
                self.forget_session(&id);
                changed = true;
            } else if can_remove {
                unsubscribe.extend(peer_topics(peer));
                self.forget_peer(&id);
                changed = true;
            }
        }
        for (id, (username, convo, handshake)) in live {
            let peer = self
                .peers
                .entry(id.clone())
                .or_insert_with(|| Peer::new(id.clone()));
            // Listed again: a sync that missed them, not a vanished identity.
            if peer.vanished_at.take().is_some() {
                peer.convo = None;
                changed = true;
            }
            if peer.username != username {
                peer.username = username;
                changed = true;
            }
            if peer.convo.as_ref() != Some(&convo) || peer.handshake.as_ref() != Some(&handshake) {
                unsubscribe.extend(peer_topics(peer));
                peer.convo = Some(convo);
                peer.handshake = Some(handshake);
                subscribe.extend(peer_filters(peer));
                changed = true;
            }
        }
        if changed {
            self.persist_state();
            self.emit(Effect::FriendsChanged);
            self.on_topics_changed(subscribe, unsubscribe);
        }
    }

    /// Adopts the invites waiting for an answer, then reads `/friends`.
    pub fn on_invites(&mut self, a: Answer, can_remove: bool) {
        let rows = a
            .body
            .get("invites")
            .and_then(Value::as_array)
            .filter(|_| a.ok());
        self.request(
            Method::Get,
            "/friends",
            None,
            true,
            Pending::Friends {
                can_remove: can_remove && rows.is_some(),
            },
        );
        let Some(rows) = rows else {
            return;
        };
        let invites: Vec<InviteView> = rows
            .iter()
            .filter_map(|r| {
                let id = PeerId::parse(&r.get("id")?.as_str()?.to_lowercase()).ok()?;
                let username = r
                    .get("username")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                Some(InviteView {
                    id: id.to_string(),
                    username,
                })
            })
            .collect();
        if invites != self.invites {
            self.invites = invites;
            self.emit(Effect::InvitesChanged);
        }
    }

    /// Removes a friend from this device: the peer, the session and every
    /// message with them.
    pub fn forget_peer(&mut self, id: &PeerId) {
        self.peers.remove(id);
        self.forget_session(id);
        for slot in self.store.list(persist::messages_prefix(id)) {
            self.store.delete(slot);
        }
    }

    /// Forgets a vanished identity and its history, which only the user
    /// decides: there is no friendship left on the server to end.
    pub fn forget_vanished(&mut self, id: &PeerId) -> Result<(), CoreError> {
        if self.peers.get(id).is_none_or(|p| p.vanished_at.is_none()) {
            return Err(CoreError::State(
                "only a vanished identity is forgotten".into(),
            ));
        }
        self.forget_peer(id);
        self.persist_state();
        self.emit(Effect::FriendsChanged);
        Ok(())
    }

    /// Marks every received message with `peer` read, up to now.
    pub fn mark_read(&mut self, id: &PeerId) -> Result<(), CoreError> {
        self.unlocked()?;
        let last = self.last_stamp;
        let peer = self.peers.get_mut(id).ok_or(CoreError::NotAFriend)?;
        if peer.unread == 0 && peer.read_until >= last {
            return Ok(());
        }
        peer.unread = 0;
        peer.read_until = last;
        self.persist_state();
        self.emit(Effect::FriendsChanged);
        Ok(())
    }

    /// A friendship action; the directory is re-read when it succeeds.
    pub fn friendship(&mut self, action: Action, path: &str, body: Value) {
        self.request(
            Method::Post,
            path,
            Some(body),
            true,
            Pending::ThenSync(action),
        );
    }

    pub fn on_then_sync(&mut self, action: Action, a: Answer) {
        if a.ok() {
            self.sync_directory();
        } else {
            self.fail(action, &a);
        }
    }

    /// Files a report about a friend's messages, with their text as the
    /// excerpt when unlocked, then blocks them if asked.
    pub fn report(&mut self, r: &ReportInput) -> Result<(), CoreError> {
        let peer_id = PeerId::parse(&r.peer)?;
        let convo = self
            .peers
            .get(&peer_id)
            .and_then(|p| p.convo.clone())
            .ok_or(CoreError::NotAFriend)?;
        let mut excerpt = Vec::new();
        if self.unlocked.is_some() {
            for id in &r.msg_ids {
                if let Some(m) = self
                    .message_slot_of(&peer_id, id)
                    .and_then(|s| self.get_message(&s).ok().flatten())
                {
                    excerpt.push(m.text);
                }
            }
        }
        let mut body = serde_json::Map::new();
        body.insert("conversation".into(), json!(convo.as_str()));
        body.insert("peer".into(), json!(peer_id.as_str()));
        body.insert("category".into(), json!(r.reason));
        if !excerpt.is_empty() {
            body.insert("excerpt".into(), json!(excerpt.join("\n")));
        }
        if let Some(first) = r.msg_ids.first() {
            body.insert("messageId".into(), json!(first));
        }
        let body = Value::Object(body);
        self.request(
            Method::Post,
            "/report",
            Some(body),
            true,
            Pending::Action(Action::Report),
        );
        if r.block {
            self.friendship(
                Action::Block,
                "/friends/block",
                json!({ "peer": peer_id.as_str() }),
            );
        }
        Ok(())
    }

    pub fn fingerprint(&self, peer: &PeerId) -> Option<String> {
        let mine = self.unlocked.as_ref()?.identity.public.as_bytes().to_vec();
        let theirs = self.peers.get(peer)?.pinned.as_ref()?;
        Some(safety_number(&mine, theirs.as_bytes()))
    }

    // ── Prekeys ────────────────────────────────────────────────────────────

    /// Keeps a bundle published: rotates the medium-term key when due, else
    /// asks how many one-time keys are left.
    pub fn ensure_prekeys(&mut self, now: i64) {
        let Some(u) = self.unlocked.as_ref() else {
            return;
        };
        let due = u
            .prekeys
            .as_ref()
            .is_none_or(|p| now.saturating_sub(p.rotated_at) > MEDIUM_TERM_LIFETIME_MS);
        if due {
            self.publish_prekeys(now, true, PREKEY_POOL);
        } else {
            self.request(
                Method::Get,
                "/prekeys/count",
                None,
                true,
                Pending::PrekeyCount,
            );
        }
    }

    pub fn on_prekey_count(&mut self, a: Answer, now: i64) {
        if !a.ok() {
            return;
        }
        // A count past u32 is absurd; read it as "plenty" rather than truncate it.
        let remaining = a
            .body
            .get("remaining")
            .and_then(Value::as_u64)
            .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));
        if remaining <= PREKEY_REPLENISH_AT {
            self.publish_prekeys(now, false, PREKEY_POOL.saturating_sub(remaining));
        }
    }

    /// Mints `count` one-time keys (and a new medium-term key when `rotate`),
    /// saves the secrets, then publishes the public halves.
    fn publish_prekeys(&mut self, now: i64, rotate: bool, count: u32) {
        let Some(u) = self.unlocked.as_mut() else {
            return;
        };
        let identity_sk = u.identity.secret.clone();
        let mut minted = Vec::new();
        let result: Result<(), CoreError> = (|| {
            if rotate || u.prekeys.is_none() {
                let medium = hqc::generate_keypair()?;
                let (one_time, next_id) = u
                    .prekeys
                    .take()
                    .map_or((BTreeMap::new(), 0), |p| (p.one_time, p.next_id));
                u.prekeys = Some(Prekeys {
                    identity_sk,
                    medium,
                    rotated_at: now,
                    one_time,
                    next_id,
                });
            }
            let p = u
                .prekeys
                .as_mut()
                .ok_or_else(|| CoreError::State("no prekeys to extend".into()))?;
            for _ in 0..count {
                let KeyPair { public, secret } = hqc::generate_keypair()?;
                let id = p.next_id;
                p.next_id = p.next_id.wrapping_add(1);
                p.one_time.insert(id, secret);
                minted.push(json!({ "id": id, "prekey": hex::encode(public.as_bytes()) }));
            }
            Ok(())
        })();
        if result.is_err() {
            return;
        }
        let Some(medium) = u
            .prekeys
            .as_ref()
            .map(|p| hex::encode(p.medium.public.as_bytes()))
        else {
            return;
        };
        // Secrets are saved before the public halves leave.
        if self.save_state().is_err() {
            return;
        }
        let body = json!({ "medium": medium, "oneTime": minted });
        self.request(
            Method::Post,
            "/prekeys",
            Some(body),
            true,
            Pending::Action(Action::PublishPrekeys),
        );
    }
}

/// A friend's topics as MQTTService.swift follows them: conversation and
/// handshake at QoS 1, presence at QoS 0. None for a read-only peer.
pub(crate) fn peer_filters(p: &Peer) -> Vec<(String, QoS)> {
    use hqchat_protocol::topics;
    let mut t = Vec::new();
    if p.is_read_only() {
        return t;
    }
    if let (Some(c), Some(h)) = (&p.convo, &p.handshake) {
        t.push((topics::conversation_topic(c), QoS::AtLeastOnce));
        t.push((topics::handshake_topic(h), QoS::AtLeastOnce));
    }
    t.push((topics::presence_topic(&p.id), QoS::AtMostOnce));
    t
}

fn peer_topics(p: &Peer) -> Vec<String> {
    peer_filters(p).into_iter().map(|(t, _)| t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_safety_number_matches_swift_and_is_symmetric() {
        let a = [1u8; 7237];
        let b = [2u8; 7237];
        let n = safety_number(&a, &b);
        assert_eq!(
            n,
            "50949 50985 38914 00946\n40248 47042 64465 02094\n62630 10301 59543 20533"
        );
        assert_eq!(safety_number(&b, &a), n);
    }
}
