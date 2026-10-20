//! Frames any signed-in account can publish into an inbox, naming a friend of
//! the victim: public ids and keys are enough to build them. None of them may
//! cost the victim a real message, unbounded memory or disk, or a
//! notification in the friend's name.

mod forge;
mod support;

use forge::{ForgedInit, conn_of, forged_msg, publish_bytes};
use hqchat_engine::Effect;
use hqchat_protocol::PeerId;
use support::{Client, FakeServer, NOW, settle};

fn texts(c: &Client, from: &Client) -> Vec<String> {
    c.engine
        .history(from.id(), None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| !m.outgoing)
        .map(|m| m.text)
        .collect()
}

fn victim_and_friend() -> (
    std::rc::Rc<std::cell::RefCell<FakeServer>>,
    Client,
    Client,
    String,
    String,
) {
    let server = FakeServer::shared();
    let mut victim = Client::signed_in(&server, "victim");
    let mut friend = Client::signed_in(&server, "friend");
    Client::befriend(&mut victim, &mut friend);
    settle(&mut [&mut victim, &mut friend]);
    let (friend_pk, victim_pk) = {
        let s = server.borrow();
        (
            s.users[&friend.id()].pk_hex.clone(),
            s.users[&victim.id()].pk_hex.clone(),
        )
    };
    (server, victim, friend, friend_pk, victim_pk)
}

fn inject(victim: &mut Client, pid: u16, frame: &[u8], now: i64) {
    let inbox = format!("u/{}/inbox", victim.id());
    let conn = conn_of(victim);
    let e = victim
        .engine
        .on_bytes(conn, publish_bytes(&inbox, pid, frame), now);
    victim.pump(e);
}

fn dropped(c: &Client, what: &str) -> usize {
    c.seen
        .iter()
        .filter(|e| matches!(e, Effect::Dropped { reason } if reason.contains(what)))
        .count()
}

#[test]
fn forged_inits_cannot_evict_a_friends_open_challenge() {
    let (_s, mut victim, mut friend, friend_pk, victim_pk) = victim_and_friend();
    let e = friend
        .engine
        .send_text(victim.id(), "first contact".into(), NOW)
        .unwrap();
    friend.pump(e);
    victim.pump(Vec::new());
    // Before the proof is back, more forged inits than there are slots.
    for i in 0..6u16 {
        let forged = ForgedInit::new(&friend_pk, &victim_pk);
        inject(
            &mut victim,
            100 + i,
            &forged.frame(&format!("x{i}"), 32),
            NOW + 1,
        );
    }
    settle(&mut [&mut victim, &mut friend]);
    assert_eq!(texts(&victim, &friend), ["first contact"]);
    assert!(dropped(&victim, "too many open challenges") >= 1);
}

#[test]
fn a_first_message_refused_while_the_slots_are_full_arrives_later() {
    let (_s, mut victim, mut friend, friend_pk, victim_pk) = victim_and_friend();
    for i in 0..4u16 {
        let forged = ForgedInit::new(&friend_pk, &victim_pk);
        inject(
            &mut victim,
            100 + i,
            &forged.frame(&format!("x{i}"), 32),
            NOW,
        );
    }
    settle(&mut [&mut victim, &mut friend]);
    let e = friend
        .engine
        .send_text(victim.id(), "first contact".into(), NOW)
        .unwrap();
    friend.pump(e);
    settle(&mut [&mut victim, &mut friend]);
    assert!(
        texts(&victim, &friend).is_empty(),
        "refused: no slot was free"
    );
    // The forged challenges expire; the friend sends its init again.
    for t in [NOW + 61_000, NOW + 125_000] {
        victim.tick(t);
        friend.tick(t);
        settle(&mut [&mut victim, &mut friend]);
    }
    assert_eq!(texts(&victim, &friend), ["first contact"]);
}

#[test]
fn the_frames_of_one_unproven_init_are_held_up_to_a_bound() {
    let (_s, mut victim, _friend, friend_pk, victim_pk) = victim_and_friend();
    let forged = ForgedInit::new(&friend_pk, &victim_pk);
    for i in 0..40u16 {
        inject(
            &mut victim,
            100 + i,
            &forged.frame(&format!("m{i}"), 100_000),
            NOW,
        );
    }
    let refused =
        dropped(&victim, "too many frames held") + dropped(&victim, "too much held for unproven");
    assert!(refused >= 32, "at most 8 held, {refused} refused");
}

#[test]
fn while_locked_a_frame_out_of_place_neither_notifies_nor_is_stored() {
    let (_s, mut victim, friend, friend_pk, victim_pk) = victim_and_friend();
    victim.engine.lock();
    victim.vault.lock();
    let (from, to) = (
        PeerId::parse(&friend.id()).unwrap(),
        PeerId::parse(&victim.id()).unwrap(),
    );
    let before = victim.seen.len();
    // A msg naming the friend, but on the inbox: only the friend's
    // conversation topic, an id the two of them hold, vouches for a msg.
    for i in 0..200u16 {
        inject(
            &mut victim,
            i + 1,
            &forged_msg(&from, &to, &format!("spoof-{i}")),
            NOW,
        );
    }
    // First contacts are vouched for by no one: no name, and a quota.
    for i in 0..100u16 {
        let forged = ForgedInit::new(&friend_pk, &victim_pk);
        inject(
            &mut victim,
            1000 + i,
            &forged.frame(&format!("x{i}"), 32),
            NOW,
        );
    }
    let seen = &victim.seen[before..];
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, Effect::Notify { peer: Some(p) } if *p == friend.id())),
        "nothing notifies in the friend's name"
    );
    let anonymous = seen
        .iter()
        .filter(|e| matches!(e, Effect::Notify { peer: None }))
        .count();
    let pending = victim
        .store
        .snapshot()
        .keys()
        .filter(|k| k.starts_with("pending/"))
        .count();
    assert_eq!(
        anonymous, 64,
        "first contacts notify without a name, up to the quota"
    );
    assert_eq!(pending, 64, "only those are kept");
    assert_eq!(victim.engine.friends()[0].unread, 0);
}

#[test]
fn a_drop_reason_never_carries_a_conversation_id() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    for text in ["hello", "again"] {
        let e = b.engine.send_text(a.id(), text.into(), b.now).unwrap();
        b.pump(e);
        settle(&mut [&mut a, &mut b]);
    }
    let before = server.borrow().broker.routed.len();
    let e = b.engine.send_text(a.id(), "third".into(), b.now).unwrap();
    b.pump(e);
    let (convo_topic, payload) = server.borrow().broker.routed[before..]
        .iter()
        .find(|(t, _)| t.starts_with("cv/"))
        .cloned()
        .expect("a conversation frame");
    // Republished on the inbox, where anyone may publish: dropped, and the
    // reason (which reaches logs) says where it was expected without the id.
    let inbox = format!("u/{}/inbox", a.id());
    server.borrow_mut().route(&inbox, payload, false);
    settle(&mut [&mut a, &mut b]);
    let id = convo_topic.trim_start_matches("cv/");
    let reasons: Vec<&String> = a
        .seen
        .iter()
        .filter_map(|e| match e {
            Effect::Dropped { reason } => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("expected cv/…")),
        "{reasons:?}"
    );
    assert!(!reasons.iter().any(|r| r.contains(&id[..8])), "{reasons:?}");
}
