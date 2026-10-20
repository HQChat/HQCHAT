//! Two engines talking through the fake server and broker: the scenarios of
//! services/server/test/scenarios/messaging.test.ts, plus what the Apple app
//! adds (statuses, the locked queue, simultaneous starts, history at rest).

mod support;

use hqchat_engine::{Delivery, Effect};
use support::{Client, FakeServer, NOW, settle};

fn pair() -> (std::rc::Rc<std::cell::RefCell<FakeServer>>, Client, Client) {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    (server, a, b)
}

fn send(c: &mut Client, to: &Client, text: &str) -> String {
    let e = c.engine.send_text(to.id(), text.into(), c.now).unwrap();
    let msg_id = e
        .iter()
        .find_map(|e| match e {
            Effect::MessageAdded(m) => Some(m.msg_id.clone()),
            _ => None,
        })
        .unwrap();
    c.pump(e);
    msg_id
}

fn texts(c: &Client, from: &Client) -> Vec<String> {
    c.engine
        .history(from.id(), None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| !m.outgoing)
        .map(|m| m.text)
        .collect()
}

fn unread(c: &Client) -> u32 {
    c.engine.friends()[0].unread
}

#[test]
fn received_messages_are_unread_until_marked_read_and_it_survives_a_restart() {
    let (_server, mut a, mut b) = pair();
    send(&mut a, &b, "one");
    send(&mut a, &b, "two");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(unread(&b), 2);
    assert_eq!(unread(&a), 0, "what one sends is not unread");

    let e = b.engine.mark_read(a.id()).unwrap();
    b.pump(e);
    assert_eq!(unread(&b), 0);
    send(&mut a, &b, "three");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(unread(&b), 1);

    let restarted =
        hqchat_engine::Engine::new(support::config("b"), b.vault.clone(), b.store.clone()).unwrap();
    restarted.unlock(NOW).unwrap();
    assert_eq!(restarted.friends()[0].unread, 1);
}

fn status(c: &Client, peer: &Client, msg_id: &str) -> Option<Delivery> {
    c.engine
        .history(peer.id(), None, 100)
        .unwrap()
        .into_iter()
        .find(|m| m.msg_id == msg_id)
        .and_then(|m| m.delivery)
}

#[test]
fn a_first_message_opens_the_session_through_the_handshake_both_ways() {
    let (_s, mut a, mut b) = pair();
    let id = send(&mut a, &b, "first contact");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["first contact"]);
    assert_eq!(
        status(&a, &b, &id),
        Some(Delivery::Delivered),
        "b's receipt came back"
    );
    send(&mut b, &a, "received");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&a, &b), ["received"]);
    assert!(
        a.engine.fingerprint(b.id()).is_some(),
        "a pinned b's key to start the session"
    );
    assert_eq!(
        a.engine.fingerprint(b.id()),
        b.engine.fingerprint(a.id()),
        "both see one safety number"
    );
}

#[test]
fn a_burst_sent_before_the_peer_replies_arrives_in_full_and_in_order() {
    let (_s, mut a, mut b) = pair();
    for t in ["hi", "you there?", "it is about tomorrow"] {
        send(&mut a, &b, t);
    }
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["hi", "you there?", "it is about tomorrow"]);
}

#[test]
fn a_message_to_an_offline_peer_is_queued_and_delivered_when_it_reconnects() {
    let (server, mut a, mut b) = pair();
    let b_conn = b
        .seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .unwrap();
    server.borrow_mut().mqtt_closed("b", b_conn);
    let e = b.engine.on_closed(
        b_conn,
        hqchat_engine::CloseReason::Failed("offline".into()),
        NOW,
    );
    b.pump(e);
    settle(&mut [&mut a, &mut b]);
    let id = send(&mut a, &b, "sent while you were away");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(
        status(&a, &b, &id),
        Some(Delivery::Queued),
        "the broker took it while b was offline"
    );
    b.tick(NOW + 2_000);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["sent while you were away"]);
}

#[test]
fn a_conversation_ratchets_and_stays_in_sync_across_many_turns() {
    let (_s, mut a, mut b) = pair();
    send(&mut a, &b, "turn 0");
    settle(&mut [&mut a, &mut b]);
    for i in 1..=6 {
        send(&mut b, &a, &format!("b{i}"));
        settle(&mut [&mut a, &mut b]);
        send(&mut a, &b, &format!("a{i}"));
        settle(&mut [&mut a, &mut b]);
    }
    assert_eq!(texts(&a, &b).len(), 6);
    assert_eq!(texts(&b, &a).len(), 7);
    assert_eq!(texts(&b, &a).last().unwrap(), "a6");
}

#[test]
fn frames_that_arrive_locked_wait_for_the_unlock_with_a_notification_meanwhile() {
    let (_s, mut a, mut b) = pair();
    send(&mut a, &b, "opening");
    settle(&mut [&mut a, &mut b]);
    b.engine.lock();
    b.vault.lock();
    let id = send(&mut a, &b, "while you were locked");
    settle(&mut [&mut a, &mut b]);
    assert!(b.seen.contains(&Effect::Notify { peer: Some(a.id()) }));
    assert_eq!(
        b.engine.friends()[0].unread,
        2,
        "the message opened before, and the frame waiting"
    );
    assert!(b.store.snapshot().keys().any(|k| k.starts_with("pending/")));
    assert_eq!(
        status(&a, &b, &id),
        Some(Delivery::Sent),
        "not delivered: b could not open it"
    );

    b.vault.unlock();
    let e = b.engine.unlock(NOW).unwrap();
    b.pump(e);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["opening", "while you were locked"]);
    assert_eq!(b.engine.friends()[0].unread, 2, "opened, still unread");
    assert!(!b.store.snapshot().keys().any(|k| k.starts_with("pending/")));
    assert_eq!(status(&a, &b, &id), Some(Delivery::Delivered));
}

#[test]
fn both_sides_starting_at_once_still_deliver_everything() {
    let (_s, mut a, mut b) = pair();
    // Each sends before seeing the other's init.
    send(&mut a, &b, "from a");
    send(&mut b, &a, "from b");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["from a"]);
    assert_eq!(texts(&a, &b), ["from b"]);
    send(&mut a, &b, "after");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["from a", "after"]);
}

#[test]
fn history_survives_a_restart_and_no_text_is_stored_in_the_clear() {
    let (_s, mut a, mut b) = pair();
    send(&mut a, &b, "remember me");
    settle(&mut [&mut a, &mut b]);
    for blob in b.store.snapshot().values() {
        assert!(
            !blob.windows(11).any(|w| w == b"remember me"),
            "plaintext at rest"
        );
    }
    let restarted =
        hqchat_engine::Engine::new(support::config("b"), b.vault.clone(), b.store.clone()).unwrap();
    restarted.unlock(NOW).unwrap();
    let h = restarted.history(a.id(), None, 10).unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].text, "remember me");
}

#[test]
fn a_friend_without_prekeys_fails_the_message_and_retry_sends_it_later() {
    let (server, mut a, mut b) = pair();
    let medium = server
        .borrow_mut()
        .users
        .get_mut(&b.id())
        .unwrap()
        .medium
        .take();
    let id = send(&mut a, &b, "are you there");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(status(&a, &b, &id), Some(Delivery::Failed));
    server.borrow_mut().users.get_mut(&b.id()).unwrap().medium = medium;
    let e = a.engine.retry(id.clone(), NOW);
    a.pump(e);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["are you there"]);
    assert_eq!(status(&a, &b, &id), Some(Delivery::Delivered));
}

#[test]
fn sending_to_a_stranger_or_while_locked_is_refused() {
    let (_s, mut a, b) = pair();
    assert!(
        a.engine
            .send_text("c".repeat(64), "hi".into(), NOW)
            .is_err(),
        "not a friend"
    );
    a.engine.lock();
    assert!(
        a.engine.send_text(b.id(), "hi".into(), NOW).is_err(),
        "locked"
    );
    let _ = &mut a;
}

#[test]
fn rotating_keys_steps_the_ratchet_and_the_conversation_goes_on() {
    let (_s, mut a, mut b) = pair();
    assert!(
        a.engine.rotate_keys(b.id()).is_err(),
        "no session yet, nothing to rotate"
    );
    send(&mut a, &b, "one");
    settle(&mut [&mut a, &mut b]);
    send(&mut b, &a, "two");
    settle(&mut [&mut a, &mut b]);
    send(&mut a, &b, "three");
    settle(&mut [&mut a, &mut b]);
    let e = a.engine.rotate_keys(b.id()).unwrap();
    a.pump(e);
    send(&mut a, &b, "four");
    settle(&mut [&mut a, &mut b]);
    send(&mut b, &a, "five");
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["one", "three", "four"]);
    assert_eq!(texts(&a, &b), ["two", "five"]);
}
