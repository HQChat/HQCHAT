//! A write that fails while a frame is handled loses nothing: the frame is
//! not acknowledged, the session does not advance, the shell is told, and the
//! frame opens when it comes again.

mod support;

use hqchat_engine::Effect;
use support::{Client, FakeServer, settle};

fn send(c: &mut Client, to: &Client, text: &str) {
    let e = c.engine.send_text(to.id(), text.into(), c.now).unwrap();
    c.pump(e);
}

fn texts(c: &Client, from: &Client) -> Vec<String> {
    let mut t: Vec<String> = c
        .engine
        .history(from.id(), None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| !m.outgoing)
        .map(|m| m.text)
        .collect();
    t.sort();
    t
}

#[test]
fn a_message_that_could_not_be_written_opens_when_it_comes_again() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    send(&mut a, &b, "one");
    settle(&mut [&mut a, &mut b]);
    send(&mut b, &a, "ack");
    settle(&mut [&mut a, &mut b]);

    b.store.set_full(true);
    let before = b.seen.len();
    let routed = server.borrow().broker.routed.len();
    send(&mut a, &b, "two");
    settle(&mut [&mut a, &mut b]);
    assert!(
        b.seen[before..]
            .iter()
            .any(|e| matches!(e, Effect::StorageFailed { .. })),
        "the shell is told"
    );
    let (topic, frame) = server.borrow().broker.routed[routed..]
        .iter()
        .find(|(t, _)| t.starts_with("cv/"))
        .cloned()
        .expect("a's frame");
    b.store.set_full(false);

    send(&mut a, &b, "three");
    settle(&mut [&mut a, &mut b]);
    // The broker delivers the unacknowledged frame again.
    server.borrow_mut().route(&topic, frame, false);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(texts(&b, &a), ["one", "three", "two"]);
}
