//! Frames anyone signed in can publish: the broker lets every client write to
//! every inbox, and a frame's `sender` is not the MQTT publisher. Nothing in
//! them may change a session before the named sender proves its key.

mod support;

use hqchat_engine::Effect;
use hqchat_protocol::{PeerId, envelope, topics};
use support::{Client, FakeServer, settle};

fn send(c: &mut Client, to: &Client, text: &str) {
    let e = c.engine.send_text(to.id(), text.into(), c.now).unwrap();
    c.pump(e);
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

/// Two friends, the one with the higher id first: on a simultaneous start, the
/// higher id is the one that yields.
fn friends_hi_lo() -> (std::rc::Rc<std::cell::RefCell<FakeServer>>, Client, Client) {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    if a.id() > b.id() {
        (server, a, b)
    } else {
        (server, b, a)
    }
}

/// An init that claims to come from `from`, built only from public values:
/// `to`'s own init to `from`, re-addressed, carrying `from`'s public key.
fn forged_init(
    server: &std::rc::Rc<std::cell::RefCell<FakeServer>>,
    from: &Client,
    to: &Client,
) -> Vec<u8> {
    let from_id = PeerId::parse(&from.id()).unwrap();
    let to_id = PeerId::parse(&to.id()).unwrap();
    let s = server.borrow();
    let (_, raw) = s
        .broker
        .routed
        .iter()
        .find(|(t, _)| *t == topics::inbox_topic(&from_id))
        .expect("the victim's init to its friend");
    let (mut frame, _) = envelope::decode(raw).unwrap();
    frame.header.sender = from_id;
    frame.header.to = to_id;
    let init = frame.header.init.as_mut().unwrap();
    init.sender_pk = hex::decode(&s.users[&from.id()].pk_hex).unwrap();
    envelope::encode(&frame).unwrap()
}

#[test]
fn an_unproven_init_does_not_wipe_a_pending_session() {
    let (server, mut hi, mut lo) = friends_hi_lo();
    // `lo` is offline: `hi`'s first message waits for an answer.
    let lo_conn = lo
        .seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .unwrap();
    server.borrow_mut().mqtt_closed(&lo.profile, lo_conn);
    let e = lo.engine.on_closed(
        lo_conn,
        hqchat_engine::CloseReason::Failed("offline".into()),
        lo.now,
    );
    lo.pump(e);
    send(&mut hi, &lo, "hello from hi");
    settle(&mut [&mut hi, &mut lo]);

    // A stranger publishes an init "from lo" into hi's inbox.
    let forged = forged_init(&server, &lo, &hi);
    let hi_id = PeerId::parse(&hi.id()).unwrap();
    server
        .borrow_mut()
        .route(&topics::inbox_topic(&hi_id), forged, false);
    settle(&mut [&mut hi, &mut lo]);

    lo.tick(lo.now + 2_000);
    settle(&mut [&mut hi, &mut lo]);
    assert_eq!(texts(&lo, &hi), ["hello from hi"]);
    send(&mut lo, &hi, "and back");
    settle(&mut [&mut hi, &mut lo]);
    assert_eq!(texts(&hi, &lo), ["and back"]);
}

#[test]
fn a_real_simultaneous_start_still_resolves_after_the_proof() {
    let (_server, mut hi, mut lo) = friends_hi_lo();
    send(&mut hi, &lo, "from hi");
    send(&mut lo, &hi, "from lo");
    settle(&mut [&mut hi, &mut lo]);
    assert_eq!(texts(&lo, &hi), ["from hi"]);
    assert_eq!(texts(&hi, &lo), ["from lo"]);
    send(&mut hi, &lo, "after");
    send(&mut lo, &hi, "after too");
    settle(&mut [&mut hi, &mut lo]);
    assert_eq!(texts(&lo, &hi), ["from hi", "after"]);
    assert_eq!(texts(&hi, &lo), ["from lo", "after too"]);
}
