//! The broker connection against the fake server's broker and gateway.

mod support;

use hqchat_engine::{ConnState, Effect, Endpoint, NetworkInfo};
use support::{Client, FakeServer, NOW, settle};

fn opens(c: &Client) -> Vec<bool> {
    c.seen
        .iter()
        .filter_map(|e| match e {
            Effect::Open { endpoint, .. } => Some(matches!(endpoint, Endpoint::Tcp { .. })),
            _ => None,
        })
        .collect()
}

fn connected(c: &Client) -> bool {
    c.seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Connection(s) => Some(*s == ConnState::Connected),
            _ => None,
        })
        .unwrap_or(false)
}

#[test]
fn without_a_gateway_the_engine_connects_over_wss_and_subscribes() {
    let server = FakeServer::shared();
    let a = Client::signed_in(&server, "a");
    assert_eq!(opens(&a), [false]);
    assert!(connected(&a));
    let routed = &server.borrow().broker.routed;
    assert!(
        routed
            .iter()
            .any(|(t, p)| *t == format!("u/{}/presence", a.id()) && p == br#"{"s":"online"}"#)
    );
}

#[test]
fn with_a_gateway_the_engine_connects_over_hqn() {
    let server = FakeServer::shared();
    server.borrow_mut().enable_hqn();
    let a = Client::signed_in(&server, "a");
    assert_eq!(opens(&a), [true]);
    assert!(connected(&a));
}

#[test]
fn an_engine_that_does_not_allow_hqn_keeps_to_wss_even_when_offered() {
    let server = FakeServer::shared();
    server.borrow_mut().enable_hqn();
    let config = hqchat_engine::Config {
        allow_hqn: false,
        ..support::config("a")
    };
    let a = Client::signed_in_with(&server, "a", config);
    assert_eq!(opens(&a), [false]);
    assert!(connected(&a));
}

#[test]
fn a_network_that_blocks_hqn_falls_back_to_wss_at_once_and_stays_there() {
    let server = FakeServer::shared();
    server.borrow_mut().enable_hqn();
    server.borrow_mut().broker.block_hqn = true;
    let mut a = Client::signed_in(&server, "a");
    assert_eq!(opens(&a), [true, false]);
    assert!(connected(&a));

    // The broker drops the link; the reconnect skips hqn/1 on this network.
    let conn = 2;
    server.borrow_mut().mqtt_closed("a", conn);
    let e = a
        .engine
        .on_closed(conn, hqchat_engine::CloseReason::Remote, NOW);
    a.pump(e);
    a.tick(NOW + 2_000);
    assert_eq!(opens(&a), [true, false, false]);
    assert!(connected(&a));
}

#[test]
fn friends_see_each_other_come_online_and_the_will_says_when_one_vanishes() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    settle(&mut [&mut a, &mut b]);
    assert!(
        a.engine.friends()[0].online,
        "b's retained presence reached a"
    );
    assert!(b.engine.friends()[0].online);

    // b's network dies without a DISCONNECT: the broker publishes b's will.
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
    settle(&mut [&mut a, &mut b]);
    assert!(a.seen.contains(&Effect::PresenceChanged {
        peer: b.id(),
        online: false
    }));
    assert!(!a.engine.friends()[0].online);
}

#[test]
fn a_graph_nudge_syncs_the_directory_without_polling() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    let e = a.engine.invite(b.id());
    a.pump(e);
    b.start(NOW);
    let e = b.engine.accept(a.id());
    b.pump(e);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(
        a.engine.friends().len(),
        1,
        "the nudge on u/{{a}}/graph made a re-read /friends"
    );
}

#[test]
fn refused_credentials_are_renewed_before_the_next_attempt() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    // The server forgets a's signing keys; a reconnect is refused once.
    server
        .borrow_mut()
        .users
        .get_mut(&a.id())
        .unwrap()
        .signing_keys
        .clear();
    let conn = a
        .seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .unwrap();
    server.borrow_mut().mqtt_closed("a", conn);
    let e = a
        .engine
        .on_closed(conn, hqchat_engine::CloseReason::Remote, NOW);
    a.pump(e);
    a.tick(NOW + 2_000);
    assert!(a.seen.iter().any(
        |e| matches!(e, Effect::Dropped { reason } if reason.contains("refused the connection"))
    ));
    a.tick(NOW + 6_000);
    assert!(
        server
            .borrow()
            .log
            .iter()
            .any(|(_, p)| p == "/auth/refresh")
    );
    assert!(connected(&a));
}

#[test]
fn a_dropped_link_reconnects_with_backoff() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let conn = 1;
    server.borrow_mut().mqtt_closed("a", conn);
    let e = a
        .engine
        .on_closed(conn, hqchat_engine::CloseReason::Remote, NOW);
    a.pump(e);
    assert!(!connected(&a));
    assert!(a.seen.contains(&Effect::Timer { at: NOW + 2_000 }));
    a.tick(NOW + 1_000);
    assert!(!connected(&a), "not before the backoff");
    a.tick(NOW + 2_000);
    assert!(connected(&a));
}

#[test]
fn moving_to_another_network_reconnects() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let e = a.engine.on_network_changed(
        NetworkInfo {
            key: "cellular".into(),
            expensive: true,
        },
        NOW,
    );
    a.pump(e);
    assert_eq!(
        opens(&a).len(),
        2,
        "the old link closed and a new one opened"
    );
    assert!(connected(&a));
}

#[test]
fn a_live_link_pings_and_polls_the_directory_every_minute() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let friends_before = server
        .borrow()
        .log
        .iter()
        .filter(|(_, p)| p == "/friends")
        .count();
    a.tick(NOW + 60_000);
    assert!(connected(&a), "the ping was answered");
    let friends_after = server
        .borrow()
        .log
        .iter()
        .filter(|(_, p)| p == "/friends")
        .count();
    assert_eq!(friends_after, friends_before + 1);
}

#[test]
fn going_to_the_background_announces_offline_and_returning_online() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    settle(&mut [&mut a, &mut b]);
    assert_eq!(a.engine.my_id(), Some(a.id()));

    let e = b.engine.set_presence(false, NOW);
    b.pump(e);
    settle(&mut [&mut a, &mut b]);
    assert!(
        !a.engine.friends()[0].online,
        "b is away: the bridge pushes"
    );

    // A reconnect while away keeps saying offline.
    b.start(NOW);
    settle(&mut [&mut a, &mut b]);
    assert!(!a.engine.friends()[0].online);

    let e = b.engine.set_presence(true, NOW);
    b.pump(e);
    settle(&mut [&mut a, &mut b]);
    assert!(a.engine.friends()[0].online);
}
