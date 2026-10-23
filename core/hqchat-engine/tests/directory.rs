//! Friends, invites, reports and prekeys against the fake server.

mod support;

use hqchat_engine::{Action, Effect, ReportInput, safety_number};
use support::{Client, FakeServer};

#[test]
fn an_invite_reaches_the_other_user_and_accepting_makes_both_friends() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    let e = b.engine.set_username("bob".into());
    b.pump(e);
    let e = a.engine.invite("bob".into());
    a.pump(e);
    let e = b.engine.start(
        support::NOW,
        hqchat_engine::NetworkInfo {
            key: "t".into(),
            expensive: false,
        },
    );
    b.pump(e);
    assert!(b.seen.contains(&Effect::InvitesChanged));
    assert_eq!(b.engine.invites().len(), 1);
    assert_eq!(b.engine.invites()[0].id, a.id());

    let e = b.engine.accept(a.id());
    b.pump(e);
    assert!(b.seen.contains(&Effect::FriendsChanged));
    assert!(b.engine.invites().is_empty());
    let e = a.engine.start(
        support::NOW,
        hqchat_engine::NetworkInfo {
            key: "t".into(),
            expensive: false,
        },
    );
    a.pump(e);
    let fa = a.engine.friends();
    assert_eq!(fa.len(), 1);
    assert_eq!(fa[0].id, b.id());
    assert_eq!(fa[0].username.as_deref(), Some("bob"));
    assert_eq!(b.engine.friends()[0].id, a.id());
}

#[test]
fn the_directory_survives_a_restart() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let restarted =
        hqchat_engine::Engine::new(support::config("a"), a.vault.clone(), a.store.clone()).unwrap();
    assert!(
        restarted.friends().is_empty(),
        "locked: the directory is sealed"
    );
    restarted.unlock(support::NOW).unwrap();
    assert_eq!(restarted.friends().len(), 1);
}

#[test]
fn removing_a_friend_drops_them_from_both_directories() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let e = a.engine.remove(b.id());
    a.pump(e);
    assert!(a.engine.friends().is_empty());
}

#[test]
fn a_failed_action_is_reported_with_its_code() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let e = a.engine.invite("nobody".into());
    a.pump(e);
    assert!(a.seen.contains(&Effect::ActionFailed {
        action: Action::Invite,
        status: 404,
        code: "USER_NOT_FOUND".into()
    }));
}

#[test]
fn a_report_names_the_conversation_and_can_block() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let e = a.engine.report(ReportInput {
        peer: b.id(),
        reason: "spam".into(),
        msg_id: None,
        note: Some("again and again".into()),
        block: true,
    });
    a.pump(e);
    let s = server.borrow();
    let report = s.reports.last().expect("filed");
    assert_eq!(report["peer"], b.id());
    assert_eq!(report["category"], "spam");
    assert_eq!(report["note"], "again and again");
    let log = &s.log;
    let reported = log.iter().position(|(_, p)| p == "/report").unwrap();
    let blocked = log.iter().position(|(_, p)| p == "/friends/block").unwrap();
    assert!(reported < blocked, "the block waits for the report");
    assert_eq!(report["conversation"].as_str().unwrap().len(), 64);
    assert!(s.users[&a.id()].blocked.contains(&b.id()));
    drop(s);
    let friends = a.engine.friends();
    assert_eq!(friends.len(), 1, "the conversation is kept");
    assert_eq!(friends[0].blocked_at, Some(support::NOW));
}

#[test]
fn a_blocked_friend_is_kept_read_only_until_unblocked() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let e = a.engine.send_text(b.id(), "before".into(), a.now).unwrap();
    a.pump(e);
    support::settle(&mut [&mut a, &mut b]);

    let e = a.engine.block(b.id());
    a.pump(e);
    let friends = a.engine.friends();
    assert_eq!(friends.len(), 1);
    assert!(friends[0].blocked_at.is_some());
    assert!(
        !friends[0].has_session,
        "the session ends with the friendship"
    );
    assert_eq!(
        a.engine.history(b.id(), None, 10).unwrap().len(),
        1,
        "the history stays"
    );
    assert!(
        a.engine.send_text(b.id(), "after".into(), a.now).is_err(),
        "nothing is sent to a blocked friend"
    );

    // A sync later (the next poll, another device) keeps them.
    a.start(a.now);
    assert!(a.engine.friends()[0].blocked_at.is_some());

    // Unblocking does not restore the friendship: the row is ordinary again,
    // absent from /friends, and goes with its history.
    let e = a.engine.unblock(b.id());
    a.pump(e);
    assert!(a.engine.friends().is_empty());
    assert!(a.engine.history(b.id(), None, 10).unwrap().is_empty());
}

#[test]
fn a_block_from_another_device_arrives_and_is_lifted_the_same_way() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    {
        let mut s = server.borrow_mut();
        let pair = FakeServer::pair_of(&a.id(), &b.id());
        s.friendships.remove(&pair);
        s.users.get_mut(&a.id()).unwrap().blocked.push(b.id());
    }
    a.start(a.now);
    assert!(a.engine.friends()[0].blocked_at.is_some(), "kept, blocked");
    server
        .borrow_mut()
        .users
        .get_mut(&a.id())
        .unwrap()
        .blocked
        .clear();
    a.start(a.now);
    assert!(a.engine.friends().is_empty());
}

#[test]
fn without_the_block_list_nobody_is_removed() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let pair = FakeServer::pair_of(&a.id(), &b.id());
    server.borrow_mut().friendships.remove(&pair);
    server.borrow_mut().fail_blocked = true;
    a.start(a.now);
    assert_eq!(
        a.engine.friends().len(),
        1,
        "a blocked friend could not be told apart"
    );
    server.borrow_mut().fail_blocked = false;
    a.start(a.now);
    assert!(a.engine.friends().is_empty());
}

#[test]
fn a_username_under_a_new_id_leaves_the_old_identity_vanished() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    let e = b.engine.set_username("bob".into());
    b.pump(e);
    Client::befriend(&mut a, &mut b);
    let e = a.engine.send_text(b.id(), "hello".into(), a.now).unwrap();
    a.pump(e);

    // Bob resets: the old identity is gone, a new one holds the name.
    {
        let mut s = server.borrow_mut();
        let pair = FakeServer::pair_of(&a.id(), &b.id());
        s.friendships.remove(&pair);
        s.users.get_mut(&b.id()).unwrap().username = None;
    }
    let mut c = Client::signed_in(&server, "c");
    let e = c.engine.set_username("bob".into());
    c.pump(e);
    let e = c.engine.invite(a.id());
    c.pump(e);
    a.start(a.now);
    assert_eq!(
        a.engine.friends().len(),
        1,
        "the invite is not a friend yet"
    );
    assert!(a.engine.friends()[0].vanished_at.is_some());
    let e = a.engine.accept(c.id());
    a.pump(e);
    c.start(c.now);
    support::settle(&mut [&mut a, &mut c]);

    let friends = a.engine.friends();
    assert_eq!(friends.len(), 2);
    let old = friends.iter().find(|f| f.id == b.id()).unwrap();
    let new = friends.iter().find(|f| f.id == c.id()).unwrap();
    assert!(old.vanished_at.is_some() && !old.has_session);
    assert!(new.vanished_at.is_none());
    assert!(a.engine.send_text(b.id(), "again".into(), a.now).is_err());
    assert_eq!(a.engine.history(b.id(), None, 10).unwrap().len(), 1);

    assert!(
        a.engine.forget(c.id()).is_err(),
        "only a vanished identity is forgotten"
    );
    let e = a.engine.forget(b.id()).unwrap();
    a.pump(e);
    assert_eq!(a.engine.friends().len(), 1);
    assert!(a.engine.history(b.id(), None, 10).unwrap().is_empty());
}

#[test]
fn signing_in_publishes_a_full_bundle_and_tops_it_up_when_low() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    {
        let s = server.borrow();
        let user = &s.users[&a.id()];
        assert!(user.medium.is_some());
        assert_eq!(user.one_time.len(), 8);
    }
    server
        .borrow_mut()
        .users
        .get_mut(&a.id())
        .unwrap()
        .one_time
        .truncate(4);
    // A refresh is a sign-in: the pool is checked and topped up.
    let later = support::NOW + 12 * 3600 * 1000 - 60_000;
    let e = a.engine.start(
        later,
        hqchat_engine::NetworkInfo {
            key: "t".into(),
            expensive: false,
        },
    );
    a.pump(e);
    let s = server.borrow();
    let ids: Vec<u64> = s.users[&a.id()]
        .one_time
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ids.len(), 8);
    assert_eq!(ids[4..], [8, 9, 10, 11], "new ids, never reused");
}

#[test]
fn the_safety_number_is_the_same_on_both_sides() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    b.start(b.now);
    let mine = a.engine.fingerprint(b.id());
    assert!(mine.is_some(), "the key is pinned at sync");
    assert_eq!(mine, b.engine.fingerprint(a.id()));
    assert_eq!(safety_number(&[1], &[2]), safety_number(&[2], &[1]));
}

#[test]
fn a_write_the_store_refuses_reaches_the_app() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    b.store.set_full(true);
    Client::befriend(&mut a, &mut b);
    assert!(
        b.seen
            .iter()
            .any(|e| matches!(e, Effect::StorageFailed { reason } if reason.contains("state"))),
        "the friend list changed and could not be saved: {:?}",
        b.seen
    );
    assert!(
        !a.seen
            .iter()
            .any(|e| matches!(e, Effect::StorageFailed { .. })),
        "a's store works"
    );
}

#[test]
fn a_sent_request_is_listed_until_answered_or_withdrawn() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    let mut c = Client::signed_in(&server, "c");
    let e = b.engine.set_username("bob".into());
    b.pump(e);
    assert!(b.seen.contains(&Effect::ActionDone {
        action: Action::SetUsername
    }));

    let e = a.engine.invite("bob".into());
    a.pump(e);
    assert!(a.seen.contains(&Effect::ActionDone {
        action: Action::Invite
    }));
    assert_eq!(a.engine.sent_invites()[0].to, "bob");
    let e = a.engine.invite(c.id());
    a.pump(e);
    assert_eq!(a.engine.sent_invites().len(), 2);

    // Answered: bob accepts, and the request is gone from the list.
    b.start(b.now);
    let e = b.engine.accept(a.id());
    b.pump(e);
    a.start(a.now);
    let sent = a.engine.sent_invites();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].to, c.id());

    // Withdrawn.
    let e = a.engine.cancel(c.id());
    a.pump(e);
    assert!(a.engine.sent_invites().is_empty());
    c.start(c.now);
    assert!(c.engine.invites().is_empty(), "c no longer sees it");

    // Survives a restart.
    let e = a.engine.invite(c.id());
    a.pump(e);
    let restarted =
        hqchat_engine::Engine::new(support::config("a"), a.vault.clone(), a.store.clone()).unwrap();
    restarted.unlock(support::NOW).unwrap();
    assert_eq!(restarted.sent_invites().len(), 1);
}

#[test]
fn a_friends_key_is_pinned_on_sync_and_can_be_marked_verified() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let f = &a.engine.friends()[0];
    assert!(f.has_key, "pinned before any message");
    assert!(!f.verified);
    assert!(a.engine.fingerprint(b.id()).is_some());

    let e = a.engine.set_verified(b.id(), true).unwrap();
    a.pump(e);
    assert!(a.engine.friends()[0].verified);
    let restarted =
        hqchat_engine::Engine::new(support::config("a"), a.vault.clone(), a.store.clone()).unwrap();
    restarted.unlock(support::NOW).unwrap();
    assert!(restarted.friends()[0].verified);
}

#[test]
fn a_report_quotes_one_message_the_friend_sent_and_nothing_else() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    let e = b
        .engine
        .send_text(a.id(), "the abuse".into(), b.now)
        .unwrap();
    b.pump(e);
    support::settle(&mut [&mut a, &mut b]);
    let e = a
        .engine
        .send_text(b.id(), "my private reply".into(), a.now)
        .unwrap();
    a.pump(e);
    support::settle(&mut [&mut a, &mut b]);
    let history = a.engine.history(b.id(), None, 10).unwrap();
    let theirs = history.iter().find(|m| !m.outgoing).unwrap().msg_id.clone();
    let mine = history.iter().find(|m| m.outgoing).unwrap().msg_id.clone();
    let report = |msg_id: Option<String>| ReportInput {
        peer: b.id(),
        reason: "abuse".into(),
        msg_id,
        note: None,
        block: false,
    };

    let filed = server.borrow().reports.len();
    let e = a.engine.report(report(Some(mine)));
    assert!(
        e.iter().any(|e| matches!(e, Effect::ActionFailed { .. })),
        "the user's own message is never quoted: {e:?}"
    );
    let e = a.engine.report(report(Some("not-a-message".into())));
    assert!(e.iter().any(|e| matches!(e, Effect::ActionFailed { .. })));
    assert_eq!(server.borrow().reports.len(), filed, "nothing was filed");

    let e = a.engine.report(report(Some(theirs.clone())));
    a.pump(e);
    let s = server.borrow();
    let filed = s.reports.last().expect("filed");
    assert_eq!(filed["excerpt"], "the abuse");
    assert_eq!(filed["messageId"], theirs);
}
