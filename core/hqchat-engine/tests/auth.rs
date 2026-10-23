//! Sign-in, refresh and the account actions against the fake server.

mod support;

use hqchat_engine::{Action, ConnState, Effect, Method, NetworkInfo, PushToken, UnlockReason};
use support::{Client, FakeServer, NOW};

fn net() -> NetworkInfo {
    NetworkInfo {
        key: "test".into(),
        expensive: false,
    }
}

/// The sign-in requests, in order (sign-in also syncs the directory and prekeys).
fn paths(server: &std::rc::Rc<std::cell::RefCell<FakeServer>>) -> Vec<String> {
    server
        .borrow()
        .log
        .iter()
        .map(|(_, p)| p.clone())
        .filter(|p| p.starts_with("/auth/") && p != "/auth/transport")
        .collect()
}

#[test]
fn start_signs_in_with_the_hqc_challenge_and_registers_a_signing_key() {
    let server = FakeServer::shared();
    let c = Client::signed_in(&server, "a");
    assert_eq!(paths(&server), ["/auth/init", "/auth/verify"]);
    assert!(
        c.seen
            .contains(&Effect::Connection(ConnState::Authenticating))
    );
    let s = server.borrow();
    let user = s
        .users
        .values()
        .next()
        .expect("the server created the account");
    assert_eq!(user.signing_keys.len(), 1);
    assert!(
        !c.seen
            .iter()
            .any(|e| matches!(e, Effect::ActionFailed { .. }))
    );
}

#[test]
fn a_sign_in_the_server_never_answered_is_tried_again_on_the_backoff() {
    let server = FakeServer::shared();
    let mut c = Client::new(&server, "a");
    let e = c.engine.create_identity().unwrap();
    c.pump(e);
    // The server is not listening yet: the request fails on the way.
    let e = c.engine.start(NOW, net());
    let req = e
        .iter()
        .find_map(|e| match e {
            Effect::Http { req, path, .. } if path == "/auth/init" => Some(*req),
            _ => None,
        })
        .expect("start signs in");
    let e = c.engine.on_http(req, 0, vec![], NOW);
    let at = e
        .iter()
        .find_map(|e| match e {
            Effect::Timer { at } => Some(*at),
            _ => None,
        })
        .expect("a failed sign-in asks to be woken");
    assert!(at > NOW, "not at once: on the backoff");
    assert!(paths(&server).is_empty());
    // A timer that fires early is armed again for the same deadline.
    let e = c.engine.tick(at - 1);
    assert!(
        e.iter().any(|e| matches!(e, Effect::Timer { at: t } if *t == at)),
        "an early wake-up leaves the retry armed"
    );
    assert!(paths(&server).is_empty());
    // Now it is up.
    let e = c.engine.tick(at);
    c.pump(e);
    assert_eq!(paths(&server), ["/auth/init", "/auth/verify"]);
}

#[test]
fn a_locked_profile_asks_for_an_unlock_then_signs_in() {
    let server = FakeServer::shared();
    let mut c = Client::new(&server, "a");
    let e = c.engine.create_identity().unwrap();
    c.pump(e);
    c.engine.lock();
    let e = c.engine.start(NOW, net());
    c.pump(e);
    assert!(c.seen.contains(&Effect::NeedUnlock {
        reason: UnlockReason::SignIn
    }));
    assert!(paths(&server).is_empty());
    let e = c.engine.unlock(NOW).unwrap();
    c.pump(e);
    assert_eq!(paths(&server), ["/auth/init", "/auth/verify"]);
}

#[test]
fn an_expiring_key_is_refreshed_and_a_lapsed_session_signs_in_again() {
    let server = FakeServer::shared();
    let mut c = Client::signed_in(&server, "a");
    let later = NOW + 12 * 3600 * 1000 - 60_000;
    let e = c.engine.start(later, net());
    c.pump(e);
    assert_eq!(paths(&server).last().unwrap(), "/auth/refresh");

    server.borrow_mut().expire_sessions = true;
    let e = c.engine.start(later + 12 * 3600 * 1000, net());
    c.pump(e);
    assert_eq!(
        &paths(&server)[3..],
        ["/auth/refresh", "/auth/init", "/auth/verify"]
    );
}

#[test]
fn a_taken_username_reaches_the_ui_as_a_stable_code() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    let e = a.engine.set_username("alice".into());
    a.pump(e);
    assert!(
        !a.seen
            .iter()
            .any(|e| matches!(e, Effect::ActionFailed { .. }))
    );
    let e = b.engine.set_username("alice".into());
    b.pump(e);
    assert!(b.seen.contains(&Effect::ActionFailed {
        action: Action::SetUsername,
        status: 409,
        code: "USERNAME_TAKEN".into()
    }));
}

#[test]
fn push_registration_names_the_platform_and_environment() {
    let server = FakeServer::shared();
    let mut c = Client::signed_in(&server, "a");
    let e = c.engine.register_push(PushToken::Apns {
        token: "abcd".into(),
        sandbox: true,
    });
    c.pump(e);
    let s = server.borrow();
    let push = s.users.values().next().unwrap().push.clone().unwrap();
    assert_eq!(push["environment"], "sandbox");
    assert_eq!(push["token"], "abcd");
    assert!(
        s.log
            .iter()
            .any(|(m, p)| *m == Method::Post && p == "/push/token")
    );
}

#[test]
fn deleting_the_account_wipes_the_profile() {
    let server = FakeServer::shared();
    let mut c = Client::signed_in(&server, "a");
    let e = c.engine.delete_account();
    c.pump(e);
    assert!(c.seen.contains(&Effect::AccountDeleted));
    assert!(
        c.store.snapshot().is_empty(),
        "nothing of the profile is left"
    );
    assert!(server.borrow().users.is_empty());
    assert!(c.engine.unlock(NOW).is_err());
}
