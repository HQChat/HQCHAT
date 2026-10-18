//! The session, ported from ratchet-session.test.ts, on real HQC-256 (the
//! TS suite uses a stub KEM; HQC's implicit rejection is the real thing
//! here). The payload is sealed with the message key and opened in
//! `verify`, which is what makes a forged key fail.

use std::collections::HashMap;

use hqc::{KeyPair, SecretKey};
use hqchat_protocol::aead;
use hqchat_protocol::ratchet::{self, MessageHeader, PrekeyBundle, PrekeySecrets, SessionState};
use hqchat_protocol::{HqcKem, Kem, OsEntropy};

const KEM: HqcKem = HqcKem;
const NOW: i64 = 1_700_000_000_000;

struct Peer {
    identity: KeyPair,
    medium: KeyPair,
    one_time: HashMap<u32, SecretKey>,
    bundle: PrekeyBundle,
}

impl PrekeySecrets for Peer {
    fn identity_sk(&self) -> &SecretKey {
        &self.identity.secret
    }
    fn medium_sk(&self) -> &SecretKey {
        &self.medium.secret
    }
    fn one_time_sk(&self, id: u32) -> Option<&SecretKey> {
        self.one_time.get(&id)
    }
}

fn peer(with_one_time: bool) -> Peer {
    let identity = KEM.generate_keypair().unwrap();
    let medium = KEM.generate_keypair().unwrap();
    let mut one_time = HashMap::new();
    let mut ot_bundle = None;
    if with_one_time {
        let ot = KEM.generate_keypair().unwrap();
        ot_bundle = Some((ot.public.clone(), 7));
        one_time.insert(7, ot.secret);
    }
    let bundle = PrekeyBundle {
        identity_pk: identity.public.clone(),
        medium_pk: medium.public.clone(),
        one_time: ot_bundle,
    };
    Peer {
        identity,
        medium,
        one_time,
        bundle,
    }
}

/// Alice's session to Bob, Bob's from Alice's first message, and that message.
fn pair() -> (SessionState, SessionState) {
    let bob = peer(true);
    let (mut alice, init) = ratchet::start_as_initiator(&KEM, &bob.bundle, NOW).unwrap();
    let first = send(&mut alice, "hello", NOW);
    let mut bob_state = ratchet::start_as_responder(&KEM, &bob, &init, NOW).unwrap();
    assert_eq!(receive(&mut bob_state, &first).as_deref(), Some("hello"));
    (alice, bob_state)
}

struct Sent {
    header: MessageHeader,
    sealed: Vec<u8>,
}

fn send(state: &mut SessionState, text: &str, now: i64) -> Sent {
    let s = ratchet::seal(&KEM, state, now).unwrap();
    let sealed = aead::seal_payload(text.as_bytes(), &s.key.0, b"", &mut OsEntropy).unwrap();
    Sent {
        header: s.header,
        sealed,
    }
}

fn receive(state: &mut SessionState, sent: &Sent) -> Option<String> {
    let mut text = None;
    ratchet::open(
        &KEM,
        state,
        &sent.header,
        &mut |k| match aead::open_payload(&sent.sealed, &k.0, b"") {
            Ok(p) => {
                text = Some(String::from_utf8(p).unwrap());
                true
            }
            Err(_) => false,
        },
    )?;
    text
}

#[test]
fn the_first_message_needs_no_round_trip_and_carries_the_init() {
    let bob = peer(true);
    let (mut alice, init) = ratchet::start_as_initiator(&KEM, &bob.bundle, NOW).unwrap();
    let sealed = ratchet::seal(&KEM, &mut alice, NOW).unwrap();
    assert_eq!(
        sealed.init.as_ref(),
        Some(&init),
        "seal reports the init until the peer answers"
    );
    assert_eq!(sealed.header.cid, init.cid);
    assert!(
        sealed.header.rk.is_none(),
        "the init carries rk; the first msg does not step"
    );
}

#[test]
fn a_conversation_steps_on_direction_flips_and_stays_in_step() {
    let (mut alice, mut bob) = pair();
    let reply = send(&mut bob, "hi alice", NOW);
    assert!(
        reply.header.rk.is_some(),
        "Bob's first send steps against Alice's key"
    );
    assert_eq!(receive(&mut alice, &reply).as_deref(), Some("hi alice"));
    assert!(
        alice.pending_init.is_none(),
        "the reply retires the pending init"
    );
    for turn in 0..4 {
        let a = send(&mut alice, &format!("a{turn}"), NOW);
        assert_eq!(
            receive(&mut bob, &a).as_deref(),
            Some(format!("a{turn}").as_str())
        );
        let b = send(&mut bob, &format!("b{turn}"), NOW);
        assert_eq!(
            receive(&mut alice, &b).as_deref(),
            Some(format!("b{turn}").as_str())
        );
    }
}

#[test]
fn a_rapid_exchange_does_not_step_every_turn_but_the_cap_forces_steps() {
    let (mut alice, mut bob) = pair();
    let first = send(&mut bob, "r0", NOW);
    assert!(
        first.header.rk.is_some(),
        "Bob's first reply steps: he has no sending chain"
    );
    receive(&mut alice, &first).unwrap();

    // Inside the interval and under the cap, the chain continues.
    for i in 0..10 {
        let f = send(&mut bob, &format!("r{}", i + 1), NOW + 1000);
        assert!(f.header.rk.is_none(), "msg {i} does not step");
        receive(&mut alice, &f).unwrap();
    }

    // The cap forces steps during a long run, even with the clock frozen.
    let run = ratchet::RATCHET_MAX_MESSAGES_PER_CHAIN * 3;
    let mut steps = 0;
    for i in 0..run {
        let f = send(&mut bob, &format!("bulk{i}"), NOW + 1000);
        if f.header.rk.is_some() {
            steps += 1;
        }
        assert_eq!(
            receive(&mut alice, &f),
            Some(format!("bulk{i}")),
            "bulk {i} opens"
        );
    }
    assert!(
        steps >= 2,
        "the cap forced {steps} steps over {run} messages"
    );
    assert!(
        steps <= run / ratchet::RATCHET_MAX_MESSAGES_PER_CHAIN + 1,
        "no more often than the cap"
    );
}

#[test]
fn the_step_policy_is_count_first_with_time_as_the_backstop() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "hello", NOW)).unwrap();
    let interval = ratchet::RATCHET_MIN_STEP_INTERVAL_MS;

    let fresh = SessionState {
        sent_on_chain: 0,
        ..alice.clone()
    };
    assert!(
        !ratchet::should_step(&fresh, NOW + interval * 10),
        "an unused chain never steps"
    );

    let busy = SessionState {
        sent_on_chain: ratchet::RATCHET_MAX_MESSAGES_PER_CHAIN,
        chain_started_at: NOW,
        ..alice.clone()
    };
    assert!(
        ratchet::should_step(&busy, NOW + 1),
        "a chain at the cap steps immediately"
    );

    let slow = SessionState {
        sent_on_chain: 1,
        chain_started_at: NOW,
        ..alice
    };
    assert!(
        !ratchet::should_step(&slow, NOW + 5 * 60_000),
        "a reply 5 minutes later is cheap"
    );
    assert!(
        !ratchet::should_step(&slow, NOW + 10 * 60_000),
        "and one at 10 minutes"
    );
    assert!(
        ratchet::should_step(&slow, NOW + interval),
        "the backstop fires"
    );
}

#[test]
fn out_of_order_delivery_resolves_across_a_step() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    let m: Vec<Sent> = (0..3)
        .map(|i| send(&mut alice, &format!("m{i}"), NOW))
        .collect();
    assert_eq!(receive(&mut bob, &m[2]).as_deref(), Some("m2"));
    assert_eq!(receive(&mut bob, &m[0]).as_deref(), Some("m0"));
    assert_eq!(receive(&mut bob, &m[1]).as_deref(), Some("m1"));
}

#[test]
fn a_replayed_frame_yields_nothing_the_second_time() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    let m = send(&mut alice, "once", NOW);
    assert_eq!(receive(&mut bob, &m).as_deref(), Some("once"));
    assert_eq!(receive(&mut bob, &m), None);
}

#[test]
fn a_hostile_n_is_refused_without_walking() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    let mut m = send(&mut alice, "far", NOW);
    let before = bob.recv.as_ref().unwrap().n;
    m.header.n = u32::MAX;
    assert_eq!(receive(&mut bob, &m), None);
    assert_eq!(
        bob.recv.as_ref().unwrap().n,
        before,
        "nothing walked or committed"
    );
}

#[test]
fn a_forged_step_cannot_destroy_a_live_session() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    // An attacker encapsulates to Bob's public ratchet key and announces a key
    // of their own: the step decapsulates, but the attacker cannot know the
    // root, so no payload they seal verifies.
    let mallory = KEM.generate_keypair().unwrap();
    let (ct, _) = KEM.encapsulate(&bob.rk.public).unwrap();
    let forged = Sent {
        header: MessageHeader {
            cid: ratchet::chain_id(mallory.public.as_bytes()),
            rk: Some(mallory.public),
            kem_ct: Some(ct),
            n: 0,
            pn: 0,
        },
        sealed: aead::seal_payload(b"evil", &[7; 32], b"", &mut OsEntropy).unwrap(),
    };
    let root_before = bob.root.clone();
    assert_eq!(receive(&mut bob, &forged), None);
    assert_eq!(bob.root, root_before, "the root is untouched");
    let m = send(&mut alice, "still here", NOW);
    assert_eq!(receive(&mut bob, &m).as_deref(), Some("still here"));
}

#[test]
fn a_cached_key_is_not_burned_by_a_frame_that_fails_to_authenticate() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    let m0 = send(&mut alice, "m0", NOW);
    let m1 = send(&mut alice, "m1", NOW);
    receive(&mut bob, &m1).unwrap();
    let tampered = Sent {
        header: m0.header.clone(),
        sealed: vec![0; m0.sealed.len()],
    };
    assert_eq!(receive(&mut bob, &tampered), None);
    assert_eq!(
        receive(&mut bob, &m0).as_deref(),
        Some("m0"),
        "the genuine late frame still opens"
    );
}

#[test]
fn a_gap_past_max_skipped_is_refused_rather_than_bridged() {
    assert!(
        ratchet::walk_chain(
            &ratchet::SymmetricKey([1; 32]),
            0,
            ratchet::MAX_SKIPPED as u32 + 1
        )
        .is_err()
    );
    assert!(ratchet::walk_chain(&ratchet::SymmetricKey([1; 32]), 5, 4).is_err());
}

#[test]
fn an_exhausted_pool_still_starts_a_session_and_a_consumed_one_time_key_is_refused() {
    let bob = peer(false);
    let (mut alice, init) = ratchet::start_as_initiator(&KEM, &bob.bundle, NOW).unwrap();
    assert!(init.one_time.is_none());
    let first = send(&mut alice, "no pool", NOW);
    let mut bob_state = ratchet::start_as_responder(&KEM, &bob, &init, NOW).unwrap();
    assert_eq!(receive(&mut bob_state, &first).as_deref(), Some("no pool"));

    let mut bob2 = peer(true);
    let (_, init2) = ratchet::start_as_initiator(&KEM, &bob2.bundle, NOW).unwrap();
    bob2.one_time.clear();
    assert!(ratchet::start_as_responder(&KEM, &bob2, &init2, NOW).is_none());
}

#[test]
fn a_frame_naming_a_retired_chain_is_refused() {
    let (mut alice, mut bob) = pair();
    let b0 = send(&mut bob, "b0", NOW);
    receive(&mut alice, &b0).unwrap();
    receive(&mut bob, &send(&mut alice, "a0", NOW)).unwrap();
    receive(&mut alice, &send(&mut bob, "b1", NOW)).unwrap();
    // b0's chain is retired on Alice's side: replaying its step is refused.
    assert_eq!(receive(&mut alice, &b0), None);
    let m = send(&mut bob, "after", NOW);
    assert_eq!(receive(&mut alice, &m).as_deref(), Some("after"));
}

#[test]
fn stragglers_from_the_previous_chain_resolve_after_the_receiver_moved_on() {
    let (mut alice, mut bob) = pair();
    receive(&mut alice, &send(&mut bob, "x", NOW)).unwrap();
    let old: Vec<Sent> = (0..2)
        .map(|i| send(&mut alice, &format!("old{i}"), NOW))
        .collect();
    receive(&mut alice, &send(&mut bob, "y", NOW))
        .ok_or(())
        .ok();
    let late_step = send(
        &mut alice,
        "new",
        NOW + ratchet::RATCHET_MIN_STEP_INTERVAL_MS,
    );
    assert!(late_step.header.rk.is_some());
    assert_eq!(receive(&mut bob, &late_step).as_deref(), Some("new"));
    assert_eq!(receive(&mut bob, &old[1]).as_deref(), Some("old1"));
    assert_eq!(receive(&mut bob, &old[0]).as_deref(), Some("old0"));
}
