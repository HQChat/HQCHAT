//! Importing another implementation's state (the TS bot's file, later the
//! Apple app's): the identity a seed derives, and sessions that keep working.

mod support;

use std::sync::Arc;

use hqc::{KeyPair, SecretKey};
use hqchat_engine::software::{MemoryStore, SoftwareVault};
use hqchat_engine::{
    CoreError, Delivery, Effect, Engine, Import, ImportIdentity, ImportMessage, ImportPeer,
    ImportPending,
};
use hqchat_protocol::ratchet::{self, PrekeyBundle, PrekeySecrets};
use hqchat_protocol::{HqcKem, PeerId};
use support::{Client, FakeServer, NOW, User, settle};

fn seed(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn identity(fill: u8) -> KeyPair {
    hqc::keypair_from_seed(&hqc::Seed::from_bytes(seed(fill))).unwrap()
}

fn only_seed(fill: u8) -> Import {
    Import {
        identity: ImportIdentity::Seed(seed(fill)),
        prekeys: None,
        peers: vec![],
        messages: vec![],
        pending: vec![],
    }
}

#[test]
fn a_seed_imports_as_the_identity_it_derives_and_survives_a_restart() {
    let vault = Arc::new(SoftwareVault::default());
    let store = Arc::new(MemoryStore::default());
    let engine = Engine::new(support::config("p"), vault.clone(), store.clone()).unwrap();
    assert_eq!(
        engine.import(only_seed(9), 0).unwrap(),
        vec![Effect::TierChanged(hqchat_engine::Tier::Software)]
    );
    assert!(
        engine.create_identity().is_err(),
        "an imported profile has its identity"
    );
    assert!(engine.import(only_seed(9), 0).is_err(), "imports once");

    let restarted = Engine::new(support::config("p"), vault, store).unwrap();
    restarted.unlock(0).unwrap();
    let peer = PeerId::of(&identity(1).public).to_string();
    assert_eq!(restarted.history(peer, None, 1), Ok(vec![]));
}

#[test]
fn a_key_that_does_not_hash_to_its_peer_is_refused_and_nothing_is_kept() {
    let store = Arc::new(MemoryStore::default());
    let engine = Engine::new(
        support::config("p"),
        Arc::new(SoftwareVault::default()),
        store.clone(),
    )
    .unwrap();
    let mut import = only_seed(9);
    import.peers.push(ImportPeer {
        id: PeerId::of(&identity(1).public).to_string(),
        username: None,
        convo_id: None,
        handshake_id: None,
        pinned_pk: Some(identity(2).public.as_bytes().to_vec()),
        session: None,
    });
    assert!(matches!(engine.import(import, 0), Err(CoreError::State(_))));
    assert!(store.snapshot().is_empty(), "nothing was written");
    engine
        .import(only_seed(9), 0)
        .expect("a refused import can be redone");
}

/// Bob's prekey secrets, as `start_as_responder` reads them.
struct Secrets {
    identity: SecretKey,
    medium: SecretKey,
}

impl PrekeySecrets for Secrets {
    fn identity_sk(&self) -> &SecretKey {
        &self.identity
    }
    fn medium_sk(&self) -> &SecretKey {
        &self.medium
    }
    fn one_time_sk(&self, _id: u32) -> Option<&SecretKey> {
        None
    }
}

#[test]
fn imported_sessions_keep_the_conversation_going_both_ways() {
    // A session two other clients opened before moving to the core: alice
    // started it, bob answered.
    let (alice_id, bob_id) = (identity(1), identity(2));
    let medium = hqc::generate_keypair().unwrap();
    let bundle = PrekeyBundle {
        identity_pk: bob_id.public.clone(),
        medium_pk: medium.public.clone(),
        one_time: None,
    };
    let (alice_session, init) = ratchet::start_as_initiator(&HqcKem, &bundle, NOW).unwrap();
    let secrets = Secrets {
        identity: bob_id.secret.clone(),
        medium: medium.secret.clone(),
    };
    let bob_session = ratchet::start_as_responder(&HqcKem, &secrets, &init, NOW).unwrap();

    // The server already knows both accounts and their friendship.
    let server = FakeServer::shared();
    let (a, b) = (
        PeerId::of(&alice_id.public).to_string(),
        PeerId::of(&bob_id.public).to_string(),
    );
    let (convo, handshake) = {
        let mut s = server.borrow_mut();
        for k in [&alice_id, &bob_id] {
            s.users.insert(
                PeerId::of(&k.public).to_string(),
                User {
                    pk_hex: hex::encode(k.public.as_bytes()),
                    ..Default::default()
                },
            );
        }
        let f = support::Friendship {
            convo: "c".repeat(64),
            handshake: "d".repeat(64),
        };
        s.friendships.insert(FakeServer::pair_of(&a, &b), f.clone());
        (f.convo, f.handshake)
    };
    let peer = |id: &str, key: &KeyPair, session| ImportPeer {
        id: id.into(),
        username: None,
        convo_id: Some(convo.clone()),
        handshake_id: Some(handshake.clone()),
        pinned_pk: Some(key.public.as_bytes().to_vec()),
        session: Some(session),
    };
    let start = |profile: &str, fill: u8, peers: Vec<ImportPeer>| {
        let mut c = Client::new(&server, profile);
        let e = c
            .engine
            .import(
                Import {
                    identity: ImportIdentity::Seed(seed(fill)),
                    prekeys: None,
                    peers,
                    messages: vec![],
                    pending: vec![],
                },
                NOW,
            )
            .unwrap();
        c.pump(e);
        c.engine_id = PeerId::of(&identity(fill).public).to_string();
        c.start(NOW);
        c
    };
    let alice_copy = alice_session.clone();
    let mut alice = start("a", 1, vec![peer(&b, &bob_id, alice_session)]);
    let mut bob = start("b", 2, vec![peer(&a, &alice_id, bob_session)]);

    let e = bob
        .engine
        .send_text(alice.id(), "from bob".into(), NOW)
        .unwrap();
    bob.pump(e);
    let from_bob = server
        .borrow()
        .broker
        .routed
        .iter()
        .find(|(topic, _)| topic.starts_with("cv/"))
        .cloned()
        .expect("bob's frame went through the broker");
    settle(&mut [&mut alice, &mut bob]);
    let e = alice
        .engine
        .send_text(bob.id(), "from alice".into(), NOW)
        .unwrap();
    alice.pump(e);
    settle(&mut [&mut alice, &mut bob]);

    let received = |c: &Client, from: &Client| -> Vec<String> {
        c.engine
            .history(from.id(), None, 10)
            .unwrap()
            .into_iter()
            .filter(|m| !m.outgoing)
            .map(|m| m.text)
            .collect()
    };
    assert_eq!(received(&alice, &bob), ["from bob"]);
    assert_eq!(received(&bob, &alice), ["from alice"]);
    assert!(
        !server
            .borrow()
            .log
            .iter()
            .any(|(_, path)| path == "/prekeys/claim"),
        "no new session was opened: the imported ones carried both messages"
    );

    // The same message, as a frame the old implementation had kept unopened
    // while locked: the import's drain opens it into the new profile's history.
    let mut later = Client::new(&server, "a-later");
    let e = later
        .engine
        .import(
            Import {
                identity: ImportIdentity::Seed(seed(1)),
                prekeys: None,
                peers: vec![peer(&b, &bob_id, alice_copy)],
                messages: vec![],
                pending: vec![ImportPending {
                    topic: from_bob.0,
                    payload: from_bob.1,
                    at: NOW,
                }],
            },
            NOW,
        )
        .unwrap();
    later.pump(e);
    later.engine_id = a.clone();
    assert_eq!(received(&later, &bob), ["from bob"]);
}

#[test]
fn history_imports_in_order_and_new_messages_sort_after_it() {
    let engine = Engine::new(
        support::config("p"),
        Arc::new(SoftwareVault::default()),
        Arc::new(MemoryStore::default()),
    )
    .unwrap();
    let friend = PeerId::of(&identity(1).public).to_string();
    let message = |id: &str, outgoing, at| ImportMessage {
        peer: friend.clone(),
        msg_id: id.into(),
        outgoing,
        text: format!("text {id}"),
        at,
        delivery: outgoing.then_some(Delivery::Delivered),
    };
    let mut import = only_seed(9);
    import.messages = vec![message("b", false, NOW + 5), message("a", true, NOW)];
    engine.import(import, NOW).unwrap();
    let history = engine.history(friend.clone(), None, 10).unwrap();
    assert_eq!(
        history
            .iter()
            .map(|m| (m.msg_id.as_str(), m.outgoing))
            .collect::<Vec<_>>(),
        [("a", true), ("b", false)]
    );
    assert_eq!(history[0].delivery, Some(Delivery::Delivered));

    let mut bad = only_seed(8);
    bad.messages = vec![ImportMessage {
        peer: "not an id".into(),
        ..message("c", false, NOW)
    }];
    let other = Engine::new(
        support::config("q"),
        Arc::new(SoftwareVault::default()),
        Arc::new(MemoryStore::default()),
    )
    .unwrap();
    assert!(
        other.import(bad, NOW).is_err(),
        "a message for no valid peer refuses the import"
    );
}
