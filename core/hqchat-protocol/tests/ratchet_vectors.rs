//! services/server/test/helpers/double-ratchet-vectors.json: the key
//! schedule, as double-ratchet.test.ts and DoubleRatchetTests.swift assert
//! it. Read in place.

use hqc::SharedSecret;
use hqchat_protocol::ratchet::{self, SymmetricKey};
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../../services/server/test/helpers/double-ratchet-vectors.json");

fn vectors() -> Value {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        v["version"], 2,
        "a v1 vector file would assert the wrong protocol"
    );
    v
}

fn b32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn ss(v: &Value) -> SharedSecret {
    SharedSecret::from_bytes(b32(v))
}

fn key(v: &Value) -> SymmetricKey {
    SymmetricKey(b32(v))
}

fn hex_of(k: &SymmetricKey) -> String {
    hex::encode(k.0)
}

#[test]
fn the_policy_matches_the_shared_contract() {
    let p = &vectors()["policy"];
    assert_eq!(p["maxSkipped"], ratchet::MAX_SKIPPED);
    assert_eq!(
        p["ratchetMinStepIntervalMs"],
        ratchet::RATCHET_MIN_STEP_INTERVAL_MS
    );
    assert_eq!(
        p["ratchetMaxMessagesPerChain"],
        ratchet::RATCHET_MAX_MESSAGES_PER_CHAIN
    );
}

#[test]
fn init_root_matches_with_and_without_a_one_time_prekey() {
    let v = vectors();
    let i = &v["input"];
    let with = ratchet::init_root(&ss(&i["ssId"]), &ss(&i["ssMt"]), Some(&ss(&i["ssOt"])));
    assert_eq!(hex_of(&with.root), v["initRoot"]["withOneTime"]["root"]);
    assert_eq!(hex_of(&with.chain), v["initRoot"]["withOneTime"]["chain"]);
    let without = ratchet::init_root(&ss(&i["ssId"]), &ss(&i["ssMt"]), None);
    assert_eq!(
        hex_of(&without.root),
        v["initRoot"]["withoutOneTime"]["root"]
    );
    assert_eq!(
        hex_of(&without.chain),
        v["initRoot"]["withoutOneTime"]["chain"]
    );
}

#[test]
fn root_step_matches_and_chains_from_the_previous_root() {
    let v = vectors();
    let step_ss = ss(&v["input"]["stepSs"]);
    let first = ratchet::root_step(&key(&v["initRoot"]["withOneTime"]["root"]), &step_ss);
    assert_eq!(hex_of(&first.root), v["rootStep"]["first"]["root"]);
    assert_eq!(hex_of(&first.chain), v["rootStep"]["first"]["chain"]);
    let second = ratchet::root_step(&first.root, &step_ss);
    assert_eq!(hex_of(&second.root), v["rootStep"]["second"]["root"]);
    assert_eq!(hex_of(&second.chain), v["rootStep"]["second"]["chain"]);
}

#[test]
fn message_keys_and_chain_keys_match() {
    let v = vectors();
    let mut ck = key(&v["initRoot"]["withOneTime"]["chain"]);
    for (i, expected) in v["chain"]["messageKeys_0_3"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(
            hex_of(&ratchet::message_key(&ck)),
            *expected,
            "message key {i}"
        );
        ck = ratchet::chain_next(&ck);
    }
    assert_eq!(hex_of(&ck), v["chain"]["afterConsuming_0_3"]);
}

#[test]
fn walk_chain_matches_the_target_and_the_skipped_keys() {
    let v = vectors();
    let w = &v["walkChain"];
    let walk = ratchet::walk_chain(&key(&v["initRoot"]["withOneTime"]["chain"]), 0, 3).unwrap();
    assert_eq!(hex_of(&walk.key), w["messageKey"]);
    assert_eq!(hex_of(&walk.next_ck), w["ck"]);
    assert_eq!(u64::from(walk.next_n), w["nextN"].as_u64().unwrap());
    let skipped = w["skipped"].as_array().unwrap();
    assert_eq!(walk.skipped.len(), skipped.len());
    for ((n, k), want) in walk.skipped.iter().zip(skipped) {
        assert_eq!(u64::from(*n), want["n"].as_u64().unwrap());
        assert_eq!(hex_of(k), want["key"]);
    }
}

#[test]
fn chain_id_matches() {
    let v = vectors();
    let rk = hex::decode(v["input"]["rkPub"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(ratchet::chain_id(&rk)), v["chainId"]["ofRkPub"]);
}
