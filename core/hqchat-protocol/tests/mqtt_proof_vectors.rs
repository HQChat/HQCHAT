//! services/server/test/helpers/mqtt-proof-vectors.json, as
//! mqtt-proof.test.ts and MQTTProofTests.swift assert it. Read in place.

use hqchat_protocol::PeerId;
use hqchat_protocol::mqtt_proof::{self, ConnectProof, SigningKey};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../services/server/test/helpers/mqtt-proof-vectors.json");

fn vectors() -> Value {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["context"], mqtt_proof::MQTT_PROOF_CONTEXT);
    assert_eq!(v["skewSeconds"], mqtt_proof::MQTT_PROOF_SKEW_SECONDS);
    v
}

fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn every_case_derives_signs_formats_parses_and_verifies() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for c in cases {
        let label = s(&c["label"]);
        let key = SigningKey::from_seed(bytes(&c["seedHex"]));
        assert_eq!(
            hex::encode(key.public_key()),
            c["publicKeyHex"],
            "{label}: public key"
        );

        let clientid = PeerId::parse(s(&c["clientid"])).unwrap();
        let ts = c["ts"].as_i64().unwrap();
        let nonce: [u8; 16] = bytes(&c["nonceHex"]);
        let message = mqtt_proof::proof_message(&clientid, s(&c["keyId"]), ts, &nonce);
        assert_eq!(hex::encode(&message), c["messageHex"], "{label}: message");

        // Ed25519 is deterministic: the same key and message give the pinned signature.
        let signature: [u8; 64] = bytes(&c["signatureHex"]);
        assert!(
            mqtt_proof::verify_signature(&key.public_key(), &message, &signature),
            "{label}"
        );

        let proof = ConnectProof {
            key_id: s(&c["keyId"]).to_owned(),
            ts,
            nonce,
            signature,
        };
        assert_eq!(
            mqtt_proof::format_password(&proof),
            c["connectField"],
            "{label}: password"
        );
        assert_eq!(
            mqtt_proof::parse_password(s(&c["connectField"])).as_ref(),
            Some(&proof),
            "{label}"
        );
    }
}

#[test]
fn a_signature_does_not_transfer_to_another_clientid_key_id_timestamp_or_nonce() {
    let v = vectors();
    let c = &v["cases"][0];
    let key = SigningKey::from_seed(bytes(&c["seedHex"]));
    let signature: [u8; 64] = bytes(&c["signatureHex"]);
    let clientid = PeerId::parse(s(&c["clientid"])).unwrap();
    let other_client = PeerId::parse(s(&v["cases"][2]["clientid"])).unwrap();
    let ts = c["ts"].as_i64().unwrap();
    let nonce: [u8; 16] = bytes(&c["nonceHex"]);
    let key_id = s(&c["keyId"]);
    for (what, message) in [
        (
            "clientid",
            mqtt_proof::proof_message(&other_client, key_id, ts, &nonce),
        ),
        (
            "key id",
            mqtt_proof::proof_message(&clientid, &"0".repeat(32), ts, &nonce),
        ),
        (
            "timestamp",
            mqtt_proof::proof_message(&clientid, key_id, ts + 1, &nonce),
        ),
        (
            "nonce",
            mqtt_proof::proof_message(&clientid, key_id, ts, &[0; 16]),
        ),
    ] {
        assert!(
            !mqtt_proof::verify_signature(&key.public_key(), &message, &signature),
            "{what}"
        );
    }
}

#[test]
fn the_password_grammar_is_exact() {
    let v = vectors();
    let good = s(&v["cases"][0]["connectField"]);
    assert!(mqtt_proof::parse_password(good).is_some());
    let p: Vec<&str> = good.split('.').collect();
    let (key_id, ts, nonce, sig) = (p[1], p[2], p[3], p[4]);
    let swapped_alphabet = nonce.replace('-', "+").replace('_', "/");
    let bad = [
        String::new(),
        "v1.".into(),
        format!("{good}."),
        format!("{good}="),
        format!("v2.{key_id}.{ts}.{nonce}.{sig}"),
        format!("v1.{}.{ts}.{nonce}.{sig}", key_id.to_uppercase()),
        format!("v1.{}.{ts}.{nonce}.{sig}", &key_id[1..]),
        format!("v1.{key_id}.0{ts}.{nonce}.{sig}"),
        format!("v1.{key_id}.-{ts}.{nonce}.{sig}"),
        format!("v1.{key_id}.1234567890123.{nonce}.{sig}"),
        format!("v1.{key_id}.{ts}.{nonce}==.{sig}"),
        format!("v1.{key_id}.{ts}.{swapped_alphabet}x.{sig}"),
        format!("v1.{key_id}.{ts}.{nonce}.{}", &sig[..sig.len() - 1]),
        format!(" {good}"),
    ];
    for b in bad {
        assert_eq!(mqtt_proof::parse_password(&b), None, "{b:?}");
    }
}

#[test]
fn a_non_canonical_base64url_spelling_is_refused() {
    // 16 bytes is 22 characters with 4 spare bits in the last one; flipping
    // a spare bit decodes to the same bytes and would give a second password.
    let v = vectors();
    let good = s(&v["cases"][0]["connectField"]);
    let p: Vec<&str> = good.split('.').collect();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = alphabet.find(p[3].chars().last().unwrap()).unwrap();
    let twin = alphabet.as_bytes()[last ^ 1] as char;
    let alt = format!(
        "v1.{}.{}.{}{twin}.{}",
        p[1],
        p[2],
        &p[3][..p[3].len() - 1],
        p[4]
    );
    assert_eq!(mqtt_proof::parse_password(&alt), None);
}
