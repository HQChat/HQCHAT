//! services/server/test/helpers/handshake-vectors.json, as handshake.test.ts
//! and apps/apple/tests/HandshakeTests.swift assert it. Read in place.

use hqc::{Ciphertext, PublicKey, SharedSecret};
use hqchat_protocol::PeerId;
use hqchat_protocol::handshake::{self, HandshakeFrame};
use hqchat_protocol::ratchet::InitHeader;
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../services/server/test/helpers/handshake-vectors.json");

/// The generator's `bytes(label, length)`: SHA-256 of the label, then of each
/// block in turn, concatenated and cut to `length`.
fn bytes(label: &str, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut block: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    while out.len() < length {
        out.extend_from_slice(&block);
        block = Sha256::digest(block).into();
    }
    out.truncate(length);
    out
}

fn arr32(hex_str: &Value) -> [u8; 32] {
    hex::decode(hex_str.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

struct Input {
    challenger: PeerId,
    prover: PeerId,
    nonce: [u8; 32],
    ss: SharedSecret,
    init: InitHeader,
}

fn input(v: &Value) -> Input {
    let i = &v["input"];
    let labels = &i["init"];
    let label = |k: &str| labels[k].as_str().unwrap();
    let ct = |k: &str| Ciphertext::from_bytes(&bytes(label(k), hqc::CIPHERTEXT_BYTES)).unwrap();
    let rk = PublicKey::from_bytes(&bytes(label("rkLabel"), hqc::PUBLIC_KEY_BYTES)).unwrap();
    Input {
        challenger: PeerId::parse(i["challenger"].as_str().unwrap()).unwrap(),
        prover: PeerId::parse(i["prover"].as_str().unwrap()).unwrap(),
        nonce: arr32(&i["nonceHex"]),
        ss: SharedSecret::from_bytes(arr32(&i["ssHex"])),
        init: InitHeader {
            ct_id: ct("ctIdLabel"),
            ct_mt: ct("ctMtLabel"),
            one_time: Some((ct("ctOtLabel"), labels["otId"].as_u64().unwrap() as u32)),
            cid: [0; 16], // not in the transcript; the generator uses zeros
            rk,
        },
    }
}

fn vectors() -> Value {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], u64::from(handshake::HANDSHAKE_VERSION));
    v
}

#[test]
fn the_generator_labels_derive_the_pinned_ids() {
    let v = vectors();
    let id = |label| PeerId::of_hex(&hex::encode(bytes(label, hqc::PUBLIC_KEY_BYTES)));
    assert_eq!(
        id("hqchat/handshake-vector/challenger").as_str(),
        v["input"]["challenger"]
    );
    assert_eq!(
        id("hqchat/handshake-vector/prover").as_str(),
        v["input"]["prover"]
    );
}

#[test]
fn transcripts_match_with_and_without_a_one_time_prekey() {
    let v = vectors();
    let mut i = input(&v);
    let t = handshake::init_transcript(&i.prover, &i.challenger, &i.init);
    assert_eq!(hex::encode(t), v["transcriptHex"]);
    i.init.one_time = None;
    let t = handshake::init_transcript(&i.prover, &i.challenger, &i.init);
    assert_eq!(hex::encode(t), v["transcriptNoOneTimeHex"]);
}

#[test]
fn the_proof_matches_and_binds_both_ids_in_order() {
    let v = vectors();
    let i = input(&v);
    let t = handshake::init_transcript(&i.prover, &i.challenger, &i.init);
    let proof = handshake::handshake_proof(&i.ss, &i.nonce, &i.challenger, &i.prover, &t);
    assert_eq!(hex::encode(proof), v["proofHex"]);
    assert_eq!(v["proofBytes"], handshake::PROOF_BYTES);
    let swapped = handshake::handshake_proof(&i.ss, &i.nonce, &i.prover, &i.challenger, &t);
    assert_eq!(hex::encode(swapped), v["proofSwappedHex"]);
}

#[test]
fn the_pinned_frames_encode_and_decode_byte_for_byte() {
    let v = vectors();
    let i = input(&v);
    let t = handshake::init_transcript(&i.prover, &i.challenger, &i.init);
    let frames = &v["frames"];

    let challenge = HandshakeFrame::Challenge {
        from: i.challenger.clone(),
        to: i.prover.clone(),
        nonce: i.nonce,
        ct: hex::decode(frames["challenge"]["ctHex"].as_str().unwrap()).unwrap(),
    };
    let raw = hex::decode(frames["challenge"]["frameHex"].as_str().unwrap()).unwrap();
    assert_eq!(handshake::encode(&challenge).unwrap(), raw);
    assert_eq!(handshake::decode(&raw).unwrap(), challenge);

    let proof = HandshakeFrame::Proof {
        from: i.prover.clone(),
        to: i.challenger.clone(),
        nonce: i.nonce,
        proof: handshake::handshake_proof(&i.ss, &i.nonce, &i.challenger, &i.prover, &t),
    };
    let raw = hex::decode(frames["proof"]["frameHex"].as_str().unwrap()).unwrap();
    assert_eq!(handshake::encode(&proof).unwrap(), raw);
    assert_eq!(handshake::decode(&raw).unwrap(), proof);
}
