//! Every decoder that reads bytes off the network, fed mutations of real
//! frames (bit flips, truncations, extensions, rewritten length prefixes)
//! and random bytes: none may panic, and whatever one accepts must encode
//! back to what it read. A stable-toolchain stand-in for cargo-fuzz, which
//! needs nightly; deterministic, so a failure reproduces.

use hqchat_protocol::{envelope, handshake, mqtt, mqtt_proof, noise};
use serde_json::Value;

/// A small deterministic generator (xorshift64*), so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Mutations of `seed`: flips, truncations, extensions, overwritten spans.
fn mutations(seed: &[u8], rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut b = seed.to_vec();
        match rng.below(5) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 => b.truncate(rng.below(b.len() + 1)),
            2 => b.extend((0..rng.below(64)).map(|_| rng.next() as u8)),
            3 if b.len() >= 4 => {
                let i = rng.below(b.len() - 3);
                b[i..i + 4].copy_from_slice(&(rng.next() as u32).to_be_bytes());
            }
            _ => b = (0..rng.below(256)).map(|_| rng.next() as u8).collect(),
        }
        out.push(b);
    }
    out
}

fn vector_bytes(file: &str, pick: impl Fn(&Value) -> Vec<String>) -> Vec<Vec<u8>> {
    let text = std::fs::read_to_string(format!(
        "{}/../../services/server/test/helpers/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    pick(&serde_json::from_str(&text).unwrap())
        .into_iter()
        .map(|h| hex::decode(h).unwrap())
        .collect()
}

#[test]
fn the_frame_decoder_survives_mutations_of_every_vector_frame() {
    let seeds = vector_bytes("envelope-v3-vectors.json", |v| {
        v["cases"]
            .as_object()
            .unwrap()
            .values()
            .map(|c| c["frameHex"].as_str().unwrap().to_owned())
            .collect()
    });
    let mut rng = Rng(0x5eed_0001);
    for seed in &seeds {
        for m in mutations(seed, &mut rng, 400) {
            if let Ok((frame, aad)) = envelope::decode(&m) {
                assert_eq!(
                    envelope::encode(&frame).unwrap(),
                    m,
                    "accepted bytes must re-encode exactly"
                );
                assert!(m.starts_with(&aad));
            }
        }
    }
}

#[test]
fn the_handshake_decoder_survives_mutations() {
    let seeds = vector_bytes("handshake-vectors.json", |v| {
        vec![
            v["frames"]["challenge"]["frameHex"]
                .as_str()
                .unwrap()
                .to_owned(),
            v["frames"]["proof"]["frameHex"]
                .as_str()
                .unwrap()
                .to_owned(),
        ]
    });
    let mut rng = Rng(0x5eed_0002);
    for seed in &seeds {
        for m in mutations(seed, &mut rng, 1000) {
            if let Ok(frame) = handshake::decode(&m) {
                assert_eq!(handshake::encode(&frame).unwrap(), m);
            }
        }
    }
}

#[test]
fn the_mqtt_decoder_survives_mutated_streams() {
    let seeds: Vec<Vec<u8>> = {
        let text = include_str!("fixtures/mqtt-packet-9.0.2.json");
        let v: Value = serde_json::from_str(text).unwrap();
        v.as_object()
            .unwrap()
            .iter()
            .filter(|(k, val)| {
                !k.starts_with('_') && *k != "generator" && *k != "bigHead" && val.is_string()
            })
            .map(|(_, h)| hex::decode(h.as_str().unwrap()).unwrap())
            .collect()
    };
    let mut rng = Rng(0x5eed_0003);
    for seed in &seeds {
        for m in mutations(seed, &mut rng, 300) {
            let mut d = mqtt::Decoder::default();
            d.push(&m);
            while let Ok(Some(p)) = d.next_packet() {
                if matches!(p, mqtt::Packet::Oversized { .. }) {
                    continue;
                }
                let again = mqtt::encode(&p).expect("a decoded packet encodes");
                let mut back = mqtt::Decoder::default();
                back.push(&again);
                assert_eq!(back.next_packet().unwrap(), Some(p));
            }
        }
    }
}

#[test]
fn the_connect_password_parser_survives_mutations() {
    let text = std::fs::read_to_string(format!(
        "{}/../../services/server/test/helpers/mqtt-proof-vectors.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let mut rng = Rng(0x5eed_0004);
    for c in v["cases"].as_array().unwrap() {
        let seed = c["connectField"].as_str().unwrap().as_bytes();
        for m in mutations(seed, &mut rng, 1000) {
            let Ok(s) = std::str::from_utf8(&m) else {
                continue;
            };
            if let Some(p) = mqtt_proof::parse_password(s) {
                assert_eq!(
                    mqtt_proof::format_password(&p),
                    s,
                    "one proof, one password"
                );
            }
        }
    }
}

#[test]
fn the_hqn_frame_reader_survives_any_stream() {
    let mut rng = Rng(0x5eed_0005);
    for _ in 0..500 {
        let mut r = noise::FrameReader::default();
        let stream: Vec<u8> = (0..rng.below(4096)).map(|_| rng.next() as u8).collect();
        for chunk in stream.chunks(rng.below(300) + 1) {
            r.push(chunk);
            while let Some(frame) = r.next_frame() {
                assert!(frame.len() <= noise::MAX_FRAME);
            }
        }
        assert!(r.pending() <= 2 + noise::MAX_FRAME);
    }
}
