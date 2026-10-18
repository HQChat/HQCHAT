//! hqn/1 against noise-hqn-vectors.json (shared with noise.test.ts and
//! NoiseHQNTests.swift), the Noise core against the published
//! Noise_NK_25519_ChaChaPoly_SHA256 vector, X25519 against RFC 7748, and the
//! behaviour of noise.test.ts on real HQC-256. Vector files are read in place.

use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey, SharedSecret};
use hqchat_protocol::noise::{self, HqnInitiator, HqnResponder, ServerStatic, X25519Secret};
use hqchat_protocol::{Entropy, Error, HqcKem, Kem, OsEntropy};
use serde_json::Value;
use sha2::{Digest, Sha256};

const HQN: &str = include_str!("../../../services/server/test/helpers/noise-hqn-vectors.json");
const NK: &str = include_str!("../../../services/server/test/helpers/noise-nk-cacophony.json");

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn secret(v: &Value) -> X25519Secret {
    X25519Secret(h(v).try_into().unwrap())
}

/// Hands out pinned bytes in order: the ephemeral keys the vectors fix.
struct Fixed(Vec<u8>);

impl Entropy for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let rest = self.0.split_off(buf.len());
        buf.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

/// The KEM with its one random draw pinned, as the vectors fix it.
struct PinnedKem {
    ct: Vec<u8>,
    ss: [u8; 32],
}

impl Kem for PinnedKem {
    fn generate_keypair(&self) -> Result<KeyPair, Error> {
        Err(Error::Invalid("not used"))
    }
    fn encapsulate(&self, _pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
        Ok((
            Ciphertext::from_bytes(&self.ct)?,
            SharedSecret::from_bytes(self.ss),
        ))
    }
    fn decapsulate(&self, _sk: &SecretKey, _ct: &Ciphertext) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from_bytes(self.ss))
    }
}

#[test]
fn the_core_matches_the_published_noise_nk_vector() {
    let v = &serde_json::from_str::<Value>(NK).unwrap()["vector"];
    let prologue = h(&v["init_prologue"]);
    let (init_e, resp_e, resp_s) = (
        secret(&v["init_ephemeral"]),
        secret(&v["resp_ephemeral"]),
        secret(&v["resp_static"]),
    );
    assert_eq!(resp_s.public_key().to_vec(), h(&v["init_remote_static"]));
    let m = v["messages"].as_array().unwrap();

    let (m1, mut is) = noise::nk_initiator_message1(
        &prologue,
        &resp_s.public_key(),
        &init_e,
        &h(&m[0]["payload"]),
    )
    .unwrap();
    assert_eq!(m1, h(&m[0]["ciphertext"]), "message 1");
    let (payload1, m2, rs) =
        noise::nk_responder_message2(&prologue, &resp_s, &m1, &resp_e, &h(&m[1]["payload"]))
            .unwrap();
    assert_eq!(payload1, h(&m[0]["payload"]));
    assert_eq!(m2, h(&m[1]["ciphertext"]), "message 2");
    let re: [u8; 32] = m2[..32].try_into().unwrap();
    is.mix_hash(&re);
    is.mix_key(&noise::dh(&init_e, &re).unwrap());
    assert_eq!(is.decrypt_and_hash(&m2[32..]).unwrap(), h(&m[1]["payload"]));
    assert_eq!(is.h.to_vec(), h(&v["handshake_hash"]));
    assert_eq!(rs.h.to_vec(), h(&v["handshake_hash"]));

    let (mut i_send, mut i_recv) = is.split();
    let (mut r_recv, mut r_send) = rs.split();
    for (i, msg) in m.iter().enumerate().skip(2) {
        let (send, recv) = if i % 2 == 0 {
            (&mut i_send, &mut r_recv)
        } else {
            (&mut r_send, &mut i_recv)
        };
        let ct = send.encrypt(&h(&msg["payload"])).unwrap();
        assert_eq!(ct, h(&msg["ciphertext"]), "transport message {i}");
        assert_eq!(recv.decrypt(&ct).unwrap(), h(&msg["payload"]));
    }
}

#[test]
fn x25519_matches_rfc_7748() {
    let alice = secret(&Value::from(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = secret(&Value::from(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    assert_eq!(
        hex::encode(alice.public_key()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(bob.public_key()),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    assert_eq!(
        hex::encode(noise::dh(&alice, &bob.public_key()).unwrap()),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
}

#[test]
fn the_hqn_vectors_reproduce_byte_for_byte() {
    let v: Value = serde_json::from_str(HQN).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["protocolName"], noise::HQN_PROTOCOL_NAME);
    assert_eq!(v["prologueLabel"], noise::HQN_PROLOGUE_LABEL);
    assert_eq!(v["hqnVersion"], noise::HQN_VERSION);
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let label = c["label"].as_str().unwrap();
        let kem = PinnedKem {
            ct: h(&c["kemCiphertextHex"]),
            ss: h(&c["kemSharedSecretHex"]).try_into().unwrap(),
        };
        let server = ServerStatic {
            key_id: c["keyId"].as_u64().unwrap() as u8,
            x25519: secret(&c["serverStaticPrivHex"]),
            hqc: KeyPair {
                public: PublicKey::from_bytes(&h(&c["serverHqcPublicHex"])).unwrap(),
                secret: SecretKey::from_bytes(&[0; hqc::SECRET_KEY_BYTES]).unwrap(),
            },
        };
        assert_eq!(
            server.public().x25519.to_vec(),
            h(&c["serverStaticPubHex"]),
            "{label}"
        );

        let mut client =
            HqnInitiator::new(server.public(), &mut Fixed(h(&c["clientEphemeralPrivHex"])))
                .unwrap();
        let payload1 = h(&c["payload1Hex"]);
        let msg1 = client.write_message1(&kem, &payload1).unwrap();
        assert_eq!(
            msg1.len() as u64,
            c["msg1Length"].as_u64().unwrap(),
            "{label}: msg1 length"
        );
        assert_eq!(msg1.len(), noise::msg1_length(payload1.len()));
        assert_eq!(
            hex::encode(Sha256::digest(&msg1)),
            c["msg1Sha256"],
            "{label}: msg1"
        );
        assert!(
            hex::encode(&msg1).starts_with(c["msg1HeadHex"].as_str().unwrap()),
            "{label}"
        );

        let mut responder = HqnResponder::new(server);
        assert_eq!(
            responder.read_message1(&kem, &msg1).unwrap(),
            payload1,
            "{label}: payload 1"
        );
        let (msg2, mut down) = responder
            .write_message2(
                &h(&c["payload2Hex"]),
                &mut Fixed(h(&c["serverEphemeralPrivHex"])),
            )
            .unwrap();
        assert_eq!(msg2, h(&c["msg2Hex"]), "{label}: msg2");
        let (payload2, mut up) = client.read_message2(&msg2).unwrap();
        assert_eq!(payload2, h(&c["payload2Hex"]), "{label}: payload 2");
        assert_eq!(
            up.handshake_hash.to_vec(),
            h(&c["handshakeHashHex"]),
            "{label}: handshake hash"
        );
        assert_eq!(down.handshake_hash, up.handshake_hash);

        let plain = h(&c["transportPlainHex"]);
        assert_eq!(
            up.send.encrypt(&plain).unwrap(),
            h(&c["transportUpHex"]),
            "{label}: upstream"
        );
        assert_eq!(
            down.send.encrypt(&plain).unwrap(),
            h(&c["transportDownHex"]),
            "{label}: downstream"
        );
    }
}

// ── Behaviour, on real HQC-256 ──────────────────────────────────────────────

fn server(key_id: u8) -> ServerStatic {
    ServerStatic {
        key_id,
        x25519: X25519Secret::generate(&mut OsEntropy).unwrap(),
        hqc: HqcKem.generate_keypair().unwrap(),
    }
}

fn msg1_for(s: &ServerStatic, payload: &[u8]) -> (HqnInitiator, Vec<u8>) {
    let mut client = HqnInitiator::new(s.public(), &mut OsEntropy).unwrap();
    let msg1 = client.write_message1(&HqcKem, payload).unwrap();
    (client, msg1)
}

#[test]
fn a_real_handshake_carries_both_payloads_and_each_direction_has_its_own_key() {
    let s = server(1);
    let (client, msg1) = msg1_for(&s, b"CONNECT");
    assert!(
        !msg1.windows(7).any(|w| w == b"CONNECT"),
        "the payload is not visible on the wire"
    );
    let mut responder = HqnResponder::new(s);
    assert_eq!(responder.read_message1(&HqcKem, &msg1).unwrap(), b"CONNECT");
    let (msg2, mut down) = responder.write_message2(b"ok", &mut OsEntropy).unwrap();
    let (payload2, mut up) = client.read_message2(&msg2).unwrap();
    assert_eq!(payload2, b"ok");
    let a = up.send.encrypt(b"same").unwrap();
    let b = down.send.encrypt(b"same").unwrap();
    assert_ne!(a, b, "each direction has its own key");
    assert_eq!(down.recv.decrypt(&a).unwrap(), b"same");
    assert_eq!(up.recv.decrypt(&b).unwrap(), b"same");
}

#[test]
fn a_bit_flip_anywhere_in_msg1_is_refused() {
    let s = server(1);
    let (_, msg1) = msg1_for(&s, b"CONNECT");
    for i in [
        0,
        31,
        32,
        100,
        32 + hqc::CIPHERTEXT_BYTES + 15,
        msg1.len() - 1,
    ] {
        let mut flipped = msg1.clone();
        flipped[i] ^= 1;
        let mut r = HqnResponder::new(s.clone());
        assert!(r.read_message1(&HqcKem, &flipped).is_err(), "flip at {i}");
    }
}

#[test]
fn a_bit_flip_in_msg2_is_refused() {
    let s = server(1);
    let (client, msg1) = msg1_for(&s, b"C");
    let mut r = HqnResponder::new(s);
    r.read_message1(&HqcKem, &msg1).unwrap();
    let (mut msg2, _) = r.write_message2(b"", &mut OsEntropy).unwrap();
    let last = msg2.len() - 1;
    msg2[last] ^= 1;
    assert!(client.read_message2(&msg2).is_err());
}

#[test]
fn the_wrong_server_key_or_key_id_cannot_complete() {
    let s = server(1);
    let (_, msg1) = msg1_for(&s, b"C");
    let other_id = ServerStatic {
        key_id: 2,
        ..s.clone()
    };
    assert!(
        HqnResponder::new(other_id)
            .read_message1(&HqcKem, &msg1)
            .is_err(),
        "key id in the prologue"
    );
    assert!(
        HqnResponder::new(server(1))
            .read_message1(&HqcKem, &msg1)
            .is_err(),
        "another server"
    );
}

#[test]
fn random_bytes_fail_phase_one_and_never_reach_decapsulation() {
    let mut random = vec![0u8; noise::msg1_length(7)];
    OsEntropy.fill(&mut random).unwrap();
    let mut r = HqnResponder::new(server(1));
    assert_eq!(r.open_message1(&random).unwrap_err(), Error::Authentication);
}

#[test]
fn a_short_msg1_is_refused_before_any_cryptography() {
    let mut r = HqnResponder::new(server(1));
    assert!(matches!(
        r.open_message1(&[0; 100]),
        Err(Error::Malformed(_))
    ));
    assert!(HqnResponder::ephemeral_of(&[0; 31]).is_err());
}

#[test]
fn a_low_order_ephemeral_key_is_refused() {
    let s = server(1);
    let (_, mut msg1) = msg1_for(&s, b"C");
    msg1[..32].fill(0);
    let mut r = HqnResponder::new(s);
    assert!(r.open_message1(&msg1).is_err());
}

#[test]
fn a_handshake_object_is_single_use() {
    let s = server(1);
    let (mut client, msg1) = msg1_for(&s, b"C");
    assert!(client.write_message1(&HqcKem, b"C").is_err());
    let mut r = HqnResponder::new(s);
    r.read_message1(&HqcKem, &msg1).unwrap();
    assert!(r.open_message1(&msg1).is_err());
}

#[test]
fn a_large_payload_is_split_and_frames_out_of_order_or_repeated_are_refused() {
    let s = server(1);
    let (client, msg1) = msg1_for(&s, b"C");
    let mut r = HqnResponder::new(s);
    r.read_message1(&HqcKem, &msg1).unwrap();
    let (msg2, mut down) = r.write_message2(b"", &mut OsEntropy).unwrap();
    let (_, mut up) = client.read_message2(&msg2).unwrap();

    let data: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();
    let wire = noise::seal_frames(&mut up.send, &data).unwrap();
    let mut reader = noise::FrameReader::default();
    reader.push(&wire);
    let mut frames = vec![];
    while let Some(f) = reader.next_frame() {
        frames.push(f);
    }
    assert_eq!(frames.len(), 3);
    let got: Vec<u8> = frames
        .iter()
        .flat_map(|f| down.recv.decrypt(f).unwrap())
        .collect();
    assert_eq!(got, data, "nothing lost");

    let a = up.send.encrypt(b"a").unwrap();
    let b = up.send.encrypt(b"b").unwrap();
    assert!(down.recv.decrypt(&b).is_err(), "out of order");
    assert_eq!(down.recv.decrypt(&a).unwrap(), b"a");
    assert!(down.recv.decrypt(&a).is_err(), "repeated");
}
