//! The MQTT codec against tests/fixtures/mqtt-packet-9.0.2.json (packets the
//! server's mqtt.js encoder produced from the inputs below), plus the edge
//! cases of apps/apple/tests/MQTTWireTests.swift and MQTTCodecEdgeTests.swift.

use hqchat_protocol::mqtt::{self, Decoder, MAX_PACKET_BYTES, Packet, QoS, Will};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/mqtt-packet-9.0.2.json");
const ID: &str = "2ce241ed8975d37cd2a416c41862320a64dfd964536b2cf94631480e3f7b0ac4";
const CV: &str = "cv/8006188126a94e92a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";

fn presence() -> String {
    format!("u/{ID}/presence")
}

/// The fixture's inputs, case by case.
fn cases() -> Vec<(&'static str, Packet)> {
    vec![
        (
            "connect",
            Packet::Connect {
                client_id: ID.into(),
                username: Some(ID.into()),
                password: Some(b"v1.proof".to_vec()),
                keep_alive: 30,
                clean_session: false,
                will: Some(Will {
                    topic: presence(),
                    payload: br#"{"s":"offline"}"#.to_vec(),
                    qos: QoS::AtLeastOnce,
                    retain: true,
                }),
            },
        ),
        (
            "connectClean",
            Packet::Connect {
                client_id: "c".into(),
                username: None,
                password: None,
                keep_alive: 0,
                clean_session: true,
                will: None,
            },
        ),
        (
            "connack",
            Packet::Connack {
                session_present: true,
                code: 0,
            },
        ),
        (
            "connackRefused",
            Packet::Connack {
                session_present: false,
                code: 5,
            },
        ),
        (
            "publishQos1",
            Packet::Publish {
                topic: CV.into(),
                payload: vec![1, 2, 3, 0, 255],
                qos: QoS::AtLeastOnce,
                retain: false,
                packet_id: Some(7),
                dup: false,
            },
        ),
        (
            "publishQos1Dup",
            Packet::Publish {
                topic: CV.into(),
                payload: b"again".to_vec(),
                qos: QoS::AtLeastOnce,
                retain: false,
                packet_id: Some(65535),
                dup: true,
            },
        ),
        (
            "publishRetained",
            Packet::Publish {
                topic: presence(),
                payload: br#"{"s":"online"}"#.to_vec(),
                qos: QoS::AtMostOnce,
                retain: true,
                packet_id: None,
                dup: false,
            },
        ),
        ("puback", Packet::Puback { packet_id: 7 }),
        (
            "subscribe",
            Packet::Subscribe {
                packet_id: 3,
                filters: vec![
                    (format!("u/{ID}/inbox"), QoS::AtLeastOnce),
                    (CV.into(), QoS::AtMostOnce),
                ],
            },
        ),
        (
            "suback",
            Packet::Suback {
                packet_id: 3,
                codes: vec![1, 0x80],
            },
        ),
        (
            "unsubscribe",
            Packet::Unsubscribe {
                packet_id: 4,
                filters: vec![CV.into()],
            },
        ),
        ("unsuback", Packet::Unsuback { packet_id: 4 }),
        ("pingreq", Packet::Pingreq),
        ("pingresp", Packet::Pingresp),
        ("disconnect", Packet::Disconnect),
    ]
}

fn decode_one(bytes: &[u8]) -> Result<Option<Packet>, hqchat_protocol::Error> {
    let mut d = Decoder::default();
    d.push(bytes);
    d.next_packet()
}

#[test]
fn every_packet_matches_mqtt_js_byte_for_byte_and_decodes_back() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for (name, packet) in cases() {
        let want = hex::decode(
            fixture[name]
                .as_str()
                .unwrap_or_else(|| panic!("{name} missing")),
        )
        .unwrap();
        assert_eq!(mqtt::encode(&packet).unwrap(), want, "{name}: encode");
        assert_eq!(decode_one(&want).unwrap(), Some(packet), "{name}: decode");
    }
}

#[test]
fn a_200_kb_publish_has_the_four_byte_length_mqtt_js_gives_it() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let packet = Packet::Publish {
        topic: "t".into(),
        payload: vec![0xab; 200_000],
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: None,
        dup: false,
    };
    let bytes = mqtt::encode(&packet).unwrap();
    assert_eq!(bytes.len() as u64, fixture["bigLen"].as_u64().unwrap());
    assert_eq!(hex::encode(&bytes[..8]), fixture["bigHead"]);
    assert_eq!(decode_one(&bytes).unwrap(), Some(packet));
}

#[test]
fn remaining_lengths_round_trip_at_every_boundary() {
    for n in [0usize, 127, 128, 16_383, 16_384, 200_000] {
        let packet = Packet::Publish {
            topic: "t".into(),
            payload: vec![0; n.saturating_sub(3)],
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
            dup: false,
        };
        let bytes = mqtt::encode(&packet).unwrap();
        assert_eq!(decode_one(&bytes).unwrap(), Some(packet), "length {n}");
    }
}

#[test]
fn a_stream_splits_anywhere_and_two_packets_in_one_buffer_both_drain() {
    let wire = [
        mqtt::encode(&cases()[4].1).unwrap(),
        mqtt::encode(&Packet::Pingresp).unwrap(),
    ]
    .concat();
    for split in 0..=wire.len() {
        let mut d = Decoder::default();
        let mut got = vec![];
        for part in [&wire[..split], &wire[split..]] {
            d.push(part);
            while let Some(p) = d.next_packet().unwrap() {
                got.push(p);
            }
        }
        assert_eq!(
            got,
            vec![cases()[4].1.clone(), Packet::Pingresp],
            "split at {split}"
        );
        assert_eq!(d.pending(), 0);
    }
}

#[test]
fn incomplete_is_not_malformed() {
    for partial in [&[][..], &[0x30], &[0x30, 0x80], &[0x30, 0x05, 0x00]] {
        assert_eq!(decode_one(partial).unwrap(), None, "{partial:?}");
    }
    let legal_four = [0x90, 0xff, 0xff, 0xff, 0x0f];
    assert!(
        decode_one(&legal_four).is_err(),
        "legal prefix, but over MAX_PACKET_BYTES"
    );
}

#[test]
fn hostile_lengths_are_refused_before_buffering() {
    assert!(
        decode_one(&[0x30, 0x80, 0x80, 0x80, 0x80, 0x01]).is_err(),
        "five continuation bytes"
    );
    let mut d = Decoder::default();
    d.push(&[0x90, 0xff, 0xff, 0xff, 0x7f]);
    assert!(d.next_packet().is_err(), "a 256 MB claim");
    let just_over = MAX_PACKET_BYTES - 2;
    let mut claim = vec![0x90];
    let mut n = just_over;
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        claim.push(b);
        if n == 0 {
            break;
        }
    }
    assert!(decode_one(&claim).is_err(), "one byte past the limit");
}

#[test]
fn the_decoder_is_strict_about_what_the_spec_forbids() {
    let refused: Vec<(&str, Vec<u8>)> = vec![
        (
            "QoS 2 publish",
            vec![0x34, 0x05, 0x00, 0x01, b't', 0x00, 0x01],
        ),
        (
            "QoS 3 publish",
            vec![0x36, 0x05, 0x00, 0x01, b't', 0x00, 0x01],
        ),
        ("dup on QoS 0", vec![0x38, 0x03, 0x00, 0x01, b't']),
        (
            "packet id 0",
            vec![0x32, 0x05, 0x00, 0x01, b't', 0x00, 0x00],
        ),
        ("bad UTF-8 topic", vec![0x30, 0x03, 0x00, 0x01, 0xff]),
        ("topic past the body", vec![0x30, 0x03, 0x00, 0x05, b't']),
        (
            "subscribe without 0010",
            vec![0x80, 0x06, 0x00, 0x01, 0x00, 0x01, b't', 0x00],
        ),
        ("subscribe without filter", vec![0x82, 0x02, 0x00, 0x01]),
        (
            "subscribe QoS 2",
            vec![0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b't', 0x02],
        ),
        ("suback bad code", vec![0x90, 0x03, 0x00, 0x01, 0x05]),
        ("puback trailing", vec![0x40, 0x03, 0x00, 0x07, 0x00]),
        ("pingresp with body", vec![0xd0, 0x01, 0x00]),
        ("pubrec (QoS 2 flow)", vec![0x50, 0x02, 0x00, 0x01]),
        ("type 0", vec![0x00, 0x00]),
        ("type 15", vec![0xf0, 0x00]),
        ("connack flags", vec![0x20, 0x02, 0x02, 0x00]),
        (
            "connect level 5",
            vec![
                0x10, 0x0d, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x02, 0x00, 0x00, 0x00, 0x01,
                b'c',
            ],
        ),
        (
            "password without username",
            vec![
                0x10, 0x0d, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x40, 0x00, 0x00, 0x00, 0x01,
                b'c',
            ],
        ),
    ];
    for (name, bytes) in refused {
        assert!(decode_one(&bytes).is_err(), "{name} must be refused");
    }
}

#[test]
fn the_encoder_refuses_what_the_decoder_would() {
    let publish = |qos, packet_id, dup| Packet::Publish {
        topic: "t".into(),
        payload: vec![],
        qos,
        retain: false,
        packet_id,
        dup,
    };
    assert!(
        mqtt::encode(&publish(QoS::AtLeastOnce, None, false)).is_err(),
        "QoS 1 without an id"
    );
    assert!(
        mqtt::encode(&publish(QoS::AtLeastOnce, Some(0), false)).is_err(),
        "id 0"
    );
    assert!(
        mqtt::encode(&publish(QoS::AtMostOnce, Some(1), false)).is_err(),
        "QoS 0 with an id"
    );
    assert!(
        mqtt::encode(&publish(QoS::AtMostOnce, None, true)).is_err(),
        "dup on QoS 0"
    );
    assert!(
        mqtt::encode(&Packet::Subscribe {
            packet_id: 1,
            filters: vec![]
        })
        .is_err()
    );
    assert!(
        mqtt::encode(&Packet::Suback {
            packet_id: 1,
            codes: vec![3]
        })
        .is_err()
    );
    let no_user = Packet::Connect {
        client_id: "c".into(),
        username: None,
        password: Some(b"p".to_vec()),
        keep_alive: 0,
        clean_session: true,
        will: None,
    };
    assert!(
        mqtt::encode(&no_user).is_err(),
        "a password without a username"
    );
    let long_topic = Packet::Publish {
        topic: "t".repeat(70_000),
        payload: vec![],
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: None,
        dup: false,
    };
    assert!(
        mqtt::encode(&long_topic).is_err(),
        "a topic over 65535 bytes"
    );
}

fn remaining(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            return out;
        }
    }
}

#[test]
fn an_oversized_publish_is_skipped_unbuffered_and_the_stream_goes_on() {
    // Anyone may publish into an inbox: one publish over the limit must not
    // end the connection, or the broker redelivers it on every reconnect.
    let topic = format!("u/{ID}/inbox");
    let payload_len = MAX_PACKET_BYTES * 4;
    let mut body = Vec::new();
    body.extend((topic.len() as u16).to_be_bytes());
    body.extend(topic.as_bytes());
    body.extend(7u16.to_be_bytes());
    let mut stream = vec![0x32];
    stream.extend(remaining(body.len() + payload_len));
    stream.extend(&body);
    stream.extend(vec![0x41; payload_len]);
    stream.extend(mqtt::encode(&Packet::Pingresp).unwrap());

    let mut d = Decoder::default();
    let mut got = Vec::new();
    for chunk in stream.chunks(4096) {
        d.push(chunk);
        assert!(d.pending() <= 2 * 4096 + body.len(), "nothing piles up");
        while let Some(p) = d.next_packet().unwrap() {
            got.push(p);
        }
    }
    assert_eq!(
        got,
        vec![
            Packet::Oversized {
                qos: QoS::AtLeastOnce,
                packet_id: Some(7)
            },
            Packet::Pingresp
        ]
    );
    assert!(mqtt::encode(&got[0]).is_err(), "never sent");
}

#[test]
fn an_oversized_packet_other_than_a_publish_still_fails_the_stream() {
    let mut claim = vec![0x90];
    claim.extend(remaining(MAX_PACKET_BYTES));
    assert!(decode_one(&claim).is_err());
}

#[test]
fn a_remaining_length_has_one_encoding() {
    // C0 80 00 is PINGREQ with a two-byte zero length; only C0 00 is.
    assert!(decode_one(&[0xc0, 0x80, 0x00]).is_err());
    assert!(decode_one(&[0xd0, 0x80, 0x80, 0x00]).is_err());
    assert_eq!(decode_one(&[0xc0, 0x00]).unwrap(), Some(Packet::Pingreq));
}
