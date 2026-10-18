//! services/server/test/helpers/envelope-v3-vectors.json, as
//! envelope-v3.test.ts and the Swift suite assert it: the pinned frames
//! decode to their fields, re-encode byte for byte, and hostile variants are
//! refused without panicking. Read in place, so the suites share one file.

use hqchat_protocol::envelope::{self, Kind};
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../../services/server/test/helpers/envelope-v3-vectors.json");
const CASES: [&str; 6] = [
    "msg",
    "stepping",
    "init",
    "initNoOneTime",
    "unicode",
    "receipt",
];

fn vectors() -> Value {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], 3);
    v
}

fn frame_bytes(case: &Value) -> Vec<u8> {
    hex::decode(case["frameHex"].as_str().unwrap()).unwrap()
}

#[test]
fn every_pinned_frame_decodes_to_the_fields_it_claims() {
    let v = vectors();
    for name in CASES {
        let case = &v["cases"][name];
        let raw = frame_bytes(case);
        assert_eq!(
            raw.len() as u64,
            case["frameBytes"].as_u64().unwrap(),
            "{name}"
        );
        let (frame, aad) = envelope::decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let h = &frame.header;
        let f = &case["fields"];
        let kind = match f["t"].as_str().unwrap() {
            "msg" => Kind::Msg,
            "init" => Kind::Init,
            "receipt" => Kind::Receipt,
            other => panic!("{name}: kind {other}"),
        };
        assert_eq!(h.kind, kind, "{name}");
        assert_eq!(h.sender.as_str(), f["sender"], "{name}");
        assert_eq!(h.to.as_str(), f["to"], "{name}");
        assert_eq!(h.msg_id, f["msgId"].as_str().unwrap(), "{name}");
        assert_eq!(hex::encode(h.cid), f["cid"], "{name}");
        assert_eq!(u64::from(h.n), f["n"].as_u64().unwrap(), "{name}");
        assert_eq!(u64::from(h.pn), f["pn"].as_u64().unwrap(), "{name}");
        assert_eq!(
            h.one_time.as_ref().map(|o| u64::from(o.ot_id)),
            f["otId"].as_u64(),
            "{name}"
        );
        assert_eq!(
            frame.payload,
            f["payloadUtf8"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(hex::encode(&aad), case["aadHex"], "{name}: the AAD");
        assert_eq!(
            aad.len() as u64,
            case["aadBytes"].as_u64().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn the_aad_is_a_prefix_of_the_frame_and_encoding_is_byte_stable() {
    let v = vectors();
    for name in CASES {
        let raw = frame_bytes(&v["cases"][name]);
        let (frame, aad) = envelope::decode(&raw).unwrap();
        assert!(
            raw.starts_with(&aad),
            "{name}: the AAD is the frame's own prefix"
        );
        assert_eq!(
            envelope::header_bytes(&frame.header).unwrap(),
            aad,
            "{name}"
        );
        assert_eq!(
            envelope::encode(&frame).unwrap(),
            raw,
            "{name}: re-encodes byte for byte"
        );
    }
}

#[test]
fn the_version_and_the_recipient_are_inside_the_aad() {
    let v = vectors();
    let case = &v["cases"]["msg"];
    let raw = frame_bytes(case);

    let mut downgraded = raw.clone();
    downgraded[4] = 2;
    assert!(
        envelope::decode(&downgraded).is_err(),
        "a downgraded version is not even parsed"
    );

    let mut readdressed = raw.clone();
    readdressed[39] ^= 0xff;
    let (_, aad) = envelope::decode(&readdressed).unwrap();
    assert_ne!(
        hex::encode(aad),
        case["aadHex"],
        "re-addressing changes the AAD"
    );
}

#[test]
fn hostile_frames_are_refused_rather_than_panicking() {
    let v = vectors();
    let frame = frame_bytes(&v["cases"]["init"]);
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = frame.clone();
        f(&mut b);
        b
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("magic only", b"HQCE".to_vec()),
        ("truncated", frame[..frame.len() - 1].to_vec()),
        ("trailing byte", [frame.as_slice(), &[0]].concat()),
        ("bad magic", mutate(&|b| b[..4].copy_from_slice(b"XXXX"))),
        ("unknown flag bit", mutate(&|b| b[6] = 0x80)),
        ("unknown kind", mutate(&|b| b[5] = 9)),
        ("msgId length 0", mutate(&|b| b[95] = 0)),
        ("msgId length 200", mutate(&|b| b[95] = 200)),
        (
            "length prefix past the buffer",
            mutate(&|b| b[112..116].copy_from_slice(&0x0fff_ffffu32.to_be_bytes())),
        ),
        ("invalid UTF-8 msgId", mutate(&|b| b[96] = 0xff)),
    ];
    for (name, bytes) in cases {
        assert!(envelope::decode(&bytes).is_err(), "{name} must be refused");
    }
}

#[test]
fn a_senderpk_that_does_not_hash_to_sender_is_refused_both_ways() {
    let v = vectors();
    let raw = frame_bytes(&v["cases"]["init"]);
    let (mut frame, _) = envelope::decode(&raw).unwrap();
    let init = frame.header.init.as_mut().unwrap();
    init.sender_pk = vec![0xab; init.sender_pk.len()];
    assert!(envelope::encode(&frame).is_err(), "refused on the way out");

    // The same substitution spliced into the wire bytes is refused on the way in.
    let pk_at = 96 + frame.header.msg_id.len() + 4 + frame.header.rk.as_ref().unwrap().len() + 4;
    let mut spliced = raw.clone();
    spliced[pk_at..pk_at + 7237].fill(0xab);
    assert!(envelope::decode(&spliced).is_err(), "refused on the way in");
}

#[test]
fn looks_like_frame_is_total_and_cheap() {
    assert!(!envelope::looks_like_frame(&[]));
    assert!(!envelope::looks_like_frame(b"{}"));
    assert!(envelope::looks_like_frame(&frame_bytes(
        &vectors()["cases"]["msg"]
    )));
}
