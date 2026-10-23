//! services/server/test/helpers/identity-vectors.json: the ids the server,
//! the Apple app and the core must all compute. Read in place, so the three
//! suites share one file.

use hqchat_protocol::PeerId;
use hqchat_protocol::identity::PEER_ID_LENGTH;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../services/server/test/helpers/identity-vectors.json");

fn keys() -> Vec<(String, String, String)> {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["publicKeyBytes"], hqc::PUBLIC_KEY_BYTES);
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let s = |f: &str| k[f].as_str().unwrap().to_owned();
            (s("label"), s("publicKeyHex"), s("id"))
        })
        .collect()
}

#[test]
fn every_vector_hashes_to_its_pinned_id() {
    let keys = keys();
    assert!(keys.len() >= 4, "full-size, short and uppercase cases");
    for (label, pk_hex, id) in keys {
        let got = PeerId::of_hex(&pk_hex);
        assert_eq!(got.as_str(), id, "{label}");
        assert_eq!(got.as_str().len(), PEER_ID_LENGTH, "{label}");
        assert_eq!(PeerId::parse(&id).unwrap(), got, "{label}: the id parses");
    }
}

#[test]
fn a_full_size_vector_key_hashes_the_same_through_the_typed_key() {
    let (label, pk_hex, id) = keys().remove(0);
    let pk = hqc::PublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();
    assert_eq!(PeerId::of(&pk).as_str(), id, "{label}");
    assert!(PeerId::parse(&id).unwrap().matches(&pk));
}
