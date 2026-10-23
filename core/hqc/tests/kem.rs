//! The KEM's behaviour (native/hqc/test/main.c) and its known answers
//! (services/server/test/unit/hqc.test.ts), against this build of the C.
//!
//! The digests came from the shipped macOS/arm64 library. If they fail on
//! another target, that target is NOT byte-compatible with the shipped
//! clients and that is the finding: do not regenerate them to make it pass.

use hqc::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn same(a: &SharedSecret, b: &SharedSecret) -> bool {
    a.ct_eq(b).into()
}

/// Bytes 0..31, as in hqc.test.ts.
fn kat_seed() -> Seed {
    Seed::from_bytes(std::array::from_fn(|i| i as u8))
}

#[test]
fn keys_match_the_shipped_known_answers() {
    let pair = keypair_from_seed(&kat_seed()).unwrap();
    assert_eq!(
        sha(pair.public.as_bytes()),
        "25cebbbb79c410d5b8c1ae0d5e5c35ff2735e7c1f51105a21e6ea7f83391f56c"
    );
    assert_eq!(
        sha(pair.secret.as_bytes()),
        "79471d21ef264d3f59c693ed20f44c0a59daec8b8b9c2708da529ef491a8022b"
    );
}

#[test]
fn implicit_rejection_matches_the_shipped_known_answer() {
    // Not a real encapsulation: what this pins is the pseudo-random secret a
    // chosen ciphertext yields, which differs between upstream revisions.
    let pair = keypair_from_seed(&kat_seed()).unwrap();
    let bytes: Vec<u8> = (0..CIPHERTEXT_BYTES).map(|i| (i * 7 + 13) as u8).collect();
    let ss = decapsulate(&pair.secret, &Ciphertext::from_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(
        sha(ss.as_bytes()),
        "8a380b3e4d305322ecb4f438bf060f4da8d0f395614be39c881f67018a3ad0f4"
    );
}

#[test]
fn the_same_seed_gives_the_same_keypair_and_another_seed_another() {
    let a = keypair_from_seed(&Seed::from_bytes([b'A'; SEED_BYTES])).unwrap();
    let again = keypair_from_seed(&Seed::from_bytes([b'A'; SEED_BYTES])).unwrap();
    let b = keypair_from_seed(&Seed::from_bytes([b'B'; SEED_BYTES])).unwrap();
    assert_eq!(a.public, again.public);
    assert_eq!(a.secret.as_bytes(), again.secret.as_bytes());
    assert_ne!(a.public, b.public);
}

#[test]
fn decapsulation_recovers_what_was_encapsulated() {
    let pair = generate_keypair().unwrap();
    let (ct, ss) = encapsulate(&pair.public).unwrap();
    assert!(same(&decapsulate(&pair.secret, &ct).unwrap(), &ss));
}

#[test]
fn every_encapsulation_is_fresh() {
    let pair = generate_keypair().unwrap();
    let (ct1, ss1) = encapsulate(&pair.public).unwrap();
    let (ct2, ss2) = encapsulate(&pair.public).unwrap();
    assert_ne!(ct1, ct2);
    assert!(!same(&ss1, &ss2));
}

#[test]
fn a_tampered_ciphertext_or_the_wrong_key_yields_another_secret_not_an_error() {
    let pair = generate_keypair().unwrap();
    let other = generate_keypair().unwrap();
    let (ct, ss) = encapsulate(&pair.public).unwrap();

    let mut bytes = ct.as_bytes().to_vec();
    bytes[0] ^= 0xff;
    let tampered = Ciphertext::from_bytes(&bytes).unwrap();
    assert!(!same(&decapsulate(&pair.secret, &tampered).unwrap(), &ss));
    assert!(!same(&decapsulate(&other.secret, &ct).unwrap(), &ss));
}

#[test]
fn concurrent_encapsulations_all_decapsulate() {
    // HQC's PRNG is process-global: without hqc-sys's lock, threads would
    // reseed it under each other and pair ciphertexts with wrong secrets.
    let pair = std::sync::Arc::new(generate_keypair().unwrap());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let pair = pair.clone();
            std::thread::spawn(move || {
                for _ in 0..4 {
                    let (ct, ss) = encapsulate(&pair.public).unwrap();
                    assert!(same(&decapsulate(&pair.secret, &ct).unwrap(), &ss));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn a_secret_key_knows_its_own_public_key_only() {
    let a = keypair_from_seed(&kat_seed()).unwrap();
    let b = generate_keypair().unwrap();
    assert!(a.secret.belongs_to(&a.public));
    assert!(b.secret.belongs_to(&b.public));
    assert!(!a.secret.belongs_to(&b.public));
}
