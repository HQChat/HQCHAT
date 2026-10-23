//! What `src/server/auth.ts`, `api.ts`, `emqx.ts` and the gateway's key
//! loading call, replacing `src/protocol/{hqc,auth-proof,mqtt-proof,identity,topics}.ts`.

use hqc::{Ciphertext, PublicKey, SecretKey, Seed};
use hqchat_protocol::topics::{self, TopicId};
use hqchat_protocol::{PeerId, auth_proof, mqtt_proof};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::err;

/// An HQC keypair: `{ pk, sk }`.
#[napi(object)]
pub struct HqcKeyPair {
    /// Public key, 7237 bytes.
    pub pk: Buffer,
    /// Secret key, 7333 bytes.
    pub sk: Buffer,
}

/// An encapsulation: `{ ct, ss }`.
#[napi(object)]
pub struct Encapsulation {
    /// Ciphertext, 14421 bytes.
    pub ct: Buffer,
    /// Shared secret, 32 bytes.
    pub ss: Buffer,
}

/// The deterministic keypair of a 32-byte seed (`HqcWrapper.keypairFromSeed`).
#[napi(catch_unwind)]
pub fn hqc_keypair_from_seed(seed: Buffer) -> napi::Result<HqcKeyPair> {
    let seed: [u8; 32] = seed
        .as_ref()
        .try_into()
        .map_err(|_| err("a seed is 32 bytes"))?;
    let pair = hqc::keypair_from_seed(&Seed::from_bytes(seed)).map_err(err)?;
    Ok(HqcKeyPair {
        pk: pair.public.as_bytes().to_vec().into(),
        sk: pair.secret.as_bytes().to_vec().into(),
    })
}

/// A fresh ciphertext for `pk` and its secret (`HqcWrapper.encapsulate`).
#[napi(catch_unwind)]
pub fn hqc_encapsulate(pk: Buffer) -> napi::Result<Encapsulation> {
    let pk = PublicKey::from_bytes(&pk).map_err(err)?;
    let (ct, ss) = hqc::encapsulate(&pk).map_err(err)?;
    Ok(Encapsulation {
        ct: ct.as_bytes().to_vec().into(),
        ss: ss.as_bytes().to_vec().into(),
    })
}

/// The secret `ct` carries for `sk`; implicit rejection (`HqcWrapper.decapsulate`).
#[napi(catch_unwind)]
pub fn hqc_decapsulate(sk: Buffer, ct: Buffer) -> napi::Result<Buffer> {
    let sk = SecretKey::from_bytes(&sk).map_err(err)?;
    let ct = Ciphertext::from_bytes(&ct).map_err(err)?;
    Ok(hqc::decapsulate(&sk, &ct)
        .map_err(err)?
        .as_bytes()
        .to_vec()
        .into())
}

/// What `/auth/init` returns, and the proof `/auth/verify` must present.
#[napi(object)]
pub struct AuthChallenge {
    /// The HQC ciphertext to the account's key.
    pub ct: Buffer,
    /// The proof that answers it, to keep until the verify.
    pub proof: Buffer,
}

/// A sign-in challenge to `pk` (raw bytes) for a sign-in at `origin`
/// (`scheme://host[:port]`). The shared secret never reaches JS: only the
/// proof that answers the challenge comes back.
#[napi(catch_unwind)]
pub fn auth_challenge(pk: Buffer, origin: String) -> napi::Result<AuthChallenge> {
    let pk = PublicKey::from_bytes(&pk).map_err(err)?;
    let (ct, proof) = auth_proof::challenge(&pk, &origin).map_err(err)?;
    Ok(AuthChallenge {
        ct: ct.as_bytes().to_vec().into(),
        proof: proof.to_vec().into(),
    })
}

/// `scheme://host[:port]` of `url`, as the sign-in proof binds it, or null.
#[napi(catch_unwind)]
pub fn origin_of(url: String) -> Option<String> {
    auth_proof::origin_of(&url)
}

/// Constant-time comparison of a presented proof with the expected one.
#[napi(catch_unwind)]
pub fn auth_proof_matches(expected: Buffer, offered: Buffer) -> bool {
    <[u8; 32]>::try_from(expected.as_ref()).is_ok_and(|e| auth_proof::proof_matches(&e, &offered))
}

/// A parsed CONNECT password.
#[napi(object)]
pub struct ConnectProof {
    /// The signing key's id, 32 hex.
    pub key_id: String,
    /// Unix seconds, server clock.
    pub ts: i64,
    /// The single-use nonce, 16 bytes.
    pub nonce: Buffer,
    /// The Ed25519 signature, 64 bytes.
    pub signature: Buffer,
}

/// Strict parse of a v1 password; `null` for anything off the shape (`parseProofPassword`).
#[napi(catch_unwind)]
pub fn parse_connect_proof(password: String) -> Option<ConnectProof> {
    let p = mqtt_proof::parse_password(&password)?;
    Some(ConnectProof {
        key_id: p.key_id,
        ts: p.ts,
        nonce: p.nonce.to_vec().into(),
        signature: p.signature.to_vec().into(),
    })
}

/// Whether `ts` is within ±60 s of `nowSec`, inclusive (`isFreshTimestamp`).
#[napi(catch_unwind)]
pub fn is_fresh_timestamp(ts: i64, now_sec: i64) -> bool {
    mqtt_proof::is_fresh_timestamp(ts, now_sec)
}

/// How long a spent CONNECT nonce must be remembered, in seconds: past it,
/// no timestamp that could accept the nonce is still fresh.
#[napi]
pub const MQTT_PROOF_NONCE_TTL_SECONDS: i64 = mqtt_proof::MQTT_PROOF_NONCE_TTL_SECONDS;

/// An id's length in hex characters.
#[napi]
pub const PEER_ID_LENGTH: u32 = u32_of(hqchat_protocol::identity::PEER_ID_LENGTH);

/// An HQC-256 public key's length in bytes.
#[napi]
pub const HQC_PUBLIC_KEY_BYTES: u32 = u32_of(hqc::PUBLIC_KEY_BYTES);

/// A core size as a JS number, at compile time: one that did not fit would
/// fail the build rather than wrap.
const fn u32_of(n: usize) -> u32 {
    assert!(n <= 0xffff_ffff, "does not fit a u32");
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "the assertion above proves the value fits; const fns cannot call try_from"
    )]
    let n = n as u32;
    n
}

/// Whether `raw` is an Ed25519 public key worth registering for CONNECT
/// proofs: 32 bytes, a canonical point, not of small order (`ed25519PublicKey`).
#[napi(catch_unwind)]
pub fn is_signing_key(raw: Buffer) -> bool {
    <[u8; 32]>::try_from(raw.as_ref()).is_ok_and(|key| mqtt_proof::is_valid_public_key(&key))
}

/// Whether the proof's signature verifies for `clientid` under the raw
/// 32-byte Ed25519 key (`verifyProofSignature` over `proofMessage`).
#[napi(catch_unwind)]
pub fn verify_connect_proof(public_key: Buffer, clientid: String, proof: ConnectProof) -> bool {
    let (Ok(key), Ok(id), Ok(nonce), Ok(sig)) = (
        <[u8; 32]>::try_from(public_key.as_ref()),
        PeerId::parse(&clientid),
        <[u8; 16]>::try_from(proof.nonce.as_ref()),
        <[u8; 64]>::try_from(proof.signature.as_ref()),
    ) else {
        return false;
    };
    mqtt_proof::verify_signature(
        &key,
        &mqtt_proof::proof_message(&id, &proof.key_id, proof.ts, &nonce),
        &sig,
    )
}

/// The id of a public key given as hex in either case (`peerId`).
#[napi(catch_unwind)]
pub fn peer_id(public_key_hex: String) -> String {
    PeerId::of_hex(&public_key_hex).to_string()
}

/// Whether `value` is an id: 64 lowercase hex (`isPeerId`).
#[napi(catch_unwind)]
pub fn is_peer_id(value: String) -> bool {
    PeerId::parse(&value).is_ok()
}

/// Whether `publicKeyHex` is the key `id` names (`keyMatchesId`).
#[napi(catch_unwind)]
pub fn key_matches_id(public_key_hex: String, id: String) -> bool {
    PeerId::of_hex(&public_key_hex).as_str() == id.to_lowercase()
}

/// `cv/{convoId}` (`conversationTopic`).
#[napi(catch_unwind)]
pub fn conversation_topic(convo_id: String) -> napi::Result<String> {
    Ok(topics::conversation_topic(
        &TopicId::parse(&convo_id).map_err(err)?,
    ))
}

/// `hs/{handshakeId}` (`handshakeTopic`).
#[napi(catch_unwind)]
pub fn handshake_topic(handshake_id: String) -> napi::Result<String> {
    Ok(topics::handshake_topic(
        &TopicId::parse(&handshake_id).map_err(err)?,
    ))
}
