//! The state file of the TS reference client (`FileStore` in
//! services/server/test/reference/client/store.ts), which the bot wrote until it moved
//! to the core: friends with their pinned keys, topics and ratchet sessions,
//! and the prekey secrets. Read once, into an [`Import`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey};
use hqchat_engine::{Import, ImportIdentity, ImportPeer, ImportPrekeys};
use hqchat_protocol::ratchet::{Chain, InitHeader, SessionState, SkippedKey, SymmetricKey};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// The import for `seed` and the file's JSON (`None` when there was no
/// file), and the ids of friends whose session could not be read: they are
/// imported without one, and the next message opens a new session.
pub fn import_of(seed: [u8; 32], json: Option<&str>) -> Result<(Import, Vec<String>), String> {
    let mut import = Import {
        identity: ImportIdentity::Seed(seed),
        prekeys: None,
        peers: vec![],
        messages: vec![],
        pending: vec![],
        sent: vec![],
    };
    let Some(json) = json else {
        return Ok((import, vec![]));
    };
    let root: Value = serde_json::from_str(json).map_err(|e| format!("state file: {e}"))?;
    let root = root.as_object().ok_or("state file: not an object")?;
    import.prekeys = match root.get("prekeys") {
        None | Some(Value::Null) => None,
        Some(p) => Some(prekeys(p).map_err(|e| format!("state file prekeys: {e}"))?),
    };
    let mut unreadable = vec![];
    if let Some(peers) = root.get("peers") {
        let peers = peers
            .as_object()
            .ok_or("state file: peers is not an object")?;
        for (id, p) in peers {
            let p = p
                .as_object()
                .ok_or_else(|| format!("state file: peer {id} is not an object"))?;
            let session = match p.get("session") {
                None | Some(Value::Null) => None,
                Some(s) => match session(s) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        unreadable.push(id.clone());
                        None
                    }
                },
            };
            import.peers.push(ImportPeer {
                id: id.clone(),
                username: text(p, "username"),
                convo_id: text(p, "convoId"),
                handshake_id: text(p, "handshakeId"),
                pinned_pk: match text(p, "pk") {
                    Some(hex_key) => Some(
                        hex::decode(&hex_key)
                            .map_err(|_| format!("state file: peer {id} has a bad pk"))?,
                    ),
                    None => None,
                },
                session,
                blocked_at: None,
                vanished_at: None,
                verified: false,
            });
        }
    }
    Ok((import, unreadable))
}

fn text(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, String> {
    v.get(key).ok_or_else(|| format!("no {key}"))
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, String> {
    field(v, key)?
        .as_str()
        .and_then(|s| STANDARD.decode(s).ok())
        .ok_or_else(|| format!("{key} is not base64"))
}

fn secret(v: &Value, key: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    bytes(v, key).map(Zeroizing::new)
}

fn array<const N: usize>(v: &Value, key: &str) -> Result<[u8; N], String> {
    bytes(v, key)?
        .try_into()
        .map_err(|_| format!("{key} is not {N} bytes"))
}

fn u32_of(v: &Value, key: &str) -> Result<u32, String> {
    field(v, key)?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("{key} is not a u32"))
}

fn i64_of(v: &Value, key: &str) -> Result<i64, String> {
    field(v, key)?
        .as_i64()
        .ok_or_else(|| format!("{key} is not an integer"))
}

/// A 16-byte chain id, which the TS client keeps as hex.
fn chain_id(v: &Value) -> Result<[u8; 16], String> {
    v.as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "a chain id is not 16 bytes of hex".to_owned())
}

fn prekeys(p: &Value) -> Result<ImportPrekeys, String> {
    let mut one_time = vec![];
    if let Some(map) = field(p, "oneTime")?.as_object() {
        for (id, _) in map {
            let n = id
                .parse::<u32>()
                .map_err(|_| format!("one-time id {id} is not a u32"))?;
            one_time.push((n, secret(field(p, "oneTime")?, id)?));
        }
    }
    Ok(ImportPrekeys {
        medium_public: bytes(p, "mediumPk")?,
        medium_secret: secret(p, "mediumSk")?,
        rotated_at: i64_of(p, "rotatedAt")?,
        one_time,
        next_id: u32_of(p, "nextId")?,
    })
}

fn chain(v: &Value, key: &str) -> Result<Option<Chain>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(c) => Ok(Some(Chain {
            ck: SymmetricKey(array(c, "ck")?),
            n: u32_of(c, "n")?,
        })),
    }
}

fn session(s: &Value) -> Result<SessionState, String> {
    let rk = KeyPair {
        public: PublicKey::from_bytes(&bytes(s, "rkPub")?).map_err(|e| e.to_string())?,
        secret: SecretKey::from_bytes(&secret(s, "rkSec")?).map_err(|e| e.to_string())?,
    };
    let peer_rk = match s.get("peerRkPub") {
        None | Some(Value::Null) => None,
        Some(_) => Some(PublicKey::from_bytes(&bytes(s, "peerRkPub")?).map_err(|e| e.to_string())?),
    };
    let mut skipped = vec![];
    for k in field(s, "skipped")?
        .as_array()
        .ok_or("skipped is not a list")?
    {
        skipped.push(SkippedKey {
            chain: chain_id(field(k, "chain")?)?,
            n: u32_of(k, "n")?,
            key: SymmetricKey(array(k, "key")?),
        });
    }
    let mut seen_chains = vec![];
    for c in field(s, "seenChains")?
        .as_array()
        .ok_or("seenChains is not a list")?
    {
        seen_chains.push(chain_id(c)?);
    }
    let pending_init = match s.get("pendingInit") {
        None | Some(Value::Null) => None,
        Some(p) => Some(init(p)?),
    };
    Ok(SessionState {
        root: SymmetricKey(array(s, "root")?),
        rk,
        peer_rk,
        send: chain(s, "send")?,
        recv: chain(s, "recv")?,
        prev_send_n: u32_of(s, "prevSendN")?,
        skipped,
        pending_init,
        seen_chains,
        sent_on_chain: u32_of(s, "sentOnChain")?,
        chain_started_at: i64_of(s, "chainStartedAt")?,
        // Engine::import decides it, the same way on both sides.
        peer_key_fresh: false,
    })
}

fn init(p: &Value) -> Result<InitHeader, String> {
    let ct = |key: &str| -> Result<Ciphertext, String> {
        Ciphertext::from_bytes(&bytes(p, key)?).map_err(|e| e.to_string())
    };
    let one_time = match (p.get("ctOt"), p.get("otId")) {
        (Some(Value::String(_)), Some(id)) if !id.is_null() => {
            Some((ct("ctOt")?, u32_of(p, "otId")?))
        }
        (None | Some(Value::Null), None | Some(Value::Null)) => None,
        _ => return Err("ctOt and otId come together".into()),
    };
    Ok(InitHeader {
        ct_id: ct("ctId")?,
        ct_mt: ct("ctMt")?,
        one_time,
        rk: PublicKey::from_bytes(&bytes(p, "rk")?).map_err(|e| e.to_string())?,
        cid: chain_id(field(p, "cid")?)?,
    })
}
