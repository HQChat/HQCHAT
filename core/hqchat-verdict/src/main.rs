//! The Rust half of the differential fuzzers in `services/server/test/fuzz`.
//!
//! Each mode reads a batch file and prints one verdict line per input line,
//! in the exact formats of the Swift verdict programs in `apps/apple/fuzz`,
//! so every harness can run against either implementation:
//!
//! ```text
//! hqchat-verdict envelope-v3 <batch.hexlines>
//! hqchat-verdict envelope-v3-encode <batch.jsonl>
//! hqchat-verdict handshake <decode|encode|round> <batch.jsonl>
//! hqchat-verdict noise <frames|msg2> <batch.jsonl> <noise-hqn-vectors.json>
//! ```
//!
//! The formats are documented beside each mode below and in the Swift files
//! of the same name. Refusal reasons are never compared.

use std::io::Write;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey, SharedSecret};
use hqchat_protocol::envelope::{self, Frame, Header, InitFields, Kind, OneTime};
use hqchat_protocol::handshake::{self, HandshakeFrame};
use hqchat_protocol::noise::{FrameReader, HqnInitiator, ServerStaticPublic};
use hqchat_protocol::{Entropy, Error, Kem, PeerId};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["envelope-v3", file] => read(file).map(|raw| envelope_decode(&raw)),
        ["envelope-v3-encode", file] => read(file).map(|raw| envelope_encode(&raw)),
        ["handshake", mode @ ("decode" | "encode" | "round"), file] => {
            read(file).map(|raw| handshake_verdicts(mode, &raw))
        }
        ["noise", mode @ ("frames" | "msg2"), file, vectors] => {
            read(file).and_then(|raw| noise_verdicts(mode, &raw, vectors))
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(out) => match std::io::stdout().lock().write_all(out.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Err(why) => {
            // Nothing more useful to do if stderr itself is gone.
            let _ignored = writeln!(std::io::stderr().lock(), "{why}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str = "usage: hqchat-verdict envelope-v3 <batch> | envelope-v3-encode <batch> \
                     | handshake <decode|encode|round> <batch> \
                     | noise <frames|msg2> <batch> <vectors.json>";

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ── envelope-v3 ─────────────────────────────────────────────────────────────
//
// In: one hex frame per line; empty lines are zero-length frames.
// Out: `A <aadLen>:<sha256(aad)>:<sha256(fields)>` or `R <reason>`.

fn envelope_decode(raw: &str) -> String {
    let mut out = String::new();
    for line in raw.split('\n') {
        let verdict = match hex::decode(line) {
            Err(_) => "R not hex".to_owned(),
            Ok(bytes) => match envelope::decode(&bytes) {
                Ok((frame, aad)) => format!(
                    "A {}:{}:{}",
                    aad.len(),
                    sha_hex(&aad),
                    fields_digest(&frame)
                ),
                Err(e) => format!("R {e}"),
            },
        };
        out.push_str(&verdict);
        out.push('\n');
    }
    out
}

/// Every decoded field, NUL-separated, as `EnvelopeV3Verdict.swift` digests it.
fn fields_digest(frame: &Frame) -> String {
    let h = &frame.header;
    let kind = match h.kind {
        Kind::Init => "init",
        Kind::Receipt => "receipt",
        Kind::Msg => "msg",
    };
    let blob = |b: Option<&Vec<u8>>| b.map(hex::encode).unwrap_or_default();
    let init = h.init.as_ref();
    let parts = [
        kind.to_owned(),
        h.sender.to_string(),
        h.to.to_string(),
        h.msg_id.clone(),
        hex::encode(h.cid),
        h.n.to_string(),
        h.pn.to_string(),
        h.one_time
            .as_ref()
            .map(|o| o.ot_id.to_string())
            .unwrap_or_default(),
        blob(h.rk.as_ref()),
        blob(h.kem_ct.as_ref()),
        blob(init.map(|i| &i.ct_id)),
        blob(init.map(|i| &i.ct_mt)),
        blob(h.one_time.as_ref().map(|o| &o.ct_ot)),
        blob(init.map(|i| &i.sender_pk)),
        hex::encode(&frame.payload),
    ];
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())
}

// ── envelope-v3-encode ──────────────────────────────────────────────────────
//
// In: one JSON struct per line, binary fields as hex.
// Out: `A <frameHex>` or `R`.

fn envelope_encode(raw: &str) -> String {
    let mut out = String::new();
    for line in raw.split('\n') {
        match wire_frame(line).and_then(|f| envelope::encode(&f).ok()) {
            Some(bytes) => {
                out.push_str("A ");
                out.push_str(&hex::encode(bytes));
            }
            None => out.push('R'),
        }
        out.push('\n');
    }
    out
}

/// The struct as the encoder takes it, or `None` for any field the typed
/// API cannot hold: the harness counts that as a refusal, as the TS and
/// Swift encoders refuse the same values.
fn wire_frame(line: &str) -> Option<Frame> {
    let value: Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;
    let text = |k: &str| obj.get(k).and_then(Value::as_str);
    let counter = |k: &str| {
        obj.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let kind = match text("t") {
        Some("init") => Kind::Init,
        Some("receipt") => Kind::Receipt,
        _ => Kind::Msg,
    };
    let init = match (
        blob(obj, "senderPk")?,
        blob(obj, "ctId")?,
        blob(obj, "ctMt")?,
    ) {
        (Some(sender_pk), Some(ct_id), Some(ct_mt)) => Some(InitFields {
            sender_pk,
            ct_id,
            ct_mt,
        }),
        (None, None, None) => None,
        _ => return None,
    };
    let one_time = match (blob(obj, "ctOt")?, obj.contains_key("otId")) {
        (Some(ct_ot), true) => Some(OneTime {
            ct_ot,
            ot_id: counter("otId")?,
        }),
        (None, false) => None,
        _ => return None,
    };
    let header = Header {
        kind,
        sender: PeerId::parse(text("sender")?).ok()?,
        to: PeerId::parse(text("to")?).ok()?,
        msg_id: text("msgId")?.to_owned(),
        cid: hex::decode(text("cid")?).ok()?.try_into().ok()?,
        n: counter("n")?,
        pn: counter("pn")?,
        rk: blob(obj, "rk")?,
        kem_ct: blob(obj, "kemCt")?,
        init,
        one_time,
    };
    Some(Frame {
        header,
        payload: blob(obj, "payload")?.unwrap_or_default(),
    })
}

/// `Some(None)` when absent, `Some(Some(bytes))` when hex, `None` when the
/// field is present and unreadable.
fn blob(obj: &Map<String, Value>, key: &str) -> Option<Option<Vec<u8>>> {
    match obj.get(key) {
        None => Some(None),
        Some(v) => hex::decode(v.as_str()?).ok().map(Some),
    }
}

// ── handshake ───────────────────────────────────────────────────────────────
//
// decode  in: a JSON string of base64 per line
//         out: `A <chal|proof> <from> <to> <nonceHex> <sha256(body)> <bodyLen>` or `R`
// encode  in: `{kind, from, to, nonce, ct?, proof?}`, bytes as base64
//         out: `A <sha256(frame)> <len>` or `R`
// round   out: `T` round-tripped, `F <why>` did not, `R` encode refused

fn handshake_verdicts(mode: &str, raw: &str) -> String {
    let mut out = String::new();
    for line in raw.split('\n').filter(|l| !l.is_empty()) {
        let verdict = match mode {
            "decode" => handshake_decode(line),
            "encode" => match handshake_frame(line).and_then(|f| handshake::encode(&f).ok()) {
                Some(bytes) => format!("A {} {}", sha_hex(&bytes), bytes.len()),
                None => "R".to_owned(),
            },
            _ => handshake_round(line),
        };
        out.push_str(&verdict);
        out.push('\n');
    }
    out
}

fn handshake_decode(line: &str) -> String {
    let bytes = serde_json::from_str::<String>(line)
        .ok()
        .and_then(|b64| B64.decode(b64).ok());
    match bytes.and_then(|b| handshake::decode(&b).ok()) {
        Some(frame) => describe(&frame),
        None => "R".to_owned(),
    }
}

fn describe(frame: &HandshakeFrame) -> String {
    let (kind, from, to, nonce, body) = match frame {
        HandshakeFrame::Challenge {
            from,
            to,
            nonce,
            ct,
        } => ("chal", from, to, nonce, ct.as_slice()),
        HandshakeFrame::Proof {
            from,
            to,
            nonce,
            proof,
        } => ("proof", from, to, nonce, proof.as_slice()),
    };
    format!(
        "A {kind} {from} {to} {} {} {}",
        hex::encode(nonce),
        sha_hex(body),
        body.len()
    )
}

fn handshake_frame(line: &str) -> Option<HandshakeFrame> {
    let value: Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;
    let text = |k: &str| obj.get(k).and_then(Value::as_str);
    let bytes = |k: &str| text(k).and_then(|s| B64.decode(s).ok());
    let from = PeerId::parse(text("from")?).ok()?;
    let to = PeerId::parse(text("to")?).ok()?;
    let nonce = bytes("nonce")?.try_into().ok()?;
    match text("kind")? {
        "chal" => Some(HandshakeFrame::Challenge {
            from,
            to,
            nonce,
            ct: bytes("ct")?,
        }),
        "proof" => Some(HandshakeFrame::Proof {
            from,
            to,
            nonce,
            proof: bytes("proof")?.try_into().ok()?,
        }),
        _ => None,
    }
}

fn handshake_round(line: &str) -> String {
    let Some(frame) = handshake_frame(line) else {
        return "R".to_owned();
    };
    let Ok(bytes) = handshake::encode(&frame) else {
        return "R".to_owned();
    };
    match handshake::decode(&bytes) {
        Err(_) => "F encode produced bytes its own decoder refuses".to_owned(),
        Ok(back) if back == frame => "T".to_owned(),
        Ok(_) => "F fields".to_owned(),
    }
}

// ── noise ───────────────────────────────────────────────────────────────────
//
// frames  in: a JSON array of base64 chunks, fed to one FrameReader in order
//         out: `F <n> <sha256 of the frames, each u16-length-prefixed> <pending>`
// msg2    in: a JSON string of base64, read by an initiator in the state
//             vector case 0 leaves after msg1
//         out: `A <payloadHex> <handshakeHashHex>` or `R`
// Either: `X` for a line that is not the expected JSON.

fn noise_verdicts(mode: &str, raw: &str, vectors: &str) -> Result<String, String> {
    let case = first_case(&read(vectors)?)?;
    let mut out = String::new();
    for line in raw.split('\n').filter(|l| !l.is_empty()) {
        let verdict = if mode == "frames" {
            noise_frames(line)
        } else {
            noise_msg2(line, &case)
        };
        out.push_str(&verdict);
        out.push('\n');
    }
    Ok(out)
}

fn noise_frames(line: &str) -> String {
    let Ok(chunks) = serde_json::from_str::<Vec<String>>(line) else {
        return "X".to_owned();
    };
    let mut reader = FrameReader::default();
    let mut joined = Vec::new();
    let mut n = 0u64;
    for chunk in chunks {
        reader.push(&B64.decode(chunk).unwrap_or_default());
        while let Some(frame) = reader.next_frame() {
            n = n.saturating_add(1);
            let len = u16::try_from(frame.len()).unwrap_or(u16::MAX);
            joined.extend_from_slice(&len.to_be_bytes());
            joined.extend_from_slice(&frame);
        }
    }
    format!("F {n} {} {}", sha_hex(&joined), reader.pending())
}

/// What vector case 0 pins: the server's public keys, the client's ephemeral
/// secret, the KEM's output and msg1's payload.
struct Case {
    server: ServerStaticPublic,
    ephemeral: Vec<u8>,
    kem: PinnedKem,
    payload1: Vec<u8>,
}

fn first_case(json: &str) -> Result<Case, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("vectors: {e}"))?;
    let c = v
        .get("cases")
        .and_then(|c| c.get(0))
        .ok_or("vectors: no cases")?;
    let field = |k: &str| -> Result<Vec<u8>, String> {
        c.get(k)
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .ok_or_else(|| format!("vectors: case 0 has no {k}"))
    };
    let key_id = c
        .get("keyId")
        .and_then(Value::as_u64)
        .and_then(|k| u8::try_from(k).ok())
        .ok_or("vectors: case 0 has no keyId")?;
    Ok(Case {
        server: ServerStaticPublic {
            key_id,
            x25519: field("serverStaticPubHex")?
                .try_into()
                .map_err(|_| "vectors: serverStaticPubHex is not 32 bytes")?,
            hqc: PublicKey::from_bytes(&field("serverHqcPublicHex")?)
                .map_err(|e| format!("vectors: {e}"))?,
        },
        ephemeral: field("clientEphemeralPrivHex")?,
        kem: PinnedKem {
            ct: field("kemCiphertextHex")?,
            ss: field("kemSharedSecretHex")?
                .try_into()
                .map_err(|_| "vectors: kemSharedSecretHex is not 32 bytes")?,
        },
        payload1: field("payload1Hex")?,
    })
}

fn noise_msg2(line: &str, case: &Case) -> String {
    let Some(msg2) = serde_json::from_str::<String>(line)
        .ok()
        .and_then(|s| B64.decode(s).ok())
    else {
        return "X".to_owned();
    };
    let opened = HqnInitiator::new(case.server.clone(), &mut Fixed(case.ephemeral.clone()))
        .and_then(|mut client| {
            client.write_message1(&case.kem, &case.payload1)?;
            client.read_message2(&msg2)
        });
    match opened {
        Ok((payload, transport)) => format!(
            "A {} {}",
            hex::encode(payload),
            hex::encode(transport.handshake_hash)
        ),
        Err(_) => "R".to_owned(),
    }
}

/// Hands out pinned bytes in order: the vector's ephemeral key.
struct Fixed(Vec<u8>);

impl Entropy for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if self.0.len() < buf.len() {
            return Err(Error::Entropy);
        }
        let rest = self.0.split_off(buf.len());
        for (slot, byte) in buf.iter_mut().zip(&self.0) {
            *slot = *byte;
        }
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
