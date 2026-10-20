//! The client-to-client frame (v3): length-prefixed binary whose header is
//! also the AAD the payload is sealed against. A receiver binds the exact
//! bytes that arrived; there is no second canonical encoding.
//!
//! ```text
//! 0   magic "HQCE" · 4 version u8 (3) · 5 kind u8 · 6 flags u8
//!     (bit0 rk, bit1 kemCt, bit2 one-time, bit3 padded payload)
//! 7   sender 32 B · 39 to 32 B · 71 cid 16 B · 87 n u32 · 91 pn u32
//! 95  msgIdLen u8 (1..128) · 96 msgId UTF-8
//!     [rk] [kemCt] [init: senderPk, ctId, ctMt] [oneTime: ctOt, otId u32]
//!     payload
//! ```
//!
//! Every blob is a `u32` big-endian length and that many bytes, never empty.
//! Keys and ciphertexts are raw bytes here, as on the wire: their sizes are
//! the ratchet's to check, exactly as in the TS and Swift decoders, so all
//! three accept and refuse the same frames. Encoders refuse rather than pad,
//! clip or wrap, so every implementation produces the same bytes or none.

use crate::wire::{Reader, len_u8, len_u32, usize_from};
use crate::{Error, PeerId};

/// The frame version this crate speaks.
pub const FRAME_VERSION: u8 = 3;
/// The longest message id, in bytes.
pub const MAX_MSG_ID_BYTES: usize = 128;
/// Upper bound on any blob, so a hostile length is not an allocation request.
pub const MAX_FIELD_BYTES: usize = 1 << 20;

const MAGIC: &[u8; 4] = b"HQCE";
const FLAG_RK: u8 = 0x01;
const FLAG_KEMCT: u8 = 0x02;
const FLAG_ONE_TIME: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const ALL_FLAGS: u8 = FLAG_RK | FLAG_KEMCT | FLAG_ONE_TIME | FLAG_PADDED;
/// Where the message id starts: everything before it has a fixed size.
const OFF_MSGID: usize = 96;

/// Whether a frame opens a session, carries a message, or acknowledges one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A message inside a session (byte 0).
    Msg,
    /// A message that also opens the session (byte 1).
    Init,
    /// A delivery receipt for the message whose id it carries (byte 2).
    Receipt,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Msg => 0,
            Kind::Init => 1,
            Kind::Receipt => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Kind> {
        match b {
            0 => Some(Kind::Msg),
            1 => Some(Kind::Init),
            2 => Some(Kind::Receipt),
            _ => None,
        }
    }
}

/// The handshake fields only an `init` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitFields {
    /// The initiator's identity key; must hash to `sender`.
    pub sender_pk: Vec<u8>,
    /// Encapsulated to the responder's identity key.
    pub ct_id: Vec<u8>,
    /// Encapsulated to the responder's medium-term prekey.
    pub ct_mt: Vec<u8>,
}

/// A one-time prekey encapsulation and the id of the prekey it used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTime {
    /// Encapsulated to the one-time prekey.
    pub ct_ot: Vec<u8>,
    /// Which one-time prekey.
    pub ot_id: u32,
}

/// Every header field: what the AAD is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Kind of frame.
    pub kind: Kind,
    /// Sender's client id.
    pub sender: PeerId,
    /// Recipient's client id.
    pub to: PeerId,
    /// Message id (1..128 bytes of UTF-8); a receipt carries the acknowledged one.
    pub msg_id: String,
    /// Chain selector: `chain_id` of the sender's current ratchet key.
    pub cid: [u8; 16],
    /// Index in the sending chain.
    pub n: u32,
    /// Length of the previous sending chain.
    pub pn: u32,
    /// The sender's new ratchet public key: on every `init`, and on a step.
    pub rk: Option<Vec<u8>>,
    /// Encapsulated to the receiver's previous ratchet key, on a step.
    pub kem_ct: Option<Vec<u8>>,
    /// On `init` only.
    pub init: Option<InitFields>,
    /// While the responder's one-time pool lasted.
    pub one_time: Option<OneTime>,
    /// The sealed plaintext is padded (`padding::pad`).
    pub padded: bool,
}

/// A whole frame: header and sealed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The header.
    pub header: Header,
    /// The AES-GCM sealed payload (`aead::seal_payload`).
    pub payload: Vec<u8>,
}

/// Why these fields cannot make a well-formed frame, or `Ok` when they can.
/// The reasons are worded as in `envelope.ts`.
pub fn validate(h: &Header) -> Result<(), Error> {
    if h.msg_id.is_empty() || h.msg_id.len() > MAX_MSG_ID_BYTES {
        return Err(Error::Invalid("msgId is empty or over 128 bytes"));
    }
    let blobs = [
        ("rk", h.rk.as_deref()),
        ("kemCt", h.kem_ct.as_deref()),
        ("senderPk", h.init.as_ref().map(|i| i.sender_pk.as_slice())),
        ("ctId", h.init.as_ref().map(|i| i.ct_id.as_slice())),
        ("ctMt", h.init.as_ref().map(|i| i.ct_mt.as_slice())),
        ("ctOt", h.one_time.as_ref().map(|o| o.ct_ot.as_slice())),
    ];
    for (_name, blob) in blobs {
        match blob {
            Some([]) => return Err(Error::Invalid("a field is present but empty")),
            Some(b) if b.len() > MAX_FIELD_BYTES => {
                return Err(Error::Invalid("a field is implausibly large"));
            }
            _ => {}
        }
    }
    match (h.kind, &h.init) {
        (Kind::Init, None) => return Err(Error::Invalid("an init needs ctId and ctMt")),
        (Kind::Msg | Kind::Receipt, Some(_)) => {
            return Err(Error::Invalid(
                "only an init carries senderPk, ctId and ctMt",
            ));
        }
        _ => {}
    }
    if h.kind == Kind::Init {
        if h.rk.is_none() {
            return Err(Error::Invalid("an init must advertise rk"));
        }
        if h.kem_ct.is_some() {
            return Err(Error::Invalid("an init must not carry a kemCt"));
        }
        if let Some(init) = &h.init
            && PeerId::of_hex(&hex::encode(&init.sender_pk)) != h.sender
        {
            return Err(Error::Invalid("senderPk does not hash to sender"));
        }
    } else if h.rk.is_some() != h.kem_ct.is_some() {
        return Err(Error::Invalid(
            "a msg carries rk and kemCt together or not at all",
        ));
    }
    Ok(())
}

/// The header bytes: the AAD to seal the payload against.
pub fn header_bytes(h: &Header) -> Result<Vec<u8>, Error> {
    validate(h)?;
    let flags = (if h.rk.is_some() { FLAG_RK } else { 0 })
        | (if h.kem_ct.is_some() { FLAG_KEMCT } else { 0 })
        | (if h.one_time.is_some() {
            FLAG_ONE_TIME
        } else {
            0
        })
        | (if h.padded { FLAG_PADDED } else { 0 });
    let mut out = Vec::with_capacity(OFF_MSGID.saturating_add(h.msg_id.len()));
    out.extend_from_slice(MAGIC);
    out.push(FRAME_VERSION);
    out.push(h.kind.byte());
    out.push(flags);
    out.extend_from_slice(&h.sender.to_bytes());
    out.extend_from_slice(&h.to.to_bytes());
    out.extend_from_slice(&h.cid);
    out.extend_from_slice(&h.n.to_be_bytes());
    out.extend_from_slice(&h.pn.to_be_bytes());
    out.push(len_u8(h.msg_id.len(), "msgId is empty or over 128 bytes")?);
    out.extend_from_slice(h.msg_id.as_bytes());
    if let Some(rk) = &h.rk {
        put_blob(&mut out, rk)?;
    }
    if let Some(kem_ct) = &h.kem_ct {
        put_blob(&mut out, kem_ct)?;
    }
    if let Some(init) = &h.init {
        put_blob(&mut out, &init.sender_pk)?;
        put_blob(&mut out, &init.ct_id)?;
        put_blob(&mut out, &init.ct_mt)?;
    }
    if let Some(one_time) = &h.one_time {
        put_blob(&mut out, &one_time.ct_ot)?;
        out.extend_from_slice(&one_time.ot_id.to_be_bytes());
    }
    Ok(out)
}

/// The frame's wire bytes; derives the same header as [`header_bytes`].
pub fn encode(frame: &Frame) -> Result<Vec<u8>, Error> {
    if frame.payload.is_empty() {
        return Err(Error::Invalid("the payload is empty"));
    }
    if frame.payload.len() > MAX_FIELD_BYTES {
        return Err(Error::Invalid("the payload is implausibly large"));
    }
    let mut out = header_bytes(&frame.header)?;
    put_blob(&mut out, &frame.payload)?;
    Ok(out)
}

/// A cheap check of magic and version, before a full decode.
pub fn looks_like_frame(raw: &[u8]) -> bool {
    raw.len() >= OFF_MSGID && raw.starts_with(MAGIC) && raw.get(MAGIC.len()) == Some(&FRAME_VERSION)
}

/// Decodes a frame and returns it with its AAD, the header bytes exactly as
/// they arrived. Refuses unknown kinds and flags, broken pairing rules, empty
/// or oversized fields, invalid UTF-8, trailing bytes, and an init whose
/// `senderPk` does not hash to `sender`.
pub fn decode(raw: &[u8]) -> Result<(Frame, Vec<u8>), Error> {
    if !looks_like_frame(raw) {
        return Err(Error::Malformed("not a v3 frame"));
    }
    let mut r = Reader::new(raw, "truncated");
    r.take(MAGIC.len().saturating_add(1))?;
    let kind = Kind::from_byte(r.u8()?).ok_or(Error::Malformed("unknown kind"))?;
    let flags = r.u8()?;
    if flags & !ALL_FLAGS != 0 {
        return Err(Error::Malformed("unknown flag"));
    }
    let has_rk = flags & FLAG_RK != 0;
    let has_kem_ct = flags & FLAG_KEMCT != 0;
    let has_one_time = flags & FLAG_ONE_TIME != 0;
    let padded = flags & FLAG_PADDED != 0;
    match kind {
        Kind::Init if !has_rk || has_kem_ct => {
            return Err(Error::Malformed("an init carries rk and no kemCt"));
        }
        Kind::Msg | Kind::Receipt if has_rk != has_kem_ct => {
            return Err(Error::Malformed("rk and kemCt travel together"));
        }
        _ => {}
    }
    let sender = PeerId::from_bytes(r.array()?);
    let to = PeerId::from_bytes(r.array()?);
    let cid = *r.array::<16>()?;
    let n = r.u32()?;
    let pn = r.u32()?;

    let msg_id_len = usize::from(r.u8()?);
    if msg_id_len == 0 || msg_id_len > MAX_MSG_ID_BYTES || r.remaining() < msg_id_len {
        return Err(Error::Malformed("bad msgId length"));
    }
    let msg_id = std::str::from_utf8(r.take(msg_id_len)?)
        .map_err(|_| Error::Malformed("msgId is not UTF-8"))?
        .to_owned();

    let rk = if has_rk { Some(blob(&mut r)?) } else { None };
    let kem_ct = if has_kem_ct {
        Some(blob(&mut r)?)
    } else {
        None
    };
    let init = if kind == Kind::Init {
        Some(InitFields {
            sender_pk: blob(&mut r)?,
            ct_id: blob(&mut r)?,
            ct_mt: blob(&mut r)?,
        })
    } else {
        None
    };
    let one_time = if has_one_time {
        Some(OneTime {
            ct_ot: blob(&mut r)?,
            ot_id: r.u32()?,
        })
    } else {
        None
    };
    let header_len = raw.len().saturating_sub(r.remaining());
    let payload = blob(&mut r)?;
    r.finish()?;

    if let Some(init) = &init
        && PeerId::of_hex(&hex::encode(&init.sender_pk)) != sender
    {
        return Err(Error::Malformed("senderPk does not hash to sender"));
    }
    let aad = raw
        .get(..header_len)
        .ok_or(Error::Malformed("truncated"))?
        .to_vec();
    let header = Header {
        kind,
        sender,
        to,
        msg_id,
        cid,
        n,
        pn,
        rk,
        kem_ct,
        init,
        one_time,
        padded,
    };
    Ok((Frame { header, payload }, aad))
}

fn put_blob(out: &mut Vec<u8>, blob: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(&len_u32(blob.len(), "a field is implausibly large")?.to_be_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

/// A length-prefixed field, refusing anything short, oversized or empty.
fn blob(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
    let len = usize_from(r.u32()?);
    if len == 0 || len > MAX_FIELD_BYTES {
        return Err(Error::Malformed("empty or oversized field"));
    }
    Ok(r.take(len)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(fill: u8) -> PeerId {
        PeerId::of_hex(&hex::encode([fill; 7237]))
    }

    fn msg() -> Header {
        Header {
            kind: Kind::Msg,
            sender: id(1),
            to: id(2),
            msg_id: "01HQZX9K2M4N6P8R".into(),
            cid: *b"0123456789abcdef",
            n: 4,
            pn: 1,
            rk: None,
            kem_ct: None,
            init: None,
            one_time: None,
            padded: false,
        }
    }

    fn init() -> Header {
        let sender_pk = vec![0x11; 7237];
        Header {
            kind: Kind::Init,
            sender: PeerId::of_hex(&hex::encode(&sender_pk)),
            rk: Some(vec![0x33; 32]),
            init: Some(InitFields {
                sender_pk,
                ct_id: vec![0x44; 64],
                ct_mt: vec![0x55; 64],
            }),
            ..msg()
        }
    }

    #[test]
    fn a_frame_round_trips_and_hands_back_its_aad() {
        for header in [msg(), init()] {
            let aad = header_bytes(&header).unwrap();
            let frame = Frame {
                header,
                payload: vec![9; 40],
            };
            let (got, got_aad) = decode(&encode(&frame).unwrap()).unwrap();
            assert_eq!(got, frame);
            assert_eq!(got_aad, aad);
        }
    }

    #[test]
    fn the_pairing_rules_hold_on_the_way_out() {
        let half_step = Header {
            rk: Some(vec![1]),
            ..msg()
        };
        assert!(
            header_bytes(&half_step).is_err(),
            "a msg with rk and no kemCt"
        );
        let full_step = Header {
            rk: Some(vec![1]),
            kem_ct: Some(vec![2]),
            ..msg()
        };
        assert!(header_bytes(&full_step).is_ok());

        assert!(
            header_bytes(&Header {
                kem_ct: Some(vec![2]),
                ..init()
            })
            .is_err(),
            "an init with a kemCt"
        );
        assert!(
            header_bytes(&Header { rk: None, ..init() }).is_err(),
            "an init without rk"
        );
        assert!(
            header_bytes(&Header {
                init: None,
                ..init()
            })
            .is_err(),
            "an init without its fields"
        );
        assert!(
            header_bytes(&Header {
                kind: Kind::Msg,
                ..init()
            })
            .is_err(),
            "init fields on a msg"
        );
    }

    #[test]
    fn the_encoders_refuse_what_could_not_be_read_back() {
        assert!(
            header_bytes(&Header {
                msg_id: String::new(),
                ..msg()
            })
            .is_err()
        );
        assert!(
            header_bytes(&Header {
                msg_id: "é".repeat(65),
                ..msg()
            })
            .is_err(),
            "130 bytes"
        );
        assert!(
            header_bytes(&Header {
                msg_id: "é".repeat(64),
                ..msg()
            })
            .is_ok(),
            "128 bytes"
        );
        assert!(
            header_bytes(&Header {
                rk: Some(vec![]),
                kem_ct: Some(vec![1]),
                ..msg()
            })
            .is_err()
        );
        let substituted = Header {
            sender: id(9),
            ..init()
        };
        assert!(
            header_bytes(&substituted).is_err(),
            "a senderPk that does not hash to sender"
        );
        assert!(
            encode(&Frame {
                header: msg(),
                payload: vec![]
            })
            .is_err(),
            "an empty payload"
        );
    }
}
