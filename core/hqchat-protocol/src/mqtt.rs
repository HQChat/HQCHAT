//! MQTT 3.1.1, the subset HQChat speaks: CONNECT/CONNACK (persistent session,
//! Last-Will, username/password), PUBLISH/PUBACK at QoS 0 and 1,
//! SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP and DISCONNECT.
//! One codec for every client, replacing Swift's `MQTTWireClient` coding and
//! the TS `mqtt` package, fuzzed once.
//!
//! Decoding is strict: anything the spec forbids or HQChat never sends (QoS
//! 2, reserved flag bits, packet id 0, a password without a username, bad
//! UTF-8) is an error, and an error fails the connection. A packet's claimed
//! size is checked against [`MAX_PACKET_BYTES`] before any of it is
//! buffered, so a hostile length cannot grow memory. An oversized PUBLISH is
//! the one exception to failing: anyone may publish into an inbox, and a
//! QoS 1 publish the client never acknowledges comes back on every
//! reconnect. It is skipped unbuffered and reported as
//! [`Packet::Oversized`], to be acknowledged and dropped.

use crate::Error;
use crate::wire::Reader;

/// The largest packet accepted. The largest legitimate one, a publish of an
/// `init` frame, is about 82 kB.
pub const MAX_PACKET_BYTES: usize = 256 * 1024;

const PROTOCOL_NAME: &str = "MQTT";
const PROTOCOL_LEVEL: u8 = 4;

/// Delivery guarantee of a publish or subscription. QoS 2 is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS {
    /// At most once.
    AtMostOnce,
    /// At least once.
    AtLeastOnce,
}

impl QoS {
    fn bits(self) -> u8 {
        match self {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce => 1,
        }
    }

    fn from_bits(bits: u8) -> Result<QoS, Error> {
        match bits {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            _ => Err(Error::Malformed("QoS 2 and 3 are not supported")),
        }
    }
}

/// The CONNECT's last will: presence goes offline when the link dies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    /// Topic.
    pub topic: String,
    /// Payload.
    pub payload: Vec<u8>,
    /// QoS (the apps use at-least-once).
    pub qos: QoS,
    /// Retained.
    pub retain: bool,
}

/// A control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Client → broker: open a session.
    Connect {
        /// The client id (`= username = id` for HQChat).
        client_id: String,
        /// The username.
        username: Option<String>,
        /// The password: the CONNECT proof (`mqtt_proof::sign_connect`).
        password: Option<Vec<u8>>,
        /// Seconds.
        keep_alive: u16,
        /// False: the broker keeps subscriptions and queues while offline.
        clean_session: bool,
        /// Presence offline.
        will: Option<Will>,
    },
    /// Broker → client: accepted (code 0) or refused.
    Connack {
        /// A previous session was resumed.
        session_present: bool,
        /// 0 accepted; otherwise refused.
        code: u8,
    },
    /// Either way: a message.
    Publish {
        /// Topic.
        topic: String,
        /// Payload.
        payload: Vec<u8>,
        /// QoS.
        qos: QoS,
        /// Retained.
        retain: bool,
        /// Present exactly when QoS is 1; never 0.
        packet_id: Option<u16>,
        /// A redelivery; only on QoS 1.
        dup: bool,
    },
    /// Acknowledges a QoS 1 publish.
    Puback {
        /// The publish's id.
        packet_id: u16,
    },
    /// Client → broker.
    Subscribe {
        /// Id, never 0.
        packet_id: u16,
        /// Filters and their QoS; at least one.
        filters: Vec<(String, QoS)>,
    },
    /// Broker → client: one code per filter, 0x80 refused.
    Suback {
        /// The subscribe's id.
        packet_id: u16,
        /// Granted QoS (0, 1, 2) or 0x80.
        codes: Vec<u8>,
    },
    /// Client → broker.
    Unsubscribe {
        /// Id, never 0.
        packet_id: u16,
        /// Filters; at least one.
        filters: Vec<String>,
    },
    /// Broker → client.
    Unsuback {
        /// The unsubscribe's id.
        packet_id: u16,
    },
    /// Keep-alive.
    Pingreq,
    /// Keep-alive answer.
    Pingresp,
    /// Client → broker: clean close (the will is not published).
    Disconnect,
    /// Decoded only: a PUBLISH over [`MAX_PACKET_BYTES`], whose body was
    /// skipped without being buffered. Acknowledge it (QoS 1) and drop it.
    Oversized {
        /// Its QoS.
        qos: QoS,
        /// Present exactly when QoS is 1.
        packet_id: Option<u16>,
    },
}

// ── Encoding ────────────────────────────────────────────────────────────────

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    let len =
        u16::try_from(b.len()).map_err(|_| Error::Invalid("a string or field over 65535 bytes"))?;
    put_u16(out, len);
    out.extend_from_slice(b);
    Ok(())
}

fn packet_id(id: u16) -> Result<u16, Error> {
    if id == 0 {
        Err(Error::Invalid("packet id 0 is reserved"))
    } else {
        Ok(id)
    }
}

/// The packet's wire bytes; refuses what [`Decoder`] would refuse.
pub fn encode(packet: &Packet) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    let header: u8 = match packet {
        Packet::Connect {
            client_id,
            username,
            password,
            keep_alive,
            clean_session,
            will,
        } => {
            if password.is_some() && username.is_none() {
                return Err(Error::Invalid("a password needs a username"));
            }
            put_bytes(&mut body, PROTOCOL_NAME.as_bytes())?;
            body.push(PROTOCOL_LEVEL);
            let mut flags = 0u8;
            if username.is_some() {
                flags |= 0x80;
            }
            if password.is_some() {
                flags |= 0x40;
            }
            if let Some(w) = will {
                flags |= 0x04 | (w.qos.bits() << 3) | if w.retain { 0x20 } else { 0 };
            }
            if *clean_session {
                flags |= 0x02;
            }
            body.push(flags);
            put_u16(&mut body, *keep_alive);
            put_bytes(&mut body, client_id.as_bytes())?;
            if let Some(w) = will {
                put_bytes(&mut body, w.topic.as_bytes())?;
                put_bytes(&mut body, &w.payload)?;
            }
            if let Some(u) = username {
                put_bytes(&mut body, u.as_bytes())?;
            }
            if let Some(p) = password {
                put_bytes(&mut body, p)?;
            }
            0x10
        }
        Packet::Connack {
            session_present,
            code,
        } => {
            body.extend_from_slice(&[u8::from(*session_present), *code]);
            0x20
        }
        Packet::Publish {
            topic,
            payload,
            qos,
            retain,
            packet_id: id,
            dup,
        } => {
            put_bytes(&mut body, topic.as_bytes())?;
            match (qos, id) {
                (QoS::AtLeastOnce, Some(id)) => put_u16(&mut body, packet_id(*id)?),
                (QoS::AtMostOnce, None) if !dup => {}
                _ => return Err(Error::Invalid("a packet id and dup go with QoS 1 only")),
            }
            body.extend_from_slice(payload);
            0x30 | (u8::from(*dup) << 3) | (qos.bits() << 1) | u8::from(*retain)
        }
        Packet::Puback { packet_id: id } => {
            put_u16(&mut body, packet_id(*id)?);
            0x40
        }
        Packet::Subscribe {
            packet_id: id,
            filters,
        } => {
            if filters.is_empty() {
                return Err(Error::Invalid("a subscribe needs a filter"));
            }
            put_u16(&mut body, packet_id(*id)?);
            for (filter, qos) in filters {
                put_bytes(&mut body, filter.as_bytes())?;
                body.push(qos.bits());
            }
            0x82
        }
        Packet::Suback {
            packet_id: id,
            codes,
        } => {
            if codes.is_empty() || codes.iter().any(|c| !matches!(c, 0 | 1 | 2 | 0x80)) {
                return Err(Error::Invalid(
                    "suback codes are 0, 1, 2 or 0x80, at least one",
                ));
            }
            put_u16(&mut body, packet_id(*id)?);
            body.extend_from_slice(codes);
            0x90
        }
        Packet::Unsubscribe {
            packet_id: id,
            filters,
        } => {
            if filters.is_empty() {
                return Err(Error::Invalid("an unsubscribe needs a filter"));
            }
            put_u16(&mut body, packet_id(*id)?);
            for filter in filters {
                put_bytes(&mut body, filter.as_bytes())?;
            }
            0xa2
        }
        Packet::Unsuback { packet_id: id } => {
            put_u16(&mut body, packet_id(*id)?);
            0xb0
        }
        Packet::Pingreq => 0xc0,
        Packet::Pingresp => 0xd0,
        Packet::Disconnect => 0xe0,
        Packet::Oversized { .. } => {
            return Err(Error::Invalid("an oversized publish is never sent"));
        }
    };
    let mut out = Vec::with_capacity(body.len().saturating_add(5));
    out.push(header);
    put_remaining_length(&mut out, body.len())?;
    if out.len().saturating_add(body.len()) > MAX_PACKET_BYTES {
        return Err(Error::Invalid("packet over MAX_PACKET_BYTES"));
    }
    out.extend_from_slice(&body);
    Ok(out)
}

/// MQTT's remaining length: 7 bits per byte, high bit = continuation.
fn put_remaining_length(out: &mut Vec<u8>, mut len: usize) -> Result<(), Error> {
    if len > 268_435_455 {
        return Err(Error::Invalid("remaining length over four bytes"));
    }
    loop {
        let mut byte = u8::try_from(len % 128).map_err(|_| Error::Invalid("remaining length"))?;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            return Ok(());
        }
    }
}

// ── Decoding ────────────────────────────────────────────────────────────────

/// Splits a byte stream into packets.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    /// Bytes of an oversized publish still to arrive, dropped as they do.
    skip: usize,
}

impl Decoder {
    /// Appends bytes as they arrive.
    pub fn push(&mut self, chunk: &[u8]) {
        let skipped = self.skip.min(chunk.len());
        self.skip = self.skip.saturating_sub(skipped);
        self.buffer
            .extend_from_slice(chunk.get(skipped..).unwrap_or_default());
    }

    /// The next complete packet; `Ok(None)` until one has arrived, an error
    /// for bytes that can never become one (close the connection then).
    pub fn next_packet(&mut self) -> Result<Option<Packet>, Error> {
        let Some((remaining, len_bytes)) = remaining_length(&self.buffer)? else {
            return Ok(None);
        };
        let header_len = len_bytes.saturating_add(1);
        let total = header_len.saturating_add(remaining);
        if total > MAX_PACKET_BYTES {
            return self.skip_oversized(header_len, total);
        }
        let (Some(&header), Some(body)) = (self.buffer.first(), self.buffer.get(header_len..total))
        else {
            return Ok(None);
        };
        let packet = parse(header, body);
        self.buffer.drain(..total);
        packet.map(Some)
    }

    /// Bytes buffered and not yet a whole packet.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// An oversized packet: an error unless it is a PUBLISH, which is
    /// reported once its topic and packet id are in, then skipped.
    fn skip_oversized(&mut self, header_len: usize, total: usize) -> Result<Option<Packet>, Error> {
        let Some(&header) = self.buffer.first() else {
            return Ok(None);
        };
        let (kind, flags) = (header >> 4, header & 0x0f);
        if kind != 3 {
            return Err(Error::Malformed("packet over MAX_PACKET_BYTES"));
        }
        let qos = QoS::from_bits((flags >> 1) & 0x03)?;
        let mut c = Reader::new(self.buffer.get(header_len..).unwrap_or_default(), "");
        // The topic (at most 64 KiB) and the id: buffered like any header.
        let Ok(_topic) = field(&mut c) else {
            return Ok(None);
        };
        let packet_id = match qos {
            QoS::AtMostOnce => None,
            QoS::AtLeastOnce => match c.u16() {
                Ok(0) => return Err(Error::Malformed("packet id 0 is reserved")),
                Ok(id) => Some(id),
                Err(_) => return Ok(None),
            },
        };
        let have = self.buffer.len().min(total);
        self.buffer.drain(..have);
        self.skip = total.saturating_sub(have);
        Ok(Some(Packet::Oversized { qos, packet_id }))
    }
}

/// The remaining length after the fixed-header byte and how many bytes it
/// took, `None` while incomplete; an error past four bytes.
fn remaining_length(buf: &[u8]) -> Result<Option<(usize, usize)>, Error> {
    let mut value = 0usize;
    let digits = buf.get(1..).unwrap_or_default();
    for (used, (&byte, shift)) in (1usize..).zip(digits.iter().zip([0u32, 7, 14, 21])) {
        let digit = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Error::Malformed("remaining length"))?;
        value |= digit;
        if byte & 0x80 == 0 {
            // A final 0 after a continuation is a longer encoding of a
            // shorter length: refused, so every length has one encoding.
            if byte == 0 && used > 1 {
                return Err(Error::Malformed("remaining length is not minimal"));
            }
            return Ok(Some((value, used)));
        }
    }
    if buf.len() > 4 {
        Err(Error::Malformed("remaining length runs past four bytes"))
    } else {
        Ok(None)
    }
}

/// A length-prefixed MQTT field.
fn field<'a>(c: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let n = c.u16()?;
    c.take(usize::from(n))
}

/// A length-prefixed MQTT UTF-8 string.
fn string(c: &mut Reader<'_>) -> Result<String, Error> {
    std::str::from_utf8(field(c)?)
        .map(str::to_owned)
        .map_err(|_| Error::Malformed("a string is not UTF-8"))
}

/// A packet id, which is never 0.
fn id(c: &mut Reader<'_>) -> Result<u16, Error> {
    match c.u16()? {
        0 => Err(Error::Malformed("packet id 0 is reserved")),
        id => Ok(id),
    }
}

/// Succeeds only when the packet body has been read to its end.
fn end(c: Reader<'_>) -> Result<(), Error> {
    c.finish()
        .map_err(|_| Error::Malformed("trailing bytes in a packet"))
}

fn parse(header: u8, body: &[u8]) -> Result<Packet, Error> {
    let (kind, flags) = (header >> 4, header & 0x0f);
    let mut c = Reader::new(body, "packet body too short");
    let expect_flags = |want: u8| {
        if flags == want {
            Ok(())
        } else {
            Err(Error::Malformed("reserved fixed-header flags"))
        }
    };
    let packet = match kind {
        1 => {
            expect_flags(0)?;
            if string(&mut c)? != PROTOCOL_NAME || c.u8()? != PROTOCOL_LEVEL {
                return Err(Error::Malformed("not MQTT 3.1.1"));
            }
            let f = c.u8()?;
            let (has_user, has_pass, will_retain, will_qos, has_will) = (
                f & 0x80 != 0,
                f & 0x40 != 0,
                f & 0x20 != 0,
                (f >> 3) & 0x03,
                f & 0x04 != 0,
            );
            if f & 0x01 != 0
                || (has_pass && !has_user)
                || (!has_will && (will_retain || will_qos != 0))
            {
                return Err(Error::Malformed("bad CONNECT flags"));
            }
            let keep_alive = c.u16()?;
            let client_id = string(&mut c)?;
            let will = if has_will {
                Some(Will {
                    topic: string(&mut c)?,
                    payload: field(&mut c)?.to_vec(),
                    qos: QoS::from_bits(will_qos)?,
                    retain: will_retain,
                })
            } else {
                None
            };
            let username = if has_user {
                Some(string(&mut c)?)
            } else {
                None
            };
            let password = if has_pass {
                Some(field(&mut c)?.to_vec())
            } else {
                None
            };
            end(c)?;
            Packet::Connect {
                client_id,
                username,
                password,
                keep_alive,
                clean_session: f & 0x02 != 0,
                will,
            }
        }
        2 => {
            expect_flags(0)?;
            let ack = c.u8()?;
            if ack & !0x01 != 0 {
                return Err(Error::Malformed("bad CONNACK flags"));
            }
            let code = c.u8()?;
            end(c)?;
            Packet::Connack {
                session_present: ack == 1,
                code,
            }
        }
        3 => {
            let qos = QoS::from_bits((flags >> 1) & 0x03)?;
            let dup = flags & 0x08 != 0;
            if dup && qos == QoS::AtMostOnce {
                return Err(Error::Malformed("dup on a QoS 0 publish"));
            }
            let topic = string(&mut c)?;
            let packet_id = if qos == QoS::AtLeastOnce {
                Some(id(&mut c)?)
            } else {
                None
            };
            Packet::Publish {
                topic,
                payload: c.rest().to_vec(),
                qos,
                retain: flags & 0x01 != 0,
                packet_id,
                dup,
            }
        }
        4 | 11 => {
            expect_flags(0)?;
            let packet_id = id(&mut c)?;
            end(c)?;
            if kind == 4 {
                Packet::Puback { packet_id }
            } else {
                Packet::Unsuback { packet_id }
            }
        }
        8 => {
            expect_flags(0x02)?;
            let packet_id = id(&mut c)?;
            let mut filters = Vec::new();
            while !c.is_empty() {
                let filter = string(&mut c)?;
                filters.push((filter, QoS::from_bits(c.u8()?)?));
            }
            if filters.is_empty() {
                return Err(Error::Malformed("a subscribe without a filter"));
            }
            Packet::Subscribe { packet_id, filters }
        }
        9 => {
            expect_flags(0)?;
            let packet_id = id(&mut c)?;
            let codes = c.rest().to_vec();
            if codes.is_empty() || codes.iter().any(|b| !matches!(b, 0 | 1 | 2 | 0x80)) {
                return Err(Error::Malformed("bad SUBACK codes"));
            }
            Packet::Suback { packet_id, codes }
        }
        10 => {
            expect_flags(0x02)?;
            let packet_id = id(&mut c)?;
            let mut filters = Vec::new();
            while !c.is_empty() {
                filters.push(string(&mut c)?);
            }
            if filters.is_empty() {
                return Err(Error::Malformed("an unsubscribe without a filter"));
            }
            Packet::Unsubscribe { packet_id, filters }
        }
        12..=14 => {
            expect_flags(0)?;
            end(c)?;
            match kind {
                12 => Packet::Pingreq,
                13 => Packet::Pingresp,
                _ => Packet::Disconnect,
            }
        }
        _ => return Err(Error::Malformed("a packet type HQChat does not speak")),
    };
    Ok(packet)
}
