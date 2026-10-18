//! MQTT 3.1.1, the subset HQChat speaks, replacing Swift's `MQTTWireClient`
//! and the TS `mqtt` package: one codec, fuzzed once.

use crate::Error;

/// Delivery guarantee of a publish or subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS {
    /// At most once.
    AtMostOnce,
    /// At least once.
    AtLeastOnce,
}

/// The CONNECT's last will: presence goes offline when the link dies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    /// Topic.
    pub topic: String,
    /// Payload.
    pub payload: Vec<u8>,
    /// Retained.
    pub retain: bool,
}

/// A control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Client → broker: open a session.
    Connect {
        /// `username = clientid = id`.
        client_id: String,
        /// The CONNECT proof (`mqtt_proof::sign_connect`).
        password: String,
        /// Seconds.
        keep_alive: u16,
        /// False: the broker keeps subscriptions and queues while offline.
        clean_session: bool,
        /// Presence offline.
        will: Option<Will>,
    },
    /// Broker → client: accepted (0) or refused.
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
        /// Present on QoS 1.
        packet_id: Option<u16>,
        /// A redelivery.
        dup: bool,
    },
    /// Acknowledges a QoS 1 publish.
    Puback {
        /// The publish's id.
        packet_id: u16,
    },
    /// Client → broker.
    Subscribe {
        /// Id.
        packet_id: u16,
        /// Filters and their QoS.
        filters: Vec<(String, QoS)>,
    },
    /// Broker → client: one code per filter, 0x80 refused.
    Suback {
        /// The subscribe's id.
        packet_id: u16,
        /// Granted QoS or 0x80.
        codes: Vec<u8>,
    },
    /// Client → broker.
    Unsubscribe {
        /// Id.
        packet_id: u16,
        /// Filters.
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
}

/// The packet's wire bytes.
pub fn encode(packet: &Packet) -> Result<Vec<u8>, Error> {
    todo!("lib/protocol-mqtt-codec")
}

/// Splits a byte stream into packets.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    /// Appends bytes as they arrive.
    pub fn push(&mut self, chunk: &[u8]) {
        todo!("lib/protocol-mqtt-codec")
    }

    /// The next complete packet; `Ok(None)` until one has arrived, an error
    /// for bytes that can never become one (the connection is then closed).
    pub fn next_packet(&mut self) -> Result<Option<Packet>, Error> {
        todo!("lib/protocol-mqtt-codec")
    }
}
