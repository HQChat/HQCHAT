//! Frames a stranger can build from public values, delivered as the broker would.
#![allow(dead_code, missing_docs)]

use hqchat_engine::Effect;
use hqchat_protocol::envelope::{self, Frame, Header, InitFields, Kind};
use hqchat_protocol::{PeerId, ratchet};

use crate::support::Client;

pub fn conn_of(c: &Client) -> u64 {
    c.seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .unwrap()
}

pub fn publish_bytes(topic: &str, pid: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u16::try_from(topic.len()).unwrap().to_be_bytes());
    body.extend(topic.as_bytes());
    body.extend(pid.to_be_bytes());
    body.extend(payload);
    let mut out = vec![0x32];
    let mut len = body.len();
    loop {
        let mut b = u8::try_from(len % 128).unwrap();
        len /= 128;
        if len > 0 {
            b |= 0x80;
        }
        out.push(b);
        if len == 0 {
            break;
        }
    }
    out.extend(body);
    out
}

/// The fixed, session-defining part of a forged init: whatever the attacker
/// picks, encapsulated to the victim's public identity key.
pub struct ForgedInit {
    pub sender: PeerId,
    pub sender_pk: Vec<u8>,
    pub to: PeerId,
    pub rk: Vec<u8>,
    pub ct_id: Vec<u8>,
    pub ct_mt: Vec<u8>,
}

impl ForgedInit {
    pub fn new(sender_pk_hex: &str, to_pk_hex: &str) -> Self {
        let sender_pk = hex::decode(sender_pk_hex).unwrap();
        let to_pk = hqc::PublicKey::from_bytes(&hex::decode(to_pk_hex).unwrap()).unwrap();
        let (ct_id, _) = hqc::encapsulate(&to_pk).unwrap();
        let (ct_mt, _) = hqc::encapsulate(&to_pk).unwrap();
        ForgedInit {
            sender: PeerId::of_hex(sender_pk_hex),
            sender_pk,
            to: PeerId::of_hex(to_pk_hex),
            rk: hqc::generate_keypair().unwrap().public.as_bytes().to_vec(),
            ct_id: ct_id.as_bytes().to_vec(),
            ct_mt: ct_mt.as_bytes().to_vec(),
        }
    }

    pub fn frame(&self, msg_id: &str, payload_len: usize) -> Vec<u8> {
        let header = Header {
            kind: Kind::Init,
            sender: self.sender.clone(),
            to: self.to.clone(),
            msg_id: msg_id.into(),
            cid: ratchet::chain_id(&self.rk),
            n: 0,
            pn: 0,
            rk: Some(self.rk.clone()),
            kem_ct: None,
            init: Some(InitFields {
                sender_pk: self.sender_pk.clone(),
                ct_id: self.ct_id.clone(),
                ct_mt: self.ct_mt.clone(),
            }),
            one_time: None,
        };
        envelope::encode(&Frame {
            header,
            payload: vec![0x5a; payload_len],
        })
        .unwrap()
    }
}

/// A `msg` frame claiming `sender`, with junk ciphertext: what a stranger can
/// publish into any inbox.
pub fn forged_msg(sender: &PeerId, to: &PeerId, msg_id: &str) -> Vec<u8> {
    let header = Header {
        kind: Kind::Msg,
        sender: sender.clone(),
        to: to.clone(),
        msg_id: msg_id.into(),
        cid: [7; 16],
        n: 0,
        pn: 0,
        rk: None,
        kem_ct: None,
        init: None,
        one_time: None,
    };
    envelope::encode(&Frame {
        header,
        payload: vec![0x5a; 64],
    })
    .unwrap()
}
