//! The hqn/1 responder for `src/gateway/gateway.ts`, replacing
//! `protocol/noise.ts`'s `HqnResponder`, `FrameReader` and transport.

use hqc::{KeyPair, SharedSecret};
use hqchat_protocol::noise::{
    self, FrameReader, HqnResponder, ServerStatic, Transport, X25519Secret,
};
use hqchat_protocol::{OsEntropy, wire};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::err;

/// The gateway's static keys: its X25519 secret and the 32-byte seed of its
/// HQC keypair, as the key file holds them.
#[napi(object)]
pub struct GatewayKey {
    /// Which key pair, during a rotation.
    pub key_id: u8,
    /// X25519 secret, 32 bytes.
    pub x25519: Buffer,
    /// HQC seed, 32 bytes.
    pub hqc_seed: Buffer,
}

/// The public half, as `/auth/transport` advertises it.
#[napi(object)]
pub struct GatewayPublicKey {
    /// Which key pair.
    pub key_id: u8,
    /// X25519 public key, 32 bytes.
    pub x25519: Buffer,
    /// HQC public key, 7237 bytes.
    pub hqc: Buffer,
}

fn server_static(k: &GatewayKey) -> napi::Result<ServerStatic> {
    let x: [u8; 32] = k
        .x25519
        .as_ref()
        .try_into()
        .map_err(|_| err("x25519 is 32 bytes"))?;
    let seed: [u8; 32] = k
        .hqc_seed
        .as_ref()
        .try_into()
        .map_err(|_| err("hqcSeed is 32 bytes"))?;
    let hqc: KeyPair = hqc::keypair_from_seed(&hqc::Seed::from_bytes(seed)).map_err(err)?;
    Ok(ServerStatic {
        key_id: k.key_id,
        x25519: X25519Secret(x),
        hqc,
    })
}

/// The `hqn/1` version byte that opens every connection.
#[napi]
pub const HQN_VERSION: u8 = noise::HQN_VERSION;

/// A gateway key pair, derived once from its seeds: the HQC key generation
/// takes milliseconds, so it happens at startup and never per connection.
#[napi]
pub struct GatewayKeyPair {
    server: ServerStatic,
}

#[napi]
impl GatewayKeyPair {
    /// Derives the key pair from the key file's seeds.
    #[napi(constructor)]
    pub fn new(key: GatewayKey) -> napi::Result<Self> {
        Ok(Self {
            server: server_static(&key)?,
        })
    }

    /// Which key pair, during a rotation.
    #[napi(getter)]
    pub fn key_id(&self) -> u8 {
        self.server.key_id
    }

    /// The public half, as `/auth/transport` advertises it and the app pins it.
    #[napi]
    pub fn public_key(&self) -> GatewayPublicKey {
        let p = self.server.public();
        GatewayPublicKey {
            key_id: p.key_id,
            x25519: p.x25519.to_vec().into(),
            hqc: p.hqc.as_bytes().to_vec().into(),
        }
    }
}

/// msg1's exact length for a payload of `payloadLen` bytes.
#[napi]
pub fn hqn_msg1_length(payload_len: u32) -> napi::Result<u32> {
    u32::try_from(noise::msg1_length(wire::usize_from(payload_len)))
        .map_err(|_| napi::Error::from_reason("msg1 length does not fit a u32"))
}

/// The gateway's side of one connection. msg1 is read in two steps so the
/// decapsulation can run on a worker (`hqcDecapsulate` with the HQC secret).
#[napi]
pub struct HqnGatewayHandshake {
    responder: Option<HqnResponder>,
}

#[napi]
impl HqnGatewayHandshake {
    /// A handshake as `key`.
    #[napi(constructor)]
    pub fn new(key: &GatewayKeyPair) -> Self {
        Self {
            responder: Some(HqnResponder::new(key.server.clone())),
        }
    }

    /// The client's ephemeral key, for the replay cache, before any work.
    #[napi]
    pub fn ephemeral_of(msg1: Buffer) -> napi::Result<Buffer> {
        Ok(HqnResponder::ephemeral_of(&msg1)
            .map_err(err)?
            .to_vec()
            .into())
    }

    fn responder(&mut self) -> napi::Result<&mut HqnResponder> {
        self.responder
            .as_mut()
            .ok_or_else(|| err("the handshake is finished"))
    }

    /// First half of msg1: returns the KEM ciphertext to decapsulate.
    #[napi]
    pub fn open_message1(&mut self, msg1: Buffer) -> napi::Result<Buffer> {
        Ok(self
            .responder()?
            .open_message1(&msg1)
            .map_err(err)?
            .as_bytes()
            .to_vec()
            .into())
    }

    /// Second half: the decapsulated secret in, the payload (the CONNECT) out.
    #[napi]
    pub fn finish_message1(&mut self, shared_secret: Buffer) -> napi::Result<Buffer> {
        let ss: [u8; 32] = shared_secret
            .as_ref()
            .try_into()
            .map_err(|_| err("a shared secret is 32 bytes"))?;
        Ok(self
            .responder()?
            .finish_message1(&SharedSecret::from_bytes(ss))
            .map_err(err)?
            .into())
    }

    /// msg2 (unframed) and the transport; the handshake is then finished.
    #[napi]
    pub fn write_message2(&mut self, payload: Buffer) -> napi::Result<HqnMessage2> {
        let responder = self
            .responder
            .take()
            .ok_or_else(|| err("the handshake is finished"))?;
        let (message, transport) = responder
            .write_message2(&payload, &mut OsEntropy)
            .map_err(err)?;
        Ok(HqnMessage2 {
            message: Some(message.into()),
            transport: Some(HqnTransport::from(transport)),
        })
    }
}

/// What `writeMessage2` returns.
#[napi]
pub struct HqnMessage2 {
    message: Option<Buffer>,
    transport: Option<HqnTransport>,
}

#[napi]
impl HqnMessage2 {
    /// msg2, to frame and send.
    #[napi]
    pub fn take_message(&mut self) -> napi::Result<Buffer> {
        self.message.take().ok_or_else(|| err("taken"))
    }

    /// The transport, once.
    #[napi]
    pub fn take_transport(&mut self) -> napi::Result<HqnTransport> {
        self.transport.take().ok_or_else(|| err("taken"))
    }
}

/// An established hqn/1 channel, gateway side: frames in, MQTT bytes out.
#[napi]
pub struct HqnTransport {
    transport: Transport,
    reader: FrameReader,
}

impl From<Transport> for HqnTransport {
    fn from(transport: Transport) -> Self {
        Self {
            transport,
            reader: FrameReader::default(),
        }
    }
}

#[napi]
impl HqnTransport {
    /// Seals bytes for the client as length-prefixed frames.
    #[napi]
    pub fn seal(&mut self, data: Buffer) -> napi::Result<Buffer> {
        Ok(noise::seal_frames(&mut self.transport.send, &data)
            .map_err(err)?
            .into())
    }

    /// Feeds bytes from the socket; returns the plaintext of every whole
    /// frame. Throws on a frame that does not open: close the connection.
    #[napi]
    pub fn open(&mut self, chunk: Buffer) -> napi::Result<Buffer> {
        self.reader.push(&chunk);
        let mut out = Vec::new();
        while let Some(frame) = self.reader.next_frame() {
            out.extend(self.transport.recv.decrypt(&frame).map_err(err)?);
        }
        Ok(out.into())
    }

    /// The handshake hash: a channel binding.
    #[napi(getter)]
    pub fn handshake_hash(&self) -> Buffer {
        self.transport.handshake_hash.to_vec().into()
    }
}

/// One length-prefixed hqn/1 message (`frame`).
#[napi]
pub fn hqn_frame(body: Buffer) -> napi::Result<Buffer> {
    Ok(noise::frame(&body).map_err(err)?.into())
}
