//! What a stranger can push through the broker at a client: anyone signed in
//! may publish into any inbox, up to the broker's packet limit.

mod support;

use hqchat_engine::Effect;
use support::{Client, FakeServer, NOW, settle};

fn conn_of(c: &Client) -> u64 {
    c.seen
        .iter()
        .rev()
        .find_map(|e| match e {
            Effect::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .unwrap()
}

/// A QoS 1 PUBLISH built by hand: the crate's encoder refuses one this big.
fn publish_bytes(topic: &str, pid: u16, payload: &[u8]) -> Vec<u8> {
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

fn acked(effects: &[Effect], conn: u64, pid: u16) -> bool {
    let puback = [0x40, 0x02, (pid >> 8) as u8, pid as u8];
    effects
        .iter()
        .any(|e| matches!(e, Effect::Write { conn: c, bytes } if *c == conn && bytes[..] == puback))
}

#[test]
fn an_oversized_inbox_publish_is_acknowledged_and_dropped_not_fatal() {
    let server = FakeServer::shared();
    let mut a = Client::signed_in(&server, "a");
    let mut b = Client::signed_in(&server, "b");
    Client::befriend(&mut a, &mut b);
    settle(&mut [&mut a, &mut b]);
    let inbox = format!("u/{}/inbox", b.id());

    let conn = conn_of(&b);
    let poison = publish_bytes(&inbox, 8, &vec![0x41; 300_000]);
    let mut e = Vec::new();
    // As the network delivers it: in pieces.
    for chunk in poison.chunks(16 * 1024) {
        e.extend(b.engine.on_bytes(conn, chunk.to_vec(), NOW));
    }
    assert!(acked(&e, conn, 8), "acknowledged, so never redelivered");
    assert!(
        !e.iter()
            .any(|x| matches!(x, Effect::Close { conn: c } if *c == conn)),
        "the link stays up"
    );
    b.pump(e);

    let id = {
        let e = a
            .engine
            .send_text(b.id(), "still reachable".into(), a.now)
            .unwrap();
        a.pump(e);
        settle(&mut [&mut a, &mut b]);
        b.engine.history(a.id(), None, 10).unwrap()
    };
    assert_eq!(id.len(), 1);
    assert_eq!(id[0].text, "still reachable");
}
