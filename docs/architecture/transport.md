# Transports and the broker

How a client's MQTT session reaches EMQX, and how the broker is set up. Two
transports carry the same MQTT 3.1.1 stream; the app tries hqn/1 first and
falls back to WebSocket.

## MQTT over WebSocket

`wss://<domain>/mqtt`: Cloudflare terminates TLS, nginx on the app host
proxies the upgrade over WireGuard to EMQX's WebSocket listener (port 8083 on
the broker's WireGuard address). nginx admits 2 new connections a second per
address (burst 20) and 50 open; EMQX caps the listener at 100,000 connections
and 500 new ones a second. The app checks the server certificate against
system trust and, when a build lists them (`Deployment.pinnedSPKIHashes`),
pinned SPKI hashes; a malformed pin list refuses every connection rather than
pinning less. Between Cloudflare and the origin, nginx speaks TLS 1.3 only,
with the hybrid X25519MLKEM768 group preferred.

## hqn/1: MQTT over a post-quantum Noise channel

A raw TCP connection to `hqnHost:443` on the broker host, terminated by
`hqcat-noise-gw`, which pipes the decrypted stream to EMQX's `gw` listener on
localhost. It saves the TLS and WebSocket round trips and makes the channel
itself post-quantum.

**Pattern:** `Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256`. The client knows the
gateway's static X25519 and HQC public keys in advance; the client stays
anonymous at this layer and proves who it is inside the stream, with the MQTT
CONNECT proof.

```
<- s, s_pq                  pre-message: both gateway statics
-> e, es, kem, [CONNECT]    msg1 (~14.7 kB, the HQC ciphertext dominates)
<- e, ee, [ ]               msg2, then CONNACK as the first transport frame
```

Every transport key depends on `es`, the HQC secret and `ee`. The client opens
with two cleartext bytes, version (1) and key id, both bound into the
prologue `hqchat-noise/1`; every later message is a `u16` big-endian length and
that many bytes, a transport frame being ChaCha20-Poly1305 ciphertext.

**Keys:** the gateway holds one or two key pairs (`noise_keys` in the broker
host's secret bundle; two during a rotation, distinguished by key id).
`GET /auth/transport` advertises the gateway host, port and public keys,
fetched from the gateway's own `/keys` over WireGuard so they always match.
A build can pin the gateway keys it trusts (`Deployment.hqnKeyPins`, passed
to the core as `Config::hqn_pins`: SHA-256 over `"hqchat/hqn-key/v1"`, the key
id and both public keys); a served key not in a non-empty list is refused and
the client keeps to WebSocket. With no pins, a key that arrives over HTTPS is
only as good as that TLS. An answer of `{"hqn": null}` switches hqn/1 off for
that server without a release.

**Choosing:** the core opens hqn/1 when the server offers it, else WebSocket.
An hqn/1 connection that closes before its CONNACK (deadline 15 s) sends that
network (Wi-Fi, cellular…) to WebSocket at once, for as long as the engine
runs.

**Admission** (everything before the first decapsulation is cheap):

| Bound | Default |
|---|---|
| New connections per source IP (nftables) | 60 per minute |
| Time to the two header bytes | 1 s |
| Handshakes in progress per IP / per IPv4 /24 or IPv6 /56 / in total | 8 / 64 / 1024 |
| Established streams per IP | 512 |
| Handshakes started per IP | 120 per minute |
| Time to a complete msg1 | 5 s |
| CONNECT size inside msg1 | 4 KiB |
| Decapsulations waiting for a worker | 64 (workers: CPUs − 1) |
| Client ephemerals remembered against replay | 2 minutes, at most 200,000 |

Only an msg1 whose HQC ciphertext opened under the X25519 key reaches a
decapsulation, so random bytes cost one X25519 operation. Every refusal is a
silent close.

## EMQX

EMQX runs in podman on the broker host from an image pinned by digest, with its
configuration rendered from `infra/emqx/emqx.conf`.

| Listener | Bound to | Used by |
|---|---|---|
| `ws` | WireGuard address, 8083 | nginx (`/mqtt`) |
| `tcp.gw` | localhost | the hqn/1 gateway |
| `tcp.internal` | WireGuard address, 1884, its own `internal` zone | the push bridge, as a superuser |
| dashboard and admin API | WireGuard address, 18083 | the server (API key `hqcat-svc`) |

The default TCP, SSL and WSS listeners are off. Client listeners allow 50
messages and 1 MB per second per connection. Nothing a client sends may grow
the broker without bound: packets are capped at 256 KB (the clients' own
limit), subscriptions at 512 per client, offline queues keep QoS 1 only,
delayed publish is off, a retained payload is at most 1 KB, and overload
protection refuses new work before memory runs out. Erlang distribution
listens on loopback only.

- **Authentication:** every client CONNECT is posted to the server's
  `/mqtt/authn` (see [auth-flow.md](auth-flow.md#mqtt-connect)); the internal
  listener uses `/mqtt/authn/internal`.
- **Authorization:** the file ACL, [emqx-acl.md](emqx-acl.md), is the whole
  policy: `no_match = deny`, `deny_action = ignore`, no caching. Wildcard
  subscriptions are off for clients and on only in the internal zone.
- **Admin API:** the server uses it to drop subscriptions when a friendship
  ends, to disconnect deleted or moderated accounts, to publish graph nudges,
  and for the broker watch's checks (nodes, authentication, the file ACL,
  `no_match`, client wildcards).

## The push bridge

`hqcat-server` connects to the internal listener with a secret generated at
start, subscribes to every presence topic and, through a shared subscription,
to every `cv/` topic and every inbox, and wakes offline members through APNs (see
[message-flow.md](message-flow.md#5-presence-and-push)).
