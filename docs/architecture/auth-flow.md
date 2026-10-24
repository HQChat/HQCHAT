# Authentication

How a client goes from holding a private key to a live MQTT session. There is
no password: an identity is an HQC-256 key pair generated on the device, and
signing in means proving it can decapsulate a ciphertext addressed to its
public key.

## Identity

- **Key pair:** HQC-256 (public key 7,237 bytes), generated on the device from a
  32-byte random seed that is never stored. The secret key, the ratchet
  sessions and the prekey secrets are sealed by the core under the profile's
  hardware key and state secret ([at rest](e2ee-protocol.md#at-rest-on-the-device)),
  so opening them needs the profile's protection tier: inbound frames wait, as
  ciphertext, for the unlock.
- **Client id:** `id = sha256(lowercase hex of the public key)`, 64 hex
  characters. Every topic, route and graph row names a client by its id. An id
  commits to its key (anyone can check a key against it) and proves nothing on
  its own (anyone holding the key can compute it).
- **Handle:** an optional username, 3–32 characters of `[A-Za-z0-9_]`, unique
  case-insensitively, with reserved names refused. Claimed after the first
  sign-in with `POST /username`.

## Sign-in

```mermaid
sequenceDiagram
    participant C as Client
    participant S as hqcat-server
    participant DB as Postgres
    C->>S: POST /auth/init { pk, origin }
    S->>S: origin allowed? rate limits (20/min per IP, 6/min per key and IP)
    S->>S: (ct, ss) = HQC.Encaps(pk); proof = signInProof(ss, origin, pk, ct)
    S->>DB: keep proof (never ss), 60 s, 4 open per key and source
    S-->>C: { ct, challenge }
    C->>C: ss = HQC.Decaps(sk, ct)  (needs the key's tier)
    C->>C: new Ed25519 key pair for MQTT
    C->>S: POST /auth/verify { pk, solution: signInProof(ss, origin, pk, ct), mqttSigningKey, challenge }
    S->>DB: match the challenge in constant time, spend only it
    S->>DB: ensure user, befriend the bot, mint bearer, register signing key
    S-->>C: { id, pk, username, sessionToken, serverTime, mqttKeyId, mqttKeyExpiresAt }
```

- The proof (v2, `core/hqchat-protocol/src/auth_proof.rs`) is
  `HKDF-SHA256(ss, salt "hqchat/v2/sign-in", info "hqchat/v2/sign-in" ‖
  len‖origin ‖ SHA-256(pk) ‖ SHA-256(ct))`. Binding the origin the client
  signed in at means a server that relays a client's sign-in to another
  cannot use the answer there; the server accepts only origins in
  `AUTH_ORIGINS` (or, unset, its own).
- The server keeps only the expected proof, never `ss` (the core drops it
  before the call returns), so `/auth/init` is not a decryption oracle.
- Challenges are kept per key and source address, and a wrong proof spends
  nothing: a stranger who knows a public key cannot keep its owner from
  signing in.
- Five failed proofs against one key within 15 minutes, or 60 inits for one
  key in a minute from all addresses together, raise an alert; there is no
  lockout, which would let anyone lock anyone out.
- A banned key is refused here (`403 BANNED`).
- Client addresses for these limits come from the header `TRUSTED_PROXY`
  names (`cf-connecting-ip` behind Cloudflare); no header is believed
  otherwise.
- The first successful sign-in creates the account and befriends it to the
  deployment's bot.

## Sessions

| Credential | Form | Lifetime | Stored server-side as |
|---|---|---|---|
| REST bearer | 32 random bytes, hex | 1 hour idle (sliding), 30 days absolute | `sha256(token)` |
| MQTT signing key | Ed25519, private half in memory only | 12 hours; the two newest per client are kept | the public key and a 16-byte key id |

`POST /auth/refresh` (bearer) registers a new signing key without a new KEM
challenge, so it costs no biometric prompt. The client refreshes when less than
two minutes remain. A 401 on the bearer means a full sign-in. `POST
/auth/logout` (bearer) ends that session, or with `everywhere: true` every
session and signing key of the account, and disconnects it. No response that
carries a token is cached (`cache-control: no-store`).

## MQTT CONNECT

The CONNECT carries `username = clientid = id` and a password that is a fresh
proof each time:

```
signed   = "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16 bytes)
password = v1.<keyId: 32 hex>.<ts: unix seconds>.<nonce: base64url>.<Ed25519 signature: base64url>
```

EMQX posts it to `/mqtt/authn`, which checks, in order: the exact shape, that
`clientid` equals the username, the timestamp within ±60 s of the server clock
(the client offsets its clock by `serverTime`), a live signing key with that
id, the signature, and finally the nonce, which is spent only once everything
else passed and is remembered for 120 s. The answer carries `expire_at`, the
signing key's expiry, after which EMQX disconnects the client.

The push bridge connects on a separate internal listener, bound to WireGuard,
as `svc-internal` with a secret generated at process start; that listener's
hook is `/mqtt/authn/internal`.

## Transport discovery

`GET /auth/transport` returns the hqn/1 gateway (host, port and its static
public keys) when the deployment runs one. The app tries hqn/1 first and falls
back to MQTT over WSS (`wss://<domain>/mqtt`). See [transport.md](transport.md).

## Signing out and deleting

Account deletion (`POST /account/delete`) removes the user, its graph rows,
prekeys, push token, sessions and signing keys, revokes the presented bearer
and disconnects the MQTT client. Reports filed against the account, blocks
other people placed on it and a ban are kept, so deleting and signing back in
with the same key walks around none of them.
On the device, deletion then removes that profile alone, with its keys and
rows; other profiles are kept. Wiping every profile is a separate, local-only
reset ([reset-local-data.md](../runbooks/reset-local-data.md)).
