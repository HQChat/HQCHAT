# Core wiring: one message through the core

**Status: proposal, not built.** Companion to [multiplatform.md](multiplatform.md).
It walks one real flow (sign in, the user taps Send, the peer receives)
through the target design, step by step, naming today's function for each
step, to fix exactly what the core exposes and how it meets the network, the
vault and the UI. The scenarios in `services/server/test/scenarios/` are the
acceptance test for every step.

Today's code read for it: `services/server/src/client/{client,conversation}.ts`
(already close to sans-IO: `receive` is synchronous and returns frames to
publish); on Apple, `ChatView.sendMessage` → `ChatSession.sealMessage` →
`RatchetSession.seal` → `ChatSession.publish` → `MQTTService` →
`MQTTWireClient`, and `ConversationRouter` / `InboundQueue` for receiving;
on the server, `auth.ts`, `emqx.ts`, `push.ts` and `src/gateway/`.

## 1. One message, end to end, in the target design

Legend: **[S]** shell, **[E]** Engine (Rust), **[V]** vault callback,
**[St]** store callback, **[N]** network done by the shell, **[Srv]** server.

### 1.1 Sign-in and connect (prerequisite)

| # | Who | Call | Today |
|---|---|---|---|
| 1 | S | user unlocks (Face ID / BiometricPrompt / Hello) then `engine.unlock()` | `MessageKeyGate.unlock` |
| 2 | E→V | `vault.agree(ephemeral_pub)` to open the sealed identity key | `AESKeyStore.read` |
| 3 | E | `Effect::Http POST /auth/init {pk}` | `AuthService.login` |
| 4 | Srv | `hqcEncaps(pk)`, `authProof(ss)` stored | `auth.ts handleInit` |
| 5 | S→E | `engine.on_http(req, 200, {ct})`; E decaps, new Ed25519 key, `Effect::Http POST /auth/verify` | `AuthService.login` |
| 6 | S→E | `on_http(...)` → session, `serverTime` offset; `Effect::Http GET /friends`, `GET /auth/transport` | `DirectorySync`, `refreshTransportDiscovery` |
| 7 | E | picks transport (policy in core, network key from shell) → `Effect::Open {conn, Tcp(hqnHost:443)}` | `TransportSelector`, `MQTTService.connect` |
| 8 | S→E | `on_opened(conn)` → E builds Noise msg1 + MQTT CONNECT (signed proof) → `Effect::Write` | `NoiseHQN`, `MQTTConnectProof`, `MQTTWireClient` |
| 9 | Srv | gateway: Noise responder (decap worker) → EMQX → `/mqtt/authn` → `verifyConnectProof` | `gateway.ts`, `auth.ts verifyConnect` |
| 10 | S→E | `on_bytes(conn, …)` → CONNACK → E emits SUBSCRIBE inbox/graph/cv/hs, PUBLISH presence (retained), prekey upkeep (`Effect::Http POST /prekeys`) | `MQTTService.didConnect`, `PrekeyService.ensurePublished` |

### 1.2 Send (the user taps Send)

| # | Who | Call | Today |
|---|---|---|---|
| 1 | S | UI inserts nothing itself; calls `engine.send_text(peer, text)` | `ChatView.sendMessage` inserts a row first |
| 2 | E | creates `msg_id`, stores the outgoing row **sealed** (`[St] put`, sealed by core with the vault's public key, no user needed), returns `Effect::MessageAdded{status: Sending}` | `Message(... .sending)` + `MessageKeyStore.wrap` |
| 3 | E | locked? → `Effect::NeedUnlock{reason}` and the send waits in the outbox | `seal()` unlock gate |
| 4 | E | no session → `Effect::Http GET /peers/{id}/key` (if not pinned), `POST /prekeys/claim` | `ChatSession.startSession`, `Conversations.openSession` |
| 5 | S→E | `on_http(...)` → `startAsInitiator` (3 Encaps), state saved via `[V]`+`[St]` **before** anything leaves | `startAsInitiator`, `this.save()` |
| 6 | E | ratchet `seal` → frame header (AAD) → AES-GCM → `encodeFrame` → topic (`init` → `u/{peer}/inbox`, else `cv/{convoId}`) | `RatchetSession.seal`, `ConversationFrame`, `AESService.encryptRaw`, `topicFor` |
| 7 | E | MQTT PUBLISH QoS1 → Noise frame → `Effect::Write{conn, bytes}` | `MQTTService.send*`, `MQTTWireClient.publish` |
| 8 | Srv | gateway decrypts → EMQX ACL (`infra/emqx`) → fan-out / queue for offline; push bridge sees `cv/+`, wakes offline members | `push.ts` |
| 9 | S→E | `on_bytes` → PUBACK → `Effect::MessageStatus{msg_id, Sent \| Queued}` | `advanceDelivery(.sent/.queued)` |
| 10 | S→E | later: receipt frame on `cv/` → opened → `Effect::MessageStatus{Delivered}` | `handleReceipt` |

### 1.3 Receive on the peer

| # | Who | Call | Today |
|---|---|---|---|
| 1 | S | push wake (APNs/FCM/UnifiedPush) → shell opens connection → `on_bytes` | `PushManager`, `NotificationService` |
| 2 | E | MQTT PUBLISH → route by topic (`hs/` handshake, `u/…/inbox` init, `cv/` msg/receipt), checks sender is a friend, addressed to me, right topic for kind | `Conversations.receive`, `ConversationRouter.handle` |
| 3 | E | **locked** → raw frame stored as pending (`[St]`, no secret needed), `Effect::Notify{peer}` (no content) | `InboundQueue.admit`, `PendingFrame` |
| 4 | E | unproven `init` → hold, Encaps to `senderPk`, publish `chal` on `hs/` | `challenge`, `challengeInitiator` |
| 5 | E (sender) | `chal` → decaps with identity key → `proof` on `hs/` | `onHandshake` / `applyHandshake` |
| 6 | E | proof matches → `startAsResponder` → open held frames → store sealed → `Effect::Deliver(Message)` + receipt PUBLISH | `openInit`, `openMessage`, `store`, `receiptFor` |
| 7 | S | `engine.unlock()` later → E drains pending in order | `drainPending` |

### 1.4 What this tells us the lib needs

- From the **network**: only "open TCP / open WSS, write bytes, deliver
  bytes, closed" plus "one HTTP request". Everything else (Noise, MQTT,
  retries policy, transport choice, clock offset) is core.
- From the **vault**, four calls only:
  `device_public_key()`, `agree(ephemeral_pub) -> shared` (user-gated),
  `tier()`, `create()`. The core does ECIES itself: sealing needs only the
  public key (works locked, like `MessageKeyStore.wrap`), opening needs one
  hardware ECDH (`SecKeyCopyKeyExchangeResult` / Keystore `KeyAgreement` /
  `TPM2_ECDH_ZGen` / `NCryptSecretAgreement`).
- From the **store**: get/put/delete/list-by-prefix of opaque blobs.
- To the **UI**: messages, statuses, friends, presence, connection state,
  unlock requests, notifications. Never keys.

## 2. The exposed surface

### 2.1 Client (uniffi, `hqchat-ffi`)

```rust
#[uniffi::export] fn core_api_version() -> u32;

#[derive(uniffi::Object)] pub struct Engine;            // Send + Sync, internal Mutex
#[uniffi::export] impl Engine {
  #[uniffi::constructor] fn new(cfg: Config, vault: Arc<dyn KeyVault>, store: Arc<dyn Store>) -> Result<Arc<Self>, CoreError>;
  // lifecycle
  fn create_identity(&self, now: i64) -> Result<Vec<Effect>, CoreError>;
  fn start(&self, now: i64, network: NetworkInfo) -> Vec<Effect>;
  fn unlock(&self, now: i64) -> Result<Vec<Effect>, CoreError>;
  fn lock(&self) -> Vec<Effect>;
  fn tick(&self, now: i64) -> Vec<Effect>;
  // user actions
  fn send_text(&self, peer: String, text: String, now: i64) -> Result<Vec<Effect>, CoreError>;
  fn retry(&self, msg_id: String, now: i64) -> Vec<Effect>;
  fn invite(&self, handle: String) -> Vec<Effect>;   fn accept(&self, peer: String) -> Vec<Effect>;
  fn remove(&self, peer: String) -> Vec<Effect>;     fn block(&self, peer: String) -> Vec<Effect>;
  fn report(&self, r: ReportInput) -> Vec<Effect>;   fn set_username(&self, h: String) -> Vec<Effect>;
  fn delete_account(&self) -> Vec<Effect>;           fn register_push(&self, p: PushToken) -> Vec<Effect>;
  // reads for the UI (sync, from the store, opened under the unlock)
  fn history(&self, peer: String, before: Option<i64>, limit: u32) -> Result<Vec<Message>, CoreError>;
  fn friends(&self) -> Vec<FriendView>;  fn fingerprint(&self, peer: String) -> Option<String>;
  // I/O results
  fn on_http(&self, req: u64, status: u16, body: Vec<u8>, now: i64) -> Vec<Effect>;
  fn on_opened(&self, conn: u64, now: i64) -> Vec<Effect>;
  fn on_bytes(&self, conn: u64, bytes: Vec<u8>, now: i64) -> Vec<Effect>;
  fn on_closed(&self, conn: u64, reason: CloseReason, now: i64) -> Vec<Effect>;
  fn on_network_changed(&self, n: NetworkInfo, now: i64) -> Vec<Effect>;
}

#[derive(uniffi::Enum)] pub enum Effect {
  Http { req: u64, method: Method, path: String, bearer: bool, body: Vec<u8> },
  Open { conn: u64, endpoint: Endpoint },          // Tcp{host,port} | Wss{url}
  Write { conn: u64, bytes: Vec<u8> },  Close { conn: u64 },
  Timer { at: i64 },
  NeedUnlock { reason: UnlockReason },
  MessageAdded(Message), MessageStatus { msg_id: String, status: Delivery },
  FriendsChanged, PresenceChanged { peer: String, online: bool },
  Connection(ConnState), TierChanged(Tier),
  Notify { peer: String },                         // never content
  Dropped { reason: String },                      // protocol log
}

#[uniffi::export(with_foreign)] pub trait KeyVault: Send + Sync {
  fn create(&self) -> Result<Tier, VaultError>;
  fn device_public_key(&self) -> Result<Vec<u8>, VaultError>;     // 65-byte P-256
  fn agree(&self, ephemeral_pub: Vec<u8>) -> Result<Vec<u8>, VaultError>; // under the shell's authenticated context
  fn tier(&self) -> Tier;
}
#[uniffi::export(with_foreign)] pub trait Store: Send + Sync {
  fn get(&self, key: String) -> Option<Vec<u8>>;
  fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError>;
  fn delete(&self, key: String);
  fn list(&self, prefix: String) -> Vec<String>;
}
```

### 2.2 Server (napi, `hqchat-node`)

| Export | Replaces in |
|---|---|
| `hqcKeypairFromSeed`, `hqcEncaps`, `hqcDecaps` | `protocol/hqc.ts` (koffi) in `auth.ts`, `gateway/keys.ts`, `gateway/decap-worker.ts` |
| `authProof`, `safeEqual` | `protocol/auth-proof.ts` in `auth.ts` |
| `parseConnectProof`, `verifyConnectProof`, `isFreshTimestamp` | `protocol/mqtt-proof.ts` in `auth.ts verifyConnect` |
| `peerId`, `isPeerId`, `conversationTopic`, `handshakeTopic`, … | `protocol/identity.ts`, `topics.ts` in `api.ts`, `emqx.ts` |
| class `HqnResponder` | `protocol/noise.ts` in `gateway/gateway.ts` |
| class `Engine` (same API as B1, JS `KeyVault`/`Store`) | `src/client/*` for the bot, `provision-client.ts`, scenarios |

## 3. Building and testing the lib

Order, each step its own `lib/<feature>` branch (see the branch table in multiplatform.md):

1. **Workspace + `hqc-sys`/`hqc`.** `build.rs` compiles `native/hqc/src` +
   the prepared upstream tree (`native/hqc/prepare-source.sh`) with `cc`,
   same flags as `native/hqc/package.nix`, never `-march=native`. Test: HQC
   known-answer digests (from `native/hqc/test`).
2. **`hqchat-protocol`.** Port module by module, each gated by its vector
   file moved to `core/vectors/`: identity → topics → aead → envelope →
   handshake → double-ratchet/ratchet → mqtt-proof → noise (+ cacophony) →
   MQTT 3.1.1 codec (new vectors captured from `MQTTWireClient` tests).
   RustCrypto crates (`aes-gcm`, `hkdf`, `sha2`, `ed25519-dalek`,
   `x25519-dalek`, `chacha20poly1305`, `p256`), `zeroize` everywhere.
3. **Differential fuzz.** cargo-fuzz targets mirroring
   `services/server/test/fuzz/*-differential.ts` and `apps/apple/fuzz/*`;
   Rust vs TS run through a tiny napi shim.
4. **`hqchat-engine`.** Port `conversation.ts` first (it is already the
   right shape: `receive` sync returning outbound), then sign-in
   (`auth.ts`), prekey upkeep, friend sync, MQTT session, transport policy,
   locked queue, sealed history, ECIES-with-vault. Unit tests run against an
   in-memory `Store`, a software `KeyVault` and a **fake broker** in Rust
   (two Engines wired together: no network).
5. **`hqchat-node` and the walking skeleton.** The scenario suite
   (`messaging.test.ts`, `accounts.test.ts`, `hqn.test.ts`) runs with the
   napi `Engine` in place of `src/client` against `run-local.sh`. **This is
   the milestone that proves section 1**: send, burst, offline delivery,
   ratchet turns, out-of-order, tamper, impostor init, unfriend, reconnect,
   graph nudge, all through the real lib.
6. **`hqchat-ffi` + conformance.** Generate Swift/Kotlin; a conformance
   suite replays the vectors and a two-Engine conversation through Swift
   (`apps/apple/tests/run.sh`), Kotlin (JVM unit test) and Node.

## 4. Wiring into the server and the apps

### 4.1 Server
- Swap imports listed in B2; delete `src/protocol/*` and koffi; `src/client`
  becomes a thin TS wrapper doing the effect loop (HTTP via `fetch`, sockets
  via `net`/`ws`) around the napi `Engine`; the bot keeps its code on top.
- Nix: `native/hqc/package.nix` → a `core-node` derivation; `HQC_LIB` env
  goes away.
- Gate: `scripts/check.sh unit|integration|scenarios`, staging deploy, prod.

### 4.2 Apple (Swift shell)
- **New**: `CoreShell` actor running the effect loop: `Http` → URLSession
  with `TLSPinningDelegate`; `Open Tcp` → `NWConnection`; `Open Wss` →
  `URLSessionWebSocketTask` (pinned); `Timer` → Task sleep; `NeedUnlock` →
  `MessageKeyGate`; `Notify` → `NotificationService`.
- **Adapters**: `SecureEnclaveVault: KeyVault` (from `MessageKeyStore`:
  SE key creation, `SecKeyCopyKeyExchangeResult` with the shared
  `LAContext`); `FileStore`/SwiftData-backed `Store`.
- **Views** read `engine.history`/`friends` and react to effects instead of
  SwiftData `Message`/`Friend` rows.
- **Deleted after the flag flips**: `ChatSession` internals,
  `ConversationRouter`, `RatchetSession`, `DoubleRatchet`, `Handshake`,
  `ConversationEnvelopeV3`, `ConversationFrame`, `NoiseHQN`,
  `MQTTWireClient`, `MQTTService`, `MQTTConnectProof`, `MQTTTopics`,
  `PrekeyService`, `InboundQueue`, `AESService`, `HQCKem`, `HQCService`.
- **Importer** (in core, run once): reads Keychain identity/ratchet items and
  SwiftData rows via a one-off Swift reader, writes core format, keeps old
  items until the new ones open. Check first whether core ECIES can open
  existing `eciesEncryptionCofactorX963SHA256AESGCM` rows as is (then message
  rows need no rewrite).
- Gate: `apps/apple/verify.sh` with the flag off and on.

### 4.3 Kotlin shell (Android + desktop, later phases)
Same effect loop in `apps/kotlin/shared` (coroutines, single-thread
dispatcher), OkHttp for Http/Wss, sockets for Tcp; `AndroidKeystoreVault`
(KeyAgreement ECDH, StrongBox→TEE→software tier) and the Rust
`hqchat-vault-desktop` for Linux/Windows.
