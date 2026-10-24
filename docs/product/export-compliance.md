# Export compliance — encryption declaration

_Product: HQChat, iOS and macOS, version 3.0.0. Last updated 2026-10-03._

The source of truth for the App Store Connect export-compliance questionnaire
and for any filing with the U.S. Bureau of Industry and Security (BIS) or the
French authority (ANSSI). Draft filings written from it are in
[`filings/`](filings/README.md), unsent. **This is not legal advice**: have it
reviewed by an export-control professional before filing.

## Info.plist declaration

`INFOPLIST_KEY_ITSAppUsesNonExemptEncryption` in
`apps/apple/HQChat.xcodeproj/project.pbxproj`:

| Target | Bundle id | Debug | Release |
|---|---|---|---|
| macOS | `martin.rougeron.DissQus` | `YES` | `YES` |
| **iOS** | `martin.rougeron.DissQus-iOS` | **`NO`** | **`NO`** |

**The iOS answer is wrong, and iOS is the shipping target.** Both apps contain
the same cryptography, which goes well beyond the OS-provided exemptions. Set
iOS to `YES` (or remove the key on both and answer per version in App Store
Connect); the two targets must not disagree.

## Apple's two documentation triggers

1. **Non-standard algorithms: yes.** The apps implement **HQC-256**, a
   post-quantum KEM, from the reference implementation compiled into the app.
   HQC was selected by NIST, but its FIPS standard is not published, so it is
   treated here as non-standard.
2. **Standard algorithms beyond the OS's own encryption: yes.** The apps run
   their own end-to-end message encryption and their own transport handshake on
   top of TLS.

## Cryptography inventory

| Purpose | Algorithm | Parameters | Implementation |
|---|---|---|---|
| End-to-end key agreement (session start, every ratchet step, sign-in challenge, sender proof) | **HQC-256** KEM | pk 7,237 B, sk 7,333 B, ct 14,421 B, ss 32 B; upstream commit pinned in `native/hqc/HQC_UPSTREAM.txt` | compiled C inside the Rust core, in the apps (`HQChatCoreFFI.xcframework`) and on the server (the Node addon) |
| End-to-end message encryption | **AES-256-GCM** | 256-bit key, 12-byte IV, 16-byte tag, header as AAD | the Rust core (RustCrypto `aes-gcm`), in the apps and the server-side bot |
| Key derivation | **HKDF-SHA-256** | 32-byte outputs, one label per use | the Rust core (RustCrypto `hkdf`) |
| Message-key schedule | KEM double ratchet over HQC-256 | a step after 32 messages or 15 minutes of a used chain; one key per message | `docs/architecture/e2ee-protocol.md` |
| Transport channel, optional (hqn/1) | **Noise** `pqNK`: **X25519** + HQC-256, **ChaCha20-Poly1305**, SHA-256 | a hybrid handshake to the server's gateway | the Rust core (`x25519-dalek`, `chacha20poly1305`), on both ends |
| Sign-in to the messaging broker | **Ed25519** signatures | a per-session key signs each connection proof | the Rust core (`ed25519-dalek`) |
| Stored data on the device | **P-256 ECDH** (Secure Enclave key) joined with a 256-bit state secret, HKDF-SHA-256, **AES-256-GCM**; HMAC-SHA-256 slot names | the core seals; the Secure Enclave performs the ECDH | the Rust core (`p256`, `aes-gcm`, `hmac`); Apple Security framework for the Enclave |
| Transport security | **TLS** (HTTPS, WSS) | OS and nginx / Cloudflare | platform |
| Fingerprints and ids | **SHA-256** | | the Rust core (`sha2`) |

**Purpose:** confidentiality of person-to-person messages (end-to-end encrypted
instant messaging) and authentication of the user to the server. Encryption is
a core function of the app.

**Digital signatures are used for authentication only** (Ed25519, connection
proofs), never to protect content.

**Hybrid only in transport.** End-to-end key agreement is HQC-256 alone; the
optional transport channel combines X25519 and HQC-256.

**No cryptographic library is home-made** apart from the HQC binding, which
wraps the reference implementation. Everything else comes from Apple's
frameworks or Node.js.

**Two facts that may change the U.S. analysis:**

- **The source is published** (<https://github.com/HQChat/HQCHAT>): the server and infrastructure under
  AGPL-3.0, and the iOS/macOS client alongside them. The EAR treats publicly
  available encryption source code differently from binaries, which may resolve
  the source side without a classification request.
- **Nothing is sold.** The app is free with no in-app purchase; donations on
  the website grant nothing.

## U.S. classification (proposed)

Because the app performs its own end-to-end encryption with a non-standard
algorithm (HQC), it likely does not qualify for mass-market self-classification
under ECCN 5D992, falls under **5D002 / 5A002**, and needs a **CCATS**
classification request to BIS before relying on License Exception ENC.

If HQC's FIPS standard is published and counts as a published standard, the app
may become self-classifiable under **5D992.c** (annual self-classification report
to BIS and NSA, no CCATS). Confirm HQC's status and the path with a professional
before submitting.

## France and the EU

As a France-based developer, supplying a means of cryptology is subject to the
French regime (declaration to ANSSI) independently of the U.S. EAR. See the
draft in [`filings/anssi-declaration.md`](filings/anssi-declaration.md).

## In App Store Connect

Attach, once available, the CCATS (or the self-classification confirmation)
and any French or EU authorisation. Keep this document and the filings with
each release.
