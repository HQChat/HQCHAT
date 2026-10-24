# BIS — commodity classification request (CCATS), copy to NSA

> **DRAFT — UNSENT.** Not legal advice.
>
> **Confirm the path before sending this one.** `docs/product/export-compliance.md`
> concludes that HQC being non-standard puts the app under ECCN 5A002/5D002 and
> requires a CCATS. That conclusion turns on a single question — whether HQC
> counts as a *published standard* today — and if the answer has changed, the
> correct filing is a one-page self-classification report instead of this.
> Have an export-control professional settle it first.
>
> **Two other things to settle with them, because they may reduce this to
> nothing:**
> - The **server is published open source** (AGPL-3.0, public repository). The
>   EAR treats publicly available encryption *source code* differently from
>   binaries, generally via an emailed notification of the URL rather than a
>   classification request. That likely covers the server outright and would
>   leave only the closed-source iOS/macOS apps here.
> - Classification requests are normally submitted through BIS's electronic
>   system, not as a letter. Treat this as the **substance** to paste into that
>   submission, and as the cover note for the copy sent to NSA.
>
> Placeholders in `[…]` are identity, dates and contact details. Do not guess them.

---

**Subject: Commodity classification request — post-quantum end-to-end encrypted
messaging application "hqchat" (HQChat)**

To: U.S. Department of Commerce, Bureau of Industry and Security,
Office of National Security and Technology Transfer Controls
Copy: National Security Agency, Attn: Encryption Request Coordinator

[Date]

Dear Sir or Madam,

I request a commodity classification for an end-to-end encrypted messaging
application that implements a post-quantum key-encapsulation mechanism. I am an
individual developer established in [country], distributing at no charge.

## 1. Submitter

- Name: [full legal name]
- Address: [postal address]
- Email / telephone: [contact]
- Company: none — the item is developed and distributed by an individual.

## 2. Item

| | |
|---|---|
| Name | **hqchat** (listed on the Apple App Store as **HQChat**) |
| Type | Software — messaging application for iOS and macOS, plus a server component |
| Function of the encryption | Confidentiality of user-to-user messages. Encryption is a **primary function**, not ancillary. |
| Price | **$0.00.** Nothing is sold. The project is funded by voluntary donations that grant no feature. |
| Source availability | The **server, infrastructure and iOS/macOS client source are published**: <https://github.com/HQChat/HQCHAT>. The server and infrastructure are under AGPL-3.0. |
| Proposed classification | **ECCN 5D002** (or 5A002 as applicable), pending your determination |

## 3. Cryptographic functionality

Messages are encrypted on the sending device and decrypted only on the receiving
device. Private keys are generated on-device and never transmitted. The server
routes ciphertext it cannot read.

| Purpose | Algorithm | Key lengths / parameters |
|---|---|---|
| End-to-end key encapsulation | **HQC-256** KEM | public key 7,237 B; secret key 7,333 B; ciphertext 14,421 B; shared secret 32 B |
| Message encryption | **AES-256-GCM** | 256-bit key, 96-bit nonce, 128-bit tag |
| Key derivation | **HKDF-SHA-256** | 32-byte outputs, domain-separated |
| Optional transport channel to the server | **Noise** handshake: **X25519** + HQC-256, **ChaCha20-Poly1305**, SHA-256 | 256-bit keys |
| Authentication of each messaging connection | **Ed25519** signatures | per-session key, public half registered with the server |
| Messages stored on the device | **ECIES over P-256** (Apple Secure Enclave) wrapping AES-256-GCM keys | P-256 |
| Hashing / identifiers | **SHA-256** | — |
| Transport | **TLS** | OS-provided (client) and nginx / Cloudflare (server) |

**Authentication.** Sign-in is a KEM challenge–response: the server
encapsulates to the claimed public key and the client proves possession of the
private key by returning `HKDF(shared_secret, "auth")`. No plaintext is ever
returned, so there is no decryption oracle. The client then authenticates each
messaging connection with an Ed25519 signature by a short-lived key. Signatures
authenticate; they never protect content.

**Key management.** A PQXDH-style initial exchange mixes three encapsulations
(long-term identity key, a medium-term prekey rotated every 7 days, and a
single-use one-time prekey) into a root secret. A KEM-based double ratchet then
re-encapsulates the root chain on a direction change once the current chain
has carried 32 messages or lived 15 minutes, while a symmetric chain derives
one key per message. A responder confirms the initiator's identity with a
separate HQC challenge before accepting a session.

**Implementation provenance.** HQC is the **official reference implementation**
from <https://gitlab.com/pqc-hqc/hqc>, compiled without algorithmic
modification; the exact upstream commit is pinned in the repository
(`native/hqc/HQC_UPSTREAM.txt`, currently `3a0f86f`). AES-GCM, ChaCha20-Poly1305,
X25519, Ed25519, P-256, HKDF, HMAC and SHA-256 come from published Rust
libraries (RustCrypto and dalek), linked into the one Rust core the apps and
the server share; the hardware key's P-256 ECDH is done by the Secure Enclave
(Apple Security framework), and TLS is the platform's. **No cryptographic algorithm was designed by the submitter** —
only the protocol composition is original.

## 4. Why a classification is being requested rather than self-classification

HQC was selected by NIST as its fifth post-quantum algorithm, but the
corresponding FIPS had not been published at the time of writing. On the
conservative reading that HQC is therefore not yet a *published standard*, the
application does not qualify for mass-market self-classification under 5D992.c,
and I am seeking your determination rather than assuming the more favourable
answer.

Two features may bear on your assessment, and I state them plainly rather than
leaving them to be discovered:

1. **End-to-end key agreement is not hybrid.** It is HQC-256 alone, with no
   X25519 or ML-KEM alongside it, so a break in HQC leaves no classical
   fallback for message confidentiality; that limitation is published to users.
   Only the optional transport channel to the server is hybrid (X25519 +
   HQC-256).
2. **The medium is a general-purpose messenger** for personal communication. It
   has no networking, key-escrow, interception or law-enforcement-access
   functionality, no ability to encrypt third-party data at rest, and no
   customisable cryptography — users cannot supply their own algorithms.

## 5. Supporting documentation

Available on request, and in the public repository:

- End-to-end protocol specification, including the wire format and the canonical
  authenticated-additional-data encoding
- Threat model, with the system's documented limitations
- Full cryptographic inventory
- Source code: <https://github.com/HQChat/HQCHAT>

I am glad to supply build instructions, or any further
technical detail your review requires.

Thank you for your consideration.

Respectfully,

[Name]
[Contact]
