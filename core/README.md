# core

The HQChat core in Rust: one implementation of the protocol and the client,
linked by the iOS, macOS, Android, Linux and Windows apps (uniffi) and by the
server (napi). The design is in
[docs/architecture/multiplatform.md](../docs/architecture/multiplatform.md);
the flow of one message through it in
[docs/architecture/core-wiring.md](../docs/architecture/core-wiring.md).

| Crate | Holds |
|---|---|
| `hqc-sys` | the HQC-256 C build and its raw FFI; the only crate allowed `unsafe` |
| `hqc` | the safe HQC-256 KEM |
| `hqchat-protocol` | the wire protocol: ids, topics, payload encryption, frames, ratchet, handshake, proofs, hqn/1, MQTT |
| `hqchat-engine` | the client as a sans-IO `Engine`: commands in, `Effect`s out, `KeyVault` and `Store` callbacks; sign-in, friends, prekeys, the broker session over hqn/1 or WSS, conversations, state sealed at rest |
| `hqchat-node` | the server's binding (napi): the protocol functions, the hqn/1 gateway, the `Engine` for the bot |
| `hqchat-ffi` | the apps' binding (uniffi, Swift and Kotlin) |

## Safety rules

Speed never buys a weaker guarantee. The lints in `Cargo.toml` enforce these
rules, and CI fails on any warning:

- **`unsafe` lives in `hqc-sys` only.** It has four calls into C, each over
  fixed-size arrays and each with a `SAFETY` comment. Every other crate
  forbids `unsafe`, except the two bindings, which deny it: napi's and
  uniffi's macros generate `unsafe` under their own `allow`.
- **Library code never panics on input.** No `unwrap`, `expect`, `panic!`,
  indexing or slicing. Bytes from the network or the disk go through
  `hqchat_protocol::wire::Reader`, whose every read returns an error instead
  of running past the end.
- **No silent truncation or wrapping.** Lengths go on the wire through
  `try_from`, never `as`. Arithmetic on counters and clocks is checked or
  explicitly saturating/wrapping, and release builds keep overflow checks.
- **Secrets are wiped.** Key types implement `ZeroizeOnDrop` and print as
  `…`. HKDF output is `Zeroizing`. After every HQC call, the C side zeroes
  the stack it used (about 210 KiB at peak) and the global PRNG.
- **Errors are not dropped.** A store write that fails reaches the app as
  `Effect::StorageFailed`, and a failed OS random generator fails the
  operation.
- **The C is hardened.** HQC compiles with stack protector, fortified libc,
  stack-clash probes (Linux), zero-initialized locals, zeroed call-used
  registers, and CET or BTI/PAC landing pads (`/GS` and `/guard:cf` on
  MSVC). None of these change what the code computes.
- **Dependencies are audited.** `cargo deny check` refuses RustSec
  advisories, yanked crates, licences AGPL cannot carry, and sources other
  than crates.io.

Tests may unwrap, index and use plain arithmetic: `clippy.toml` exempts
`#[test]` functions, and `scripts/check.sh core` relaxes those lints in a
second pass that covers test helpers.

Everything runs inside `nix develop`, which provides the toolchain and
`HQC_SOURCE`, the prepared HQC tree the build compiles:

```bash
cd core && cargo test
```

The full gate (format, both lint passes, `cargo deny`, every test, the Node
addon) is:

```bash
scripts/check.sh core
```

AGPL-3.0, like the server ([LICENSING.md](../LICENSING.md)).
