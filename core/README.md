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
| `hqchat-protocol` | the wire protocol: ids, topics, frames, ratchet, handshake, proofs, hqn/1, MQTT (API surface; HQC implemented, the rest `todo!()` per feature branch) |
| `hqchat-engine` | the client as a sans-IO `Engine`: commands in, `Effect`s out, `KeyVault` and `Store` callbacks (API surface) |

Everything runs inside `nix develop`, which provides the toolchain and
`HQC_SOURCE`, the prepared HQC tree the build compiles:

```bash
cd core && cargo test
```

AGPL-3.0, like the server ([LICENSING.md](../LICENSING.md)).
