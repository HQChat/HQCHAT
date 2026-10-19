# The HQC native library

HQC-256 comes from the upstream reference implementation, wrapped by
`native/hqc/src/low_wrap.c` (IND-CCA2 KEM: keypair from seed, encapsulate,
decapsulate, each returning a status and writing into caller-allocated
buffers). Every consumer builds it from the commit pinned in
`native/hqc/HQC_UPSTREAM.txt`, and every client reaches it through the Rust
core (`core/hqc-sys`), which compiles it for whatever target it is built for.

| Consumer | Built by | Result |
|---|---|---|
| Server, gateway, bot, CI, hosts | `nix build .#hqchat-node` (`core/hqchat-node/package.nix`), which compiles the prepared tree (`.#hqc.source`) into the core's Node addon | `lib/hqchat_node.node`, loaded through `HQCHAT_NODE` |
| Local server runs and the core's own tests | `core/hqchat-node/build.sh`, inside `nix develop` (`HQC_SOURCE`) | `core/hqchat-node/hqchat_node.node`, found by `src/common/core.ts` when `HQCHAT_NODE` is unset |
| The standalone library and its self-test | `nix build .#hqc` (`native/hqc/package.nix`) | `lib/libhqc_wrap.so`; no server program loads it any more |
| The Apple apps and the Swift test slices | `core/hqchat-ffi/build-apple.sh`, inside `nix develop .#apple` | `core/swift/HQChatCore/HQChatCoreFFI.xcframework` (committed; `release.sh` refuses a stale one) |

Every build compiles the same bytes: `native/hqc/prepare-source.sh` turns the
pinned upstream tree into the compiled source (it guards the unused x86
intrinsics headers and adds the wrapper); `package.nix` runs it, and the core
builds from its output (`HQC_SOURCE`).

The Nix package runs a self-test (deterministic keys from a seed, round trips,
implicit rejection); the addon's build runs the core's known-answer tests, and
the server's unit suite checks them again through the addon
(`test/unit/hqc.test.ts`, `test/unit/core-addon.test.ts`), so a build that
computes anything different fails. The apps never call the C functions
themselves: Swift talks to the core.

## After a fresh clone, or a source bump

```bash
core/hqchat-node/build.sh                 # server and tests, inside nix develop
```

The Apple core package is committed, so the Xcode project builds straight from
a clone.

## Moving to a new upstream commit

1. Update `REF`, `PINNED_COMMIT` and `HASH` in `native/hqc/HQC_UPSTREAM.txt`
   (`nix-prefetch-git` gives the hash).
2. `nix build .#hqc` must pass its self-test, and `npm run test:unit` its
   known-answer digests (a new upstream that changes outputs needs new
   digests, which means every existing identity changes too).
3. Rebuild the core everywhere (`scripts/check.sh core`, and
   `core/hqchat-ffi/build-apple.sh` for the Apple package) and run the
   vectors: `cargo test` in `core/` and `npm run test:unit` in
   `services/server`.

The weekly `hqc-upstream.yml` workflow raises a notice when upstream has moved
past the pinned commit.
