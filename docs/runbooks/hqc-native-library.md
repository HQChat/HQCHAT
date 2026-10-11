# The HQC native library

HQC-256 comes from the upstream reference implementation, wrapped by
`native/hqc/src/low_wrap.c` (IND-CCA2 KEM: keypair from seed, encapsulate,
decapsulate, each returning a status and writing into caller-allocated
buffers). No binary is committed: every consumer builds it from the commit
pinned in `native/hqc/HQC_UPSTREAM.txt`.

| Consumer | Built by | Result |
|---|---|---|
| Server, gateway, bot, CI, hosts | `nix build .#hqc` (`native/hqc/package.nix`) | `lib/libhqc_wrap.so`, loaded through `HQC_LIB` |
| Local server runs | `nix build .#hqc -o native/hqc/result` | found by `src/protocol/hqc.ts` when `HQC_LIB` is unset |
| macOS app and the Swift test slices | `bash native/hqc/build-apple.sh` | `apps/apple/libhqc_wrap.dylib` (arm64) |
| iOS app | the same script | `native/hqc/dist/apple/HQC.xcframework` (device arm64, simulator arm64 and x86_64) |
| The App Store builds (Apple release workflow) | `apps/apple/release.sh ios\|macos`, which runs the same script | the xcframework or the dylib, then the signed upload |

Every build compiles the same bytes: `native/hqc/prepare-source.sh` turns the
pinned upstream tree into the compiled source (it guards the unused x86
intrinsics headers and adds the wrapper), and both `package.nix` and
`build-apple.sh` run it. Where Nix is missing (the Apple release workflow's macOS
runner), `build-apple.sh` fetches `PINNED_COMMIT` from `REPO` with git and
refuses any other commit.

The Nix package runs a self-test (deterministic keys from a seed, round trips,
implicit rejection), and the server's unit suite checks the built library
against committed known-answer digests (`test/unit/hqc.test.ts`), so a build
that computes anything different fails. Swift reaches the C functions through
`apps/apple/HQChat/Core/HQC-Bridging-Header.h` and `public_wrapper.h`; the
Xcode project already links the dylib (macOS, embedded and signed on copy) and
the xcframework (iOS).

## After a fresh clone, or a source bump

```bash
nix build .#hqc -o native/hqc/result      # server and tests
bash native/hqc/build-apple.sh            # Apple; a no-op when already built from this source
```

Both outputs are gitignored. A linker error such as `library 'hqc_wrap' not
found` means the Apple build has not run in this checkout.

## Moving to a new upstream commit

1. Update `REF`, `PINNED_COMMIT` and `HASH` in `native/hqc/HQC_UPSTREAM.txt`
   (`nix-prefetch-git` gives the hash).
2. `nix build .#hqc` must pass its self-test, and `npm run test:unit` its
   known-answer digests (a new upstream that changes outputs needs new
   digests, which means every existing identity changes too).
3. Rebuild the Apple outputs and run the cross-implementation vectors:
   `bash apps/apple/tests/run.sh` and `npm run test:unit` in `services/server`.

The weekly `hqc-upstream.yml` workflow raises a notice when upstream has moved
past the pinned commit.
