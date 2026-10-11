# Third-party licences

`LICENSE.md` beside this file covers the app code this project wrote (see
`LICENSING.md` at the root for the rest of the repository). It does not cover
the components below, which were written by other people and carry their own
terms. Each entry names the exact upstream revision so the claim can be checked
rather than taken.

---

## HQC reference implementation

| | |
|---|---|
| **Where it lives** | Source not vendored: `native/hqc/package.nix` fetches it at build time; `native/hqc/HQC_UPSTREAM.txt` pins it. The Apple builds compiled from it are committed (`native/hqc/dist/apple/HQC.xcframework`, `apps/apple/libhqc_wrap.dylib`) so the app builds from a clone. |
| **Upstream** | https://gitlab.com/pqc-hqc/hqc |
| **Revision** | `3a0f86f84f6cb9c90729f038828a6e5f7df8634f` (Nix hash `sha256-uBlMOtCz7c8ZA+ldPXuaHendLR3/wCVWgiND2ssEcVE=`) |
| **Licence** | Public domain (SPDX: `LicenseRef-PublicDomain`), per the upstream `LICENSE` at that revision |
| **Modified by this project?** | Yes, at build time only; see below |

The upstream `LICENSE` reads, in full:

> This software is released into the public domain.
>
> You are free to use, modify, and distribute this software for any purpose,
> with or without fee, and without any warranty.
>
> This project incorporates third-party code from the FIPS202 implementation
> used in the PQClean project, which is itself based on public domain code:
>
> - crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html by Ronny Van Keer
> - TweetFips202 by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe (https://twitter.com/tweetfips202)
>
> All of the included code is believed to be in the public domain.

The algorithm is the work of the HQC submission team: Carlos Aguilar Melchor,
Nicolas Aragon, Slim Bettaieb, Loïc Bidoux, Olivier Blazy, Jurjen Bos,
Jean-Christophe Deneuville, Arnaud Dion, Philippe Gaborit, Jérôme Lacan,
Edoardo Persichetti, Jean-Marc Robert, Pascal Véron and Gilles Zémor. Public
domain removes the legal obligation to credit them; it does not remove the
reason to.

**Local modifications.** No algorithm code is changed. `native/hqc/package.nix`
does two things to the fetched tree, both visible in that file:

1. It wraps each `#include <…intrin.h>` (x86 intrinsics headers that the
   reference C includes but does not use) in `#if defined(__i386__) ||
   defined(__x86_64__)`, so the tree compiles for ARM.
2. It adds this project's wrapper (`native/hqc/src/`: `low_wrap.c`,
   `wrapper.h`, `hqc_portability.h`), which exports
   `hqc_kem_{keypair,enc,dec}_wrap`. The wrapper is this project's code, under
   AGPL-3.0 with the rest of `native/`.

`native/hqc/build-apple.sh` compiles the Apple targets from that same patched
tree (`nix build .#hqc.source`).

---

## Swift packages

One row per package linked into a shipped build, as pinned in
`HQChat.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`.

| Component | Upstream | Version | Licence |
|---|---|---|---|
| sentry-cocoa | https://github.com/getsentry/sentry-cocoa | 9.25.0 (`d27a0ddf0cd1bc90ab038f5781fddc39b894430e`) | MIT |

No other package is linked. The tests, the e2e harness and the fuzzers use only
Apple frameworks and the sources above.

---

## Compiled artefacts in this repository

None. `libhqc_wrap.dylib` and the xcframework are built locally by
`native/hqc/build-apple.sh` (or `nix build .#hqc`) and are `.gitignore`d.

---

## Full licence texts

### sentry-cocoa (MIT)

```
The MIT License (MIT)

Copyright (c) 2015 Sentry

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The HQC reference implementation is public domain and needs no licence text;
its upstream notice is quoted above.

---

## Keeping this accurate

- Update this file in the **same commit** that adds, removes or bumps a
  dependency.
- Record commit SHAs, not branch names. A branch is not a provenance claim.
- Re-check upstream licences on every bump — projects relicense.
- When a vendored component is patched, the patch belongs in the tree as a
  patch file, so the diff against upstream stays visible.

Questions or corrections: <support@martinrougeron.me>.
