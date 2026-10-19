#!/usr/bin/env bash
# Prints one hash over every file the core's Apple build reads: the
# workspace manifests and lock file, the crates the library is made of, the
# HQC pin and wrapper it compiles, and the build scripts. Compared with core/swift/HQChatCore/.source to tell a
# stale committed build; other crates (the Node addon, the fuzz oracle) and
# their tests do not count.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
git ls-files -co --exclude-standard -- core/Cargo.toml core/Cargo.lock core/hqc-sys core/hqc \
  core/hqchat-protocol/src core/hqchat-protocol/Cargo.toml core/hqchat-engine/src core/hqchat-engine/Cargo.toml \
  core/hqchat-ffi/src core/hqchat-ffi/Cargo.toml core/hqchat-ffi/build-apple.sh core/hqchat-ffi/apple-source-hash.sh \
  native/hqc/HQC_UPSTREAM.txt native/hqc/prepare-source.sh native/hqc/src \
  | LC_ALL=C sort | while IFS= read -r f; do
    [[ -f "$f" ]] && printf '%s  %s\n' "$(shasum -a 256 <"$f" | cut -d' ' -f1)" "$f"
  done | shasum -a 256 | cut -d' ' -f1
