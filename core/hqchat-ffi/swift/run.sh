#!/usr/bin/env bash
# Generates the Swift bindings from the built library, compiles main.swift
# against them and runs it. macOS, inside `nix develop`:
#
#   core/hqchat-ffi/swift/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
core="$here/../.."
out="$core/target/swift-bindings"
cd "$core"
cargo build --manifest-path "$core/Cargo.toml" -p hqchat-ffi
rm -rf "$out" && mkdir -p "$out"
cargo run -q --manifest-path "$core/Cargo.toml" -p hqchat-ffi --bin uniffi-bindgen -- \
  generate --no-format --library "$core/target/debug/libhqchat_ffi.dylib" --language swift --out-dir "$out"
# Xcode's swiftc, not a Nix one: the bindings target the Apple SDK.
/usr/bin/xcrun swiftc -O -module-name HQChatCoreTest \
  -I "$out" -Xcc -fmodule-map-file="$out/hqchat_ffiFFI.modulemap" \
  "$out/hqchat_ffi.swift" "$here/main.swift" \
  -L "$core/target/debug" -lhqchat_ffi -o "$out/test"
DYLD_LIBRARY_PATH="$core/target/debug" "$out/test"
