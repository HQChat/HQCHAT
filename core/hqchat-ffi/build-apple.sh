#!/usr/bin/env bash
# Builds the core for the Apple app:
#
# into the Swift package core/swift/HQChatCore, which the app links:
#
#   HQChatCoreFFI.xcframework           static libraries: iOS device (arm64),
#                                       iOS simulator (arm64 + x86_64), macOS (arm64)
#   Sources/HQChatCore/HQChatCore.swift the uniffi bindings, generated from them
#
# The xcframework is never committed: it is built here, once after a clone
# and after every core change (apps/apple/verify.sh runs this), and by the
# Apple release workflow on its own runner before it archives. The bindings
# are committed, so a change to the core's Swift surface shows in review; the
# release workflow fails when the ones it generates differ from them.
# `.built-from` records the commit built, or `dirty` when the core's inputs had
# uncommitted changes; apps/apple/release.sh ships nothing else.
#
# Runs inside `nix develop .#apple` (Rust with the Apple targets, HQC_SOURCE),
# or anywhere `cargo` has those four targets and HQC_SOURCE names the prepared
# HQC tree (`nix build .#hqc.source`, or native/hqc/prepare-source.sh). Needs
# Xcode. The deployment targets are the app's own.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
core="$(cd "$here/.." && pwd)"
: "${HQC_SOURCE:?HQC_SOURCE is not set: run inside nix develop .#apple}"

export IPHONEOS_DEPLOYMENT_TARGET=18.5
export MACOSX_DEPLOYMENT_TARGET=15.5
# Xcode's compiler and archiver, never a Nix-wrapped one: the wrapper adds
# host (macOS) flags to every compile, which iOS targets refuse.
CC="$(xcrun --find clang)"
AR="$(xcrun --find ar)"
export CC AR
for t in AARCH64_APPLE_IOS AARCH64_APPLE_IOS_SIM X86_64_APPLE_IOS AARCH64_APPLE_DARWIN; do
  export "CARGO_TARGET_${t}_LINKER=$CC"
done
unset NIX_CFLAGS_COMPILE NIX_LDFLAGS NIX_CC NIX_BINTOOLS SDKROOT DEVELOPER_DIR LIBRARY_PATH
targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin)
target_dir="$core/target/apple"
lib=libhqchat_ffi.a
out="$core/swift/HQChatCore"
xcframework="$out/HQChatCoreFFI.xcframework"
swift_out="$out/Sources/HQChatCore/HQChatCore.swift"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# What this build is made from, taken before it starts: the commit, unless the
# core's inputs differ from it.
built_from="$(git -C "$core" rev-parse HEAD)"
if [[ -n "$(git -C "$core/.." status --porcelain -- core native flake.nix flake.lock)" ]]; then
  built_from=dirty
fi
rm -f "$out/.built-from"

for t in "${targets[@]}"; do
  # The static library alone: the crate's other types (cdylib, rlib) are for
  # the bindings generator and the tests.
  cargo rustc --manifest-path "$core/Cargo.toml" --locked --release -p hqchat-ffi --lib \
    --crate-type staticlib --target "$t" --target-dir "$target_dir"
done

# One library per platform: the two simulator architectures go into one file.
mkdir -p "$work/ios" "$work/ios-sim" "$work/macos"
cp "$target_dir/aarch64-apple-ios/release/$lib" "$work/ios/$lib"
lipo -create "$target_dir/aarch64-apple-ios-sim/release/$lib" "$target_dir/x86_64-apple-ios/release/$lib" \
  -output "$work/ios-sim/$lib"
cp "$target_dir/aarch64-apple-darwin/release/$lib" "$work/macos/$lib"
# Debug info and local symbols out (Rust's std ships with debug info): about a
# quarter of the size. Exported symbols stay.
for l in "$work"/*/"$lib"; do xcrun strip -S -x "$l" 2>/dev/null; done

# The bindings come from the library's own metadata, so they always match it.
# uniffi reads the workspace through cargo metadata, from the workspace.
cd "$core"
bindings="$work/bindings"
cargo run -q --manifest-path "$core/Cargo.toml" --locked -p hqchat-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --no-format --library "$target_dir/aarch64-apple-darwin/release/$lib" \
  --language swift --out-dir "$bindings"
headers="$work/headers"
mkdir -p "$headers"
cp "$bindings/hqchat_ffiFFI.h" "$headers/"
# Xcode looks for module.modulemap inside an xcframework's Headers.
cp "$bindings/hqchat_ffiFFI.modulemap" "$headers/module.modulemap"

rm -rf "$xcframework"
mkdir -p "$out"
xcodebuild -create-xcframework \
  -library "$work/ios/$lib" -headers "$headers" \
  -library "$work/ios-sim/$lib" -headers "$headers" \
  -library "$work/macos/$lib" -headers "$headers" \
  -output "$xcframework" >/dev/null
cp "$bindings/hqchat_ffi.swift" "$swift_out"
printf '%s\n' "$built_from" >"$out/.built-from"

echo "built $xcframework and $swift_out"
du -sh "$xcframework"/*/ | sed "s|$xcframework/||"
