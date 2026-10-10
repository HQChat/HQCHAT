#!/usr/bin/env bash
# Builds the Apple targets of the HQC wrapper from the source Nix pins
# (`nix build .#hqc.source`), where the Xcode project and the Swift test
# scripts link them:
#
#   apps/apple/libhqc_wrap.dylib                    macOS arm64
#   native/hqc/dist/apple/HQC.xcframework           iOS device + simulator (arm64, x86_64)
#
# Does nothing when both already exist for the current source. Needs Nix and Xcode.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
dylib="$root/apps/apple/libhqc_wrap.dylib"
xcframework="$here/dist/apple/HQC.xcframework"
stamp="$here/dist/apple/.source"
ios_min=14.0

src="$(nix build --no-link --print-out-paths "$root#hqc.source")"
if [[ -f "$dylib" && -d "$xcframework" && "$(cat "$stamp" 2>/dev/null)" == "$src" ]]; then
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sources=("$src"/src/common/*.c "$src"/src/ref/*.c "$src/lib/fips202/fips202.c" "$src/low_wrap.c")
flags=(-O2 -DHQC_ARCH_REF=1 -I"$src/src/common" -I"$src/src/common/hqc-5" -I"$src/src/ref"
  -I"$src/src/ref/hqc-5" -I"$src/lib/fips202" -I"$src" -include "$src/hqc_portability.h")

# objects <name> <clang target> <sdk>
objects() {
  local dir="$work/$1"
  mkdir -p "$dir"
  for f in "${sources[@]}"; do
    xcrun --sdk "$3" clang -target "$2" "${flags[@]}" -c "$f" -o "$dir/$(basename "${f%.c}").o"
  done
}

objects macos arm64-apple-macos13.0 macosx
xcrun clang -dynamiclib -target arm64-apple-macos13.0 -install_name @rpath/libhqc_wrap.dylib \
  "$work"/macos/*.o -o "$dylib"

objects device "arm64-apple-ios$ios_min" iphoneos
objects sim_arm64 "arm64-apple-ios$ios_min-simulator" iphonesimulator
objects sim_x86 "x86_64-apple-ios$ios_min-simulator" iphonesimulator
ar rcs "$work/libhqc_wrap_device.a" "$work"/device/*.o
ar rcs "$work/sim_arm64.a" "$work"/sim_arm64/*.o
ar rcs "$work/sim_x86.a" "$work"/sim_x86/*.o
lipo -create "$work/sim_arm64.a" "$work/sim_x86.a" -output "$work/libhqc_wrap_simulator.a"

mkdir -p "$work/headers"
cp "$here/include/public_wrapper.h" "$work/headers/wrapper.h"
rm -rf "$xcframework"
mkdir -p "$(dirname "$xcframework")"
xcodebuild -create-xcframework \
  -library "$work/libhqc_wrap_device.a" -headers "$work/headers" \
  -library "$work/libhqc_wrap_simulator.a" -headers "$work/headers" \
  -output "$xcframework" >/dev/null
printf '%s' "$src" >"$stamp"
echo "built $dylib and $xcframework from $src"
