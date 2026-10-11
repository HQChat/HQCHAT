#!/usr/bin/env bash
# Builds the Apple targets of the HQC wrapper, where the Xcode project and the
# Swift test scripts link them:
#
#   apps/apple/libhqc_wrap.dylib                    macOS arm64
#   native/hqc/dist/apple/HQC.xcframework           iOS device + simulator (arm64, x86_64)
#
# The source is the one Nix pins (`nix build .#hqc.source`). Without Nix (the
# Apple release workflow's macOS runner, see apps/apple/release.sh), the pinned
# commit in HQC_UPSTREAM.txt is fetched with git, checked against that commit
# id, and prepared by the same prepare-source.sh, so both paths compile the
# same bytes.
#
# Both outputs are committed, so the Xcode project builds and runs on a device
# straight from a clone. Rerun this and commit the result whenever
# HQC_UPSTREAM.txt moves; `scripts/check.sh lint` fails while the committed
# build names another commit. Releases rebuild from source regardless.
#
# Does nothing when both already exist for the current source. Needs Xcode, and
# Nix or git with network access.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
dylib="$root/apps/apple/libhqc_wrap.dylib"
xcframework="$here/dist/apple/HQC.xcframework"
stamp="$here/dist/apple/.source"
ios_min=14.0

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pin() { sed -n "s/^$1=//p" "$here/HQC_UPSTREAM.txt"; }
built_from() { [[ -f "$dylib" && -d "$xcframework" && "$(cat "$stamp" 2>/dev/null)" == "$1" ]]; }

if command -v nix >/dev/null 2>&1 && [[ -z "${HQC_WITHOUT_NIX:-}" ]]; then
  src="$(nix build --no-link --print-out-paths "$root#hqc.source")"
  id="$src"
  built_from "$id" && exit 0
else
  commit="$(pin PINNED_COMMIT)"
  id="git:$commit:$(cat "$here/prepare-source.sh" "$here"/src/* | git hash-object --stdin)"
  built_from "$id" && exit 0
  echo "fetching HQC $commit from $(pin REPO) (no Nix)"
  git init -q "$work/upstream"
  git -C "$work/upstream" fetch -q --depth 1 "$(pin REPO)" "$commit"
  git -C "$work/upstream" checkout -q FETCH_HEAD
  [[ "$(git -C "$work/upstream" rev-parse HEAD)" == "$commit" ]] || {
    echo "fetched commit is not $commit" >&2
    exit 1
  }
  src="$work/source"
  bash "$here/prepare-source.sh" "$work/upstream" "$src" "$here/src"
fi

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
printf '%s' "$id" >"$stamp"
echo "built $dylib and $xcframework from $id"
