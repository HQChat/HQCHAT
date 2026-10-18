#!/usr/bin/env bash
# Builds the addon and puts it where Node loads it: core/hqchat-node/hqchat_node.node.
#
#   core/hqchat-node/build.sh [--release]
#
# Runs inside `nix develop` (HQC_SOURCE and the toolchain).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
profile=debug
flags=()
if [[ "${1:-}" == "--release" ]]; then
  profile=release
  flags=(--release)
fi
cargo build --manifest-path "$here/../Cargo.toml" -p hqchat-node "${flags[@]}"
case "$(uname -s)" in
  Darwin) lib=libhqchat_node.dylib ;;
  MINGW* | MSYS* | CYGWIN*) lib=hqchat_node.dll ;;
  *) lib=libhqchat_node.so ;;
esac
cp "$here/../target/$profile/$lib" "$here/hqchat_node.node"
