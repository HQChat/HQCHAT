#!/usr/bin/env bash
# The HQC reference tree as every build compiles it:
#
#   prepare-source.sh <upstream checkout> <out> [wrapper dir, default native/hqc/src]
#
# copies the upstream `src` and `lib` into <out>, guards the x86 intrinsics
# headers the reference C includes but never uses (so it compiles for ARM), and
# adds the wrapper sources. package.nix runs this; the Linux library and the
# Rust core (core/hqc-sys, through HQC_SOURCE) both build from its output, so
# every target compiles the same bytes. POSIX tools only: it runs on GNU and BSD alike.
set -euo pipefail

upstream="$1"
out="$2"
wrapper="${3:-$(cd "$(dirname "$0")" && pwd)/src}"

mkdir -p "$out"
cp -R "$upstream/src" "$upstream/lib" "$out/"
chmod -R u+w "$out"

grep -rlE '#include <(imm|emm|x86|xmm|smm|tmm|pmm|nmm|wmm|mm)intrin\.h>' "$out/src" | while read -r h; do
  awk '/^[[:space:]]*#include <(imm|emm|x86|xmm|smm|tmm|pmm|nmm|wmm|mm)intrin\.h>/ {
         print "#if defined(__i386__) || defined(__x86_64__)"; print; print "#endif"; next
       }
       { print }' "$h" >"$h.guarded"
  mv "$h.guarded" "$h"
done

cp "$wrapper"/* "$out/"
