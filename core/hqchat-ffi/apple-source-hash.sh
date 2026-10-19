#!/usr/bin/env bash
# Prints one hash over every file the core's Apple build reads: the workspace
# sources, manifests and lock file, and the bindings' build script. Compared
# with core/swift/HQChatCore/.source to tell a stale committed build.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
git ls-files -co --exclude-standard -- core ':!core/swift' ':!core/target' \
  | LC_ALL=C sort | while IFS= read -r f; do
    [[ -f "$f" ]] && printf '%s  %s\n' "$(shasum -a 256 <"$f" | cut -d' ' -f1)" "$f"
  done | shasum -a 256 | cut -d' ' -f1
