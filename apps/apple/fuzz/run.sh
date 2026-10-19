#!/usr/bin/env bash
#
# The Swift half of the scrubber differential: Redaction.swift against
# services/server/src/common/scrub.ts, driven by
# services/server/test/fuzz/scrub-differential.ts.
#
#   ./run.sh scrub-verdict              build it
#
# The protocol's parsers, which the other targets here used to fuzz, now live
# in the Rust core: they are fuzzed against the TypeScript reference there
# (`scripts/check.sh core`, `hqchat-verdict`).
set -euo pipefail
cd "$(dirname "$0")"

BUILD="build"
mkdir -p "$BUILD"

case "${1:-}" in
  scrub-verdict)
    # The pair is maintained by hand and each file asks the next person to keep
    # them in step; this is what checks whether anyone did. A divergence here
    # leaks a secret from whichever side redacts less.
    echo "── building scrub-verdict ─────────────────────"
    cp ScrubVerdict.swift "$BUILD/main.swift"
    xcrun swiftc -O "$BUILD/main.swift" ../HQChat/Helpers/Redaction.swift -o "$BUILD/scrub-verdict"
    echo "built $BUILD/scrub-verdict"
    ;;
  *)
    sed -n '3,11p' "$0"
    exit 2
    ;;
esac
