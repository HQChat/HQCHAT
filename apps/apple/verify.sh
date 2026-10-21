#!/usr/bin/env bash
# The full Apple gate, run locally before merging anything under apps/apple/
# and before a release (macOS runners are too costly for CI):
#
#   bash apps/apple/verify.sh
#
# The xcodebuild invocations share one DerivedData directory.
set -euo pipefail

cd "$(dirname "$0")"

DERIVED="${DERIVED_DATA_PATH:-$PWD/.build/DerivedData}"
# The newest iPhone simulator this Xcode has, unless SIM_NAME names one.
SIM_NAME="${SIM_NAME:-$(xcrun simctl list devices available | sed -n 's/^ *\(iPhone [^(]*[^ (]\) (.*/\1/p' | tail -1)}"
mkdir -p "$DERIVED"

command -v xcodebuild >/dev/null || {
  echo "❌ xcodebuild not found — this script needs Xcode and only runs on macOS." >&2
  exit 1
}

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# 0. The Rust core (HQChatCore), built from this checkout: the xcframework is
#     never committed, so a clone has none until this runs (cargo rebuilds only
#     what changed). The committed bindings must be the ones it generates.
step "Rust core (HQChatCore)"
core_pkg=../../core/swift/HQChatCore
nix develop "$(cd ../.. && pwd)#apple" --command bash ../../core/hqchat-ffi/build-apple.sh
if ! git diff --quiet -- "$core_pkg/Sources"; then
  echo "⚠️  the core's Swift bindings changed: commit core/swift/HQChatCore/Sources with the core change"
fi
(cd "$core_pkg" && xcrun swift test)
# The shell that carries out the engine's effects (apps/apple/CoreShell).
(cd CoreShell && xcrun swift test)

# 1. The Swift suites (the move from 3.1.1, the store and reset, TLS pinning,
#    the shared unlock, redaction), compiled from the real implementations.
#
#    A suite that skips a check fails unless tests/expected-skips.txt budgets
#    it: some checks cannot run in an unsigned local build (Secure Enclave and
#    the keychain access group).
step "Swift tests (move / store / pinning / unlock)"
COVERAGE=1 bash tests/run.sh

# The number that says how much of the app those suites actually reach.
#
# There is no Xcode unit-test target here, so `-enableCodeCoverage` has nothing
# to attach to — but swiftc takes the instrumentation flags directly, so the
# compile lists in tests/run.sh stay the single source of truth and still produce
# per-file coverage. NO THRESHOLD YET: this establishes the baseline, and the
# gate goes on once the number is somewhere worth defending.
step "Swift coverage"
bash tests/coverage-report.sh

# 2. macOS app builds. No signing: this proves the target compiles, nothing more.
step "Build macOS"
xcodebuild -scheme HQChat -destination 'platform=macOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build

# 3. iOS app builds for a real device slice.
step "Build iOS (device)"
xcodebuild -scheme 'HQChat iOS' -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build

# 4. UI tests on the simulator. Split into build-for-testing + test-without-
#    building so the compile is visible separately from the (flakier) run, and
#    so a rerun of just the tests doesn't recompile.
step "Build for testing (iOS simulator)"
xcodebuild -scheme 'HQChat iOS' -destination "platform=iOS Simulator,name=$SIM_NAME" \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet build-for-testing

#     TEST_RUNNER_HQCAT_UNSIGNED tells the UI bundle what this invocation
#     already knows: CODE_SIGNING_ALLOWED=NO, so the app has no keychain access
#     group and SecKeyCreateRandomKey fails with -34018 errSecMissingEntitlement.
#     Two tests depend on that key and skip on it (MAS-8). xcodebuild strips the
#     TEST_RUNNER_ prefix on the way into the test process.
#
#     Declared rather than detected on purpose. The first attempt asked the test
#     process `SecureEnclave.isAvailable`, which is TRUE on a modern Simulator
#     and answers the wrong question twice over — the blocker is signing, not the
#     Enclave, and XCUITest runs in a different process from the app whose
#     entitlements actually decide it. A signed device run simply does not set
#     this, and the two tests run.
step "UI tests (iOS simulator: $SIM_NAME)"
TEST_RUNNER_HQCAT_UNSIGNED=1 \
  xcodebuild -scheme 'HQChat iOS' -destination "platform=iOS Simulator,name=$SIM_NAME" \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  -quiet test-without-building

# The protocol itself (frames, handshake, ratchet, hqn/1, MQTT) is the Rust
# core's, tested and fuzzed against the TypeScript reference by
# `scripts/check.sh core`; the app's store runs live against the local stack in
# `scripts/check.sh scenarios` (apps/apple/e2e/hqn-live). What stays here is
# what only Swift has.

# 5. The scrubber, against its TypeScript twin.
#
#     src/common/scrub.ts and Redaction.swift are one rule set maintained twice, and
#     each file asks the next person to keep them in step. This is what checks
#     whether anyone did. It has already found a ReDoS that hung both engines and
#     a key-name split that made the CLIENT — the side holding plaintext — redact
#     less than the server.
step "Scrubber differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh scrub-verdict
(cd ../../services/server &&
  npx tsx test/fuzz/scrub-differential.ts \
    --iterations "${FUZZ_SCRUB_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode redact &&
  npx tsx test/fuzz/scrub-differential.ts \
    --iterations "${FUZZ_SCRUB_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode key)

# Record WHAT was verified, so a push can check it.
#
# This gate is local by choice — a macOS runner was 84% of this repo's Actions
# bill — and a local gate only works if it is actually run. The stamp is what
# makes "I ran verify.sh" checkable instead of a claim: apps/apple/hooks/pre-push
# reads it and refuses to push Apple changes it does not cover.
#
# A dirty tree stamps as dirty rather than as HEAD. Verifying uncommitted work
# says nothing about the commit that gets pushed, and quietly pretending
# otherwise is the failure mode this is meant to remove.
mkdir -p .build
if [ -z "$(git status --porcelain -- . 2>/dev/null)" ]; then
  git rev-parse HEAD >.build/verify-stamp
else
  echo "dirty" >.build/verify-stamp
fi

printf '\n\033[1;32m✅ Apple verification passed\033[0m\n'
printf '   stamped %s\n' "$(cat .build/verify-stamp)"
