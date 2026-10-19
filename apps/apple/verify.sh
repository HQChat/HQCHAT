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
SIM_NAME="${SIM_NAME:-iPhone 16 Pro}"
mkdir -p "$DERIVED"

command -v xcodebuild >/dev/null || {
  echo "❌ xcodebuild not found — this script needs Xcode and only runs on macOS." >&2
  exit 1
}

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# 0. The HQC wrapper, built from the pinned source (its C self-test runs in `nix build .#hqc`).
step "Native HQC wrapper"
nix build "$(cd ../.. && pwd)#hqc" --no-link
bash ../../native/hqc/build-apple.sh

# 0b. The Rust core (HQChatCore), rebuilt when its sources moved since the
#     committed build, then its Swift tests against the xcframework.
step "Rust core (HQChatCore)"
core_pkg=../../core/swift/HQChatCore
if [[ "$(cat "$core_pkg/.source" 2>/dev/null)" != "$(bash ../../core/hqchat-ffi/apple-source-hash.sh)" ]]; then
  nix develop "$(cd ../.. && pwd)#apple" --command bash ../../core/hqchat-ffi/build-apple.sh
  echo "⚠️  rebuilt core/swift/HQChatCore: commit it with the core change"
fi
(cd "$core_pkg" && xcrun swift test)
# The shell that carries out the engine's effects (apps/apple/CoreShell).
(cd CoreShell && xcrun swift test)

# 1. The pure-Swift suites (crypto, ratchet, key fingerprint, MQTT wire codec,
#    message-at-rest), compiled from the real implementations.
#
#    A suite that skips a check fails unless tests/expected-skips.txt budgets
#    it: some checks cannot run in an unsigned local build (Secure Enclave and
#    the keychain access group).
step "Swift tests (crypto / ratchet / codec)"
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

# 4b. The two targets that need no TypeScript half.
#
#     `topic-route` is `MQTTTopics.route` on attacker-supplied strings — every
#     inbound publish carries a topic the sender chose, and route decides which
#     conversation the payload belongs to before anything authenticates who sent
#     it. `scrub-verdict` is built here rather than run, because its driver lives
#     on the TypeScript side (step 5b).
step "Topic routing fuzz"
bash fuzz/run.sh topic-route --iterations "${FUZZ_TOPIC_ITERATIONS:-50000}" --seed "${FUZZ_SEED:-$RANDOM}"

#     `n` and `pn` arrive on a frame header and are read to CHOOSE the message
#     key, so they cannot have been authenticated by the payload that key opens.
#     A gap walked before it is bounded is an HKDF per step — two billion of them
#     at n = 2^31, on the MainActor.
step "Ratchet state fuzz"
bash fuzz/run.sh ratchet-state --iterations "${FUZZ_RATCHET_ITERATIONS:-10000}" --seed "${FUZZ_SEED:-$RANDOM}"

# 5. Cross-implementation frame fuzzing.
#
# This is the check CI cannot run. `ConversationEnvelopeV3.decodeReporting`
# and services/server/test/reference/protocol/envelope.ts `decodeFrame` must be the same
# predicate over the same bytes; a divergence passes both suites while one
# end silently drops the other's frames.
#
# Three oracles: verdict, AAD and the decoded fields. An AAD divergence
# surfaces as a GCM tag mismatch, indistinguishable from a wrong key.
#
# Seeded from the shared vectors, then mutated. A finding is written to
# services/server/test/fuzz/findings/. Frames carry up to 58 kB of KEM
# material, so this runs at a few hundred per second; mutations aim at the
# header, where the offsets are.
step "Frame differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh envelope-v3-verdict
(cd ../../services/server && npx tsx test/fuzz/envelope-v3-differential.ts \
  --iterations "${FUZZ_V3_ITERATIONS:-5000}" --seed "${FUZZ_SEED:-$RANDOM}")

# 7. The same two implementations, from the other end.
#
#    Everything above tests DECODERS. The encoders were the half nobody had
#    pointed a fuzzer at, and they disagreed on every malformed input, because
#    they fail in structurally different ways: TypeScript copies into a fixed
#    buffer (short pads, long clips), Swift appends (a wrong length shifts every
#    field after it), and writeUInt32BE throws where truncatingIfNeeded wraps.
#
#    Structs in, frames out: both must refuse the same ones and produce
#    byte-identical bytes for the rest. Faster than the decode driver — a
#    generator, no mutation corpus — so the default count is higher.
step "Envelope v3 ENCODE differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh envelope-v3-encode-verdict
(cd ../../services/server && npx tsx test/fuzz/envelope-v3-encode-differential.ts \
  --iterations "${FUZZ_V3_ENCODE_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}")

# 7b. The scrubber, against its TypeScript twin.
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

# 7c. The handshake frame, both directions.
#
#     h/{friendshipHash} carries what closes the impersonation gap an init leaves
#     open, and both ends parse it with hand-written offset arithmetic. Until this
#     existed the only thing comparing them was five pinned vectors they agree on
#     by construction.
#
#     Three modes: decode (bytes in), encode (frames in — the half the envelope
#     work found diverging on every malformed input while the decoders agreed),
#     and round, which checks each side is its own inverse.
step "Handshake differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh handshake-verdict
(cd ../../services/server &&
  for m in decode encode round; do
    npx tsx test/fuzz/handshake-differential.ts \
      --iterations "${FUZZ_HANDSHAKE_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode "$m" || exit 1
  done)

#   hqn/1 — the raw-TCP transport's Noise handshake and framing. The pinned
#   vectors cover VALID transcripts; this covers the input an attacker controls:
#   frame streams cut anywhere, mutated server replies (Swift and TypeScript
#   must refuse the same ones), and — TypeScript only — the gateway's responder,
#   which must refuse every hostile msg1 without a single unexpected exception.
step "hqn/1 differential fuzz (Swift ↔ TypeScript)"
bash fuzz/run.sh noise-verdict
(cd ../../services/server &&
  for m in frames msg2 responder; do
    npx tsx test/fuzz/noise-differential.ts \
      --iterations "${FUZZ_NOISE_ITERATIONS:-20000}" --seed "${FUZZ_SEED:-$RANDOM}" --mode "$m" || exit 1
  done)

# 8. A whole interaction through the real Swift implementation: first contact
#    to a verified transcript (friend request, prekey claim, init, the
#    initiator-authentication handshake, five messages each way, replay
#    refusal) over a file bus, with the real HQC library linked.
step "End-to-end (file bus, real HQC)"
bash e2e/run.sh

# 9. The same script over a channel that misbehaves.
#
#    Nothing above is interesting over a perfect channel: the ratchet's
#    skipped-key cache and the replay refusal are only reachable when delivery
#    duplicates or reorders, and MQTT at QoS 1 promises at LEAST once, so a
#    redelivery is ordinary rather than exotic. Seeded, so a failure replays.
#
#    The run asserts that the channel actually misbehaved — a fault injector that
#    injects nothing reports the same green as a clean run.
step "End-to-end over a lossy channel"
bash e2e/run.sh --faults --seed "${FUZZ_SEED:-$RANDOM}"

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
