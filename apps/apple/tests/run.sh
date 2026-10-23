#!/usr/bin/env bash
#
# Compiles selected app source files together with the Swift test files and
# runs them. Tests the real implementations (no copies) without needing an
# Xcode test target. Used by CI and runnable locally: `bash apple/tests/run.sh`
#
set -euo pipefail

cd "$(dirname "$0")"
LOG_SWIFT="$(pwd)/../HQChat/Helpers/Log.swift"
SRC="../HQChat/Services"
MODELS="../HQChat/Models"
HELPERS="../HQChat/Helpers"
APP="../HQChat"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- Skip census -------------------------------------------------------------
# A skipped check is coverage that left. expected-skips.txt says how many skips
# each suite is allowed; a suite with no line gets zero, and exceeding the
# allowance fails the run. See TestSupport.swift.
CENSUS="$PWD/expected-skips.txt"
expected_skips() {
  # Tab-separated: <suite> <count> <reason>. Missing suite -> 0.
  awk -v s="$1" -F'\t' '$1 == s { print $2; found = 1 } END { if (!found) print 0 }' "$CENSUS"
}

# --- Coverage (opt-in) -------------------------------------------------------
# COVERAGE=1 builds every slice with source-based coverage instrumentation and
# writes a per-file report at the end.
#
# WHY NOT AN XCODE TEST TARGET. `xcodebuild test -enableCodeCoverage YES` needs a
# unit-test bundle, and this project has none — the suites are compiled here by
# swiftc from explicit source lists. Adding a target would mean maintaining those
# lists twice, in a .pbxproj, which is exactly the duplication that broke this
# script silently once before. swiftc takes the same instrumentation flags
# directly, so the compile lists below stay the single source of truth.
#
#   COVERAGE=1 bash tests/run.sh
#
# shellcheck disable=SC2086  # COV_FLAGS is deliberately word-split
COVERAGE="${COVERAGE:-0}"
COV_FLAGS=""
BINDIR="$TMP"

# Each slice stages its test file as main.swift (Swift requires top-level code to
# live there). Give every slice its OWN directory: sharing one path made
# llvm-profdata see conflicting records for `main.swift:main` and warn
# "counter mismatch" on every merge, which would hide a real one.
# Staged under $TMP/stage/, NOT $TMP/ — macOS is case-insensitive by default, so
# a staging dir named CryptoTests collides with the binary cryptoTests and the
# linker fails with "Is a directory". Only bites when COVERAGE is unset, because
# the binaries move to .coverage/bin when it is set.
stage() { # stage <TestFile.swift> -> prints the staged main.swift path
  local d="$TMP/stage/${1%.swift}"
  mkdir -p "$d"
  cp "$1" "$d/main.swift"
  echo "$d/main.swift"
}

# The core's Swift module (core/swift/HQChatCore) and the shell around it
# (apps/apple/CoreShell), compiled once for the slices that build every app
# file: the files that talk to the core import them, as the app does through
# its Swift packages. Those slices target the app's own macOS deployment
# target, which the core's library is built for.
CORE_PKG="$(cd ../../../core/swift/HQChatCore && pwd)"
CORE_FFI="$CORE_PKG/HQChatCoreFFI.xcframework/macos-arm64"
CORE_MOD="$TMP/core-module"
mkdir -p "$CORE_MOD"
xcrun swiftc -O -target arm64-apple-macos15.5 -swift-version 5 -parse-as-library \
  -module-name HQChatCore -emit-module -emit-module-path "$CORE_MOD/HQChatCore.swiftmodule" \
  -emit-library -static -o "$CORE_MOD/libHQChatCore.a" \
  -I "$CORE_FFI/Headers" "$CORE_PKG/Sources/HQChatCore/HQChatCore.swift"
xcrun swiftc -O -target arm64-apple-macos15.5 -swift-version 5 -parse-as-library \
  -module-name CoreShell -emit-module -emit-module-path "$CORE_MOD/CoreShell.swiftmodule" \
  -emit-library -static -o "$CORE_MOD/libCoreShell.a" \
  -I "$CORE_MOD" -I "$CORE_FFI/Headers" ../CoreShell/Sources/CoreShell/*.swift
CORE_FLAGS=(-I "$CORE_MOD" -I "$CORE_FFI/Headers" -L "$CORE_MOD" -lCoreShell -lHQChatCore "$CORE_FFI/libhqchat_ffi.a")
if [ "$COVERAGE" = "1" ]; then
  COV_DIR="${COV_DIR:-$PWD/.coverage}"
  rm -rf "$COV_DIR"
  mkdir -p "$COV_DIR/bin"
  BINDIR="$COV_DIR/bin"
  COV_FLAGS="-profile-generate -profile-coverage-mapping"
  # %m expands to a per-binary signature, so each slice writes its own raw
  # profile without any per-invocation plumbing.
  export LLVM_PROFILE_FILE="$COV_DIR/%m.profraw"
fi

# Top-level test code must live in a file named main.swift when compiling
# multiple files, so each test file is copied there before building.
#
# A slice with an explicit list must list the FULL transitive source set —
# there is no target here to resolve it. The slices that reach the store build
# every non-view file instead (APP_SOURCES below).
echo "── Network path change rule ───────────────────"
MAIN="$(stage ReachabilityTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" \
  "$SRC/Reachability.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/reachabilityTests"
"$BINDIR/reachabilityTests"

echo ""
echo "── Redaction (the Sentry scrubber) ────────────"
# The last thing that runs before an event leaves the device. A miss here sends
# plaintext to a third-party crash reporter from the one place that has it.
# Untestable until Redaction.swift was split out of Observability.swift, which
# imports Sentry and so could not be compiled by a slice.
MAIN="$(stage RedactionTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/Redaction.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/redactionTests"
"$BINDIR/redactionTests"

echo ""
echo "── Key protection tier (the -25293 fix) ───────"
# Pure mapping checks: capability→tier, tier→LAPolicy, tier→ACL flag, and the
# marker's default. Every Keychain incident this app has had was a mapping that
# drifted, and none of them failed loudly — a `.devicePasscode` key
# authenticated `WithBiometrics` simply never opens.
MAIN="$(stage KeyProtectionTierTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/DeviceAuthCapability.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/keyProtectionTierTests"
EXPECTED_SKIPS="$(expected_skips KeyProtectionTierTests)" "$BINDIR/keyProtectionTierTests"

echo ""
echo "── Pure rules (username filter, error text) ───"
# UsernameRule is the ONLY input filter on this client — `sanitized` runs as the
# user types, so it decides whether a paste can reach the field at all. AppError
# is what a person actually reads when something fails. Neither had ever been
# compiled by a test.
MAIN="$(stage PureHelpersTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/UsernameRule.swift" "$MODELS/AppError.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/pureHelpersTests"
"$BINDIR/pureHelpersTests"

echo ""
echo "── Protocol trace (what Release is allowed to log) ──"
# The one log that survives Release, on a device with no Mac attached. It is only
# allowed to exist because redaction there is by CONSTRUCTION — no Event case can
# carry a payload, a key or a username. Nothing checked that rule, so a case
# added tomorrow could ship free text into the unified log, where `log collect`
# hands it to anyone with the device.
MAIN="$(stage ProtocolLogTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$HELPERS/ProtocolLog.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/protocolLogTests"
"$BINDIR/protocolLogTests"

echo ""
echo "── TLS pinning (MAS-2) ────────────────────────"
# The one check between this client and anyone holding a certificate a system
# root will vouch for. What is actually fragile is `spkiSHA256`, which rebuilds
# the DER SubjectPublicKeyInfo from a hand-written table of four ASN.1 headers —
# a wrong entry matches no pin, refuses every connection, and looks exactly like
# an attack in the log.
#
# So the fixtures are REAL certificates and the expected digest is computed by
# openssl, not restated in Swift. Generated per run: Swift has no X.509 writer,
# and a committed certificate expires.
PIN_FIXTURES="$TMP/pins"
mkdir -p "$PIN_FIXTURES"
gen_pin_fixture() {
  local name="$1"
  shift
  openssl req -x509 -nodes -days 2 -subj "/CN=$name.pin.test" \
    "$@" -keyout "$PIN_FIXTURES/$name.key" -out "$PIN_FIXTURES/$name.pem" 2>/dev/null
  openssl x509 -in "$PIN_FIXTURES/$name.pem" -outform der -out "$PIN_FIXTURES/$name.der"
  # The SPKI digest, the way every pinning guide tells you to compute it.
  openssl x509 -in "$PIN_FIXTURES/$name.pem" -pubkey -noout |
    openssl pkey -pubin -outform der |
    openssl dgst -sha256 -hex |
    sed 's/.*= *//' >"$PIN_FIXTURES/$name.sha256"
}
gen_pin_fixture rsa2048 -newkey rsa:2048
gen_pin_fixture rsa4096 -newkey rsa:4096
gen_pin_fixture ec256 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1
gen_pin_fixture ec384 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1

MAIN="$(stage TLSPinningTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/TLSPinning.swift" "../HQChat/Deployment.swift" \
  -framework Security \
  "$LOG_SWIFT" \
  -o "$BINDIR/tlsPinningTests"
"$BINDIR/tlsPinningTests" "$PIN_FIXTURES"

echo ""
echo "── Shared auth context (one prompt, every key) ──"
# The LAContext the unlock produces, shared by everything that needs the
# profile's keys (the core's vault, and the move's reads of 3.1.1 items), so
# one unlock opens them all.
MAIN="$(stage SharedAuthContextTests.swift)"
xcrun swiftc -O $COV_FLAGS \
  "$MAIN" TestSupport.swift \
  "$SRC/MessageKeyStore.swift" "$SRC/DeviceAuthCapability.swift" \
  "$SRC/BiometricAudit.swift" "$SRC/BiometricCoordinator.swift" \
  "$LOG_SWIFT" \
  -o "$BINDIR/sharedAuthContextTests"
"$BINDIR/sharedAuthContextTests"

# Every non-view app file, for the slices that reach the store and the move.
# A glob with a skip list rather than a hand-kept list, so a new file cannot be
# forgotten here; the skipped ones import UI or Sentry.
APP_SOURCES=()
for f in "$APP"/*.swift "$APP"/Models/*.swift "$APP"/Services/*.swift \
  "$APP"/Helpers/*.swift "$APP"/Migration/*.swift; do
  case "${f##*/}" in
    ContentView.swift | HQChatApp.swift | PlatformColors.swift | \
      StatusPresentation.swift | Observability.swift) continue ;;
  esac
  APP_SOURCES+=("$f")
done

echo ""
echo "── Moving a profile to the core ───────────────"
# The import the app runs once per profile: 3.1.1 records, mapped into the
# core's ImportData and opened by a real engine (Migration/CoreImport.swift).
MAIN="$(stage CoreImportTests.swift)"
xcrun swiftc -O $COV_FLAGS -target arm64-apple-macos15.5 \
  "$MAIN" TestSupport.swift \
  "${APP_SOURCES[@]}" "${CORE_FLAGS[@]}" \
  -framework Security \
  -o "$BINDIR/coreImportTests"
"$BINDIR/coreImportTests" "$PWD/fixtures/legacy-3.1.1-session.json"

echo ""
echo "── Store, move and reset ──────────────────────"
# The profile list, the 3.1.1 rows the move deletes, and a reset that leaves
# no row and no core store behind.
MAIN="$(stage PersistenceTests.swift)"
xcrun swiftc -O $COV_FLAGS -target arm64-apple-macos15.5 \
  "$MAIN" TestSupport.swift \
  "${APP_SOURCES[@]}" "${CORE_FLAGS[@]}" \
  -framework Security \
  -o "$BINDIR/persistenceTests"
"$BINDIR/persistenceTests"

echo ""
echo "✅ All Swift tests passed"
