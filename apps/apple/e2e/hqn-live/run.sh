#!/usr/bin/env bash
#
# The app's ChatStore, live, against the local e2e stack's server, noise-gw and
# EMQX. Called by services/server/test/scenarios/run-local.sh with the stack's
# env set (TEST_BASE_URL, TEST_MQTT_URL, TEST_HQN_HOST).
set -euo pipefail
cd "$(dirname "$0")"
APP="../../HQChat"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

CORE_PKG="$(cd ../../../../core/swift/HQChatCore && pwd)"
CORE_FFI="$CORE_PKG/HQChatCoreFFI.xcframework/macos-arm64"
xcrun swiftc -O -target arm64-apple-macos15.5 -swift-version 5 -parse-as-library \
  -module-name HQChatCore -emit-module -emit-module-path "$BUILD/HQChatCore.swiftmodule" \
  -emit-library -static -o "$BUILD/libHQChatCore.a" \
  -I "$CORE_FFI/Headers" "$CORE_PKG/Sources/HQChatCore/HQChatCore.swift"
xcrun swiftc -O -target arm64-apple-macos15.5 -swift-version 5 -parse-as-library \
  -module-name CoreShell -emit-module -emit-module-path "$BUILD/CoreShell.swiftmodule" \
  -emit-library -static -o "$BUILD/libCoreShell.a" \
  -I "$BUILD" -I "$CORE_FFI/Headers" ../../CoreShell/Sources/CoreShell/*.swift

# Every non-view app file, as tests/run.sh builds them.
SOURCES=()
for f in "$APP"/*.swift "$APP"/Models/*.swift "$APP"/Services/*.swift \
  "$APP"/Helpers/*.swift "$APP"/Migration/*.swift; do
  case "${f##*/}" in
    ContentView.swift | HQChatApp.swift | PlatformColors.swift | \
      StatusPresentation.swift | Observability.swift) continue ;;
  esac
  SOURCES+=("$f")
done

xcrun swiftc -O -target arm64-apple-macos15.5 -swift-version 5 \
  main.swift "${SOURCES[@]}" \
  -I "$BUILD" -I "$CORE_FFI/Headers" -L "$BUILD" -lCoreShell -lHQChatCore "$CORE_FFI/libhqchat_ffi.a" \
  -framework Security \
  -o "$BUILD/hqn-live"
"$BUILD/hqn-live"
