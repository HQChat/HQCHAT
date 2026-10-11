#!/usr/bin/env bash
# Archive the iOS or macOS app, sign it for the App Store and upload it to App
# Store Connect (TestFlight). The Apple release workflow runs this; it also runs
# on any Mac.
#
#   ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_P8=… [VERSION=3.1.0] apps/apple/release.sh ios|macos
#
# ASC_*    an App Store Connect API key (role App Manager or Admin): Xcode uses
#          it to fetch the signing certificate and profile (cloud-managed
#          signing, nothing kept on the runner) and to upload; asc-next.mjs uses
#          it to read what is already uploaded.
# VERSION  optional CFBundleShortVersionString; must be higher than every
#          version of this platform in App Store Connect. Without it, the patch
#          of the highest one goes up (asc-next.mjs). The build number is always
#          one above every build already uploaded, so each run ships a newer
#          version.
#
# Submitting the uploaded build for review stays a decision made in App Store Connect.
set -euo pipefail

: "${ASC_KEY_ID:?}" "${ASC_ISSUER_ID:?}" "${ASC_KEY_P8:?}"
case "${1:-}" in
  ios) scheme="HQChat iOS" destination="generic/platform=iOS" asc_platform=IOS arch=() ;;
  # libhqc_wrap.dylib is built for arm64 only (native/hqc/build-apple.sh).
  macos) scheme="HQChat" destination="generic/platform=macOS" asc_platform=MAC_OS arch=(ARCHS=arm64) ;;
  *)
    echo "usage: $0 ios|macos" >&2
    exit 2
    ;;
esac
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

key="$work/AuthKey_$ASC_KEY_ID.p8"
(
  umask 077
  printf '%s\n' "$ASC_KEY_P8" >"$key"
)
auth=(-allowProvisioningUpdates -authenticationKeyPath "$key"
  -authenticationKeyID "$ASC_KEY_ID" -authenticationKeyIssuerID "$ASC_ISSUER_ID")
project="$here/HQChat.xcodeproj"

xcodebuild -version
bash "$root/native/hqc/build-apple.sh"

settings="$(xcodebuild -project "$project" -scheme "$scheme" -configuration Release -showBuildSettings 2>/dev/null)"
setting() { awk -F' = ' -v k="$1" '$1 ~ "^ *"k"$" {print $2; exit}' <<<"$settings"; }
team="$(setting DEVELOPMENT_TEAM)"
bundle_id="$(setting PRODUCT_BUNDLE_IDENTIFIER)"
[[ -n "$team" && -n "$bundle_id" ]] || {
  echo "no DEVELOPMENT_TEAM or PRODUCT_BUNDLE_IDENTIFIER in $scheme" >&2
  exit 1
}

read -r version build < <(node "$here/asc-next.mjs" "$bundle_id" "$asc_platform" \
  "$(setting MARKETING_VERSION)" "$(setting CURRENT_PROJECT_VERSION)" "${VERSION:-}")
[[ -n "$version" && -n "$build" ]] || {
  echo "could not work out the next version from App Store Connect" >&2
  exit 1
}

echo "archiving $scheme $version ($build), team $team"
xcodebuild archive -project "$project" -scheme "$scheme" -configuration Release \
  -destination "$destination" -archivePath "$work/HQChat.xcarchive" \
  "${auth[@]}" ${arch[@]+"${arch[@]}"} MARKETING_VERSION="$version" CURRENT_PROJECT_VERSION="$build" -quiet

cat >"$work/export.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>$team</string>
  <key>signingStyle</key><string>automatic</string>
  <key>uploadSymbols</key><true/>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
EOF

echo "signing for the App Store and uploading"
xcodebuild -exportArchive -archivePath "$work/HQChat.xcarchive" \
  -exportOptionsPlist "$work/export.plist" -exportPath "$work/export" "${auth[@]}"
echo "uploaded $scheme $version ($build); it appears in App Store Connect → TestFlight once processed"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo "Uploaded **$scheme $version ($build)** to App Store Connect." >>"$GITHUB_STEP_SUMMARY"
fi
