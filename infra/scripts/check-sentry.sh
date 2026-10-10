#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Warn, without failing, when a deployment would ship without Sentry.
#
#   infra/scripts/check-sentry.sh <environment>
#
# The server's DSN is `sentryDsn` in infra/environments/<environment>.json,
# embedded in the host units at build time; the app's is `sentryDSN` in
# apps/apple/HQChat/Deployment.swift, embedded in the bundle. Either one empty
# means crashes from that half go nowhere. In GitHub Actions each gap is a
# ::warning:: annotation and a line in the job summary; locally it is stderr.
# Exits 0 either way: an environment may run without reporting on purpose.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

environment="${1:?usage: check-sentry.sh <environment>}"
file="$(env_json "$environment")"
swift="$root/apps/apple/HQChat/Deployment.swift"

dsn_shape='^https://[0-9a-f]+@[^/]+/[0-9]+$'
gaps=()

server_dsn="$(jq -r '.sentryDsn // ""' "$file")"
if [[ -z "$server_dsn" ]]; then
  gaps+=("server: sentryDsn is empty in ${file#"$root"/}; server, gateway and bot crashes will not be reported")
elif [[ ! "$server_dsn" =~ $dsn_shape ]]; then
  gaps+=("server: sentryDsn in ${file#"$root"/} does not look like a Sentry DSN")
fi

app_dsn="$(sed -n 's/^[[:space:]]*static let sentryDSN *= *"\(.*\)".*/\1/p' "$swift")"
if [[ -z "$app_dsn" ]]; then
  gaps+=("app: sentryDSN is empty in apps/apple/HQChat/Deployment.swift; app crashes will not be reported")
elif [[ ! "$app_dsn" =~ $dsn_shape ]]; then
  gaps+=("app: sentryDSN in apps/apple/HQChat/Deployment.swift does not look like a Sentry DSN")
fi

if ((${#gaps[@]} == 0)); then
  echo "sentry: server and app DSNs are set"
  exit 0
fi

for gap in "${gaps[@]}"; do
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::warning title=Sentry not configured::$gap"
    echo "- ⚠️ Sentry: $gap" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
  else
    echo "warning: $gap" >&2
  fi
done
