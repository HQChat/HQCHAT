#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Builds each host's secret bundle, encrypts it with age to the host's SSH key
# and uploads it to <cache bucket>/secrets/<environment>/<role>.age, where the
# host's hqcat-secrets-sync (infra/nixos/modules/secrets.nix) fetches it.
#
#   infra/scripts/publish-secrets.sh <environment>
#
# A bundle is a JSON object, file name → content: Terraform's entries (from
# $TF_OUTPUTS) plus these variables when set: BOT_SEED, BOT_ID,
# STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, APNS_KEY_P8 (app) and NOISE_KEYS
# (mqtt). An entry left out is left unchanged on the host.
set -euo pipefail

ENVIRONMENT="${1:?usage: publish-secrets.sh <environment>}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
outputs="${TF_OUTPUTS:-/tmp/tf-outputs.json}"
bucket="$(env_get "$ENVIRONMENT" .cache.bucket)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
umask 077

extra() {
  local json='{}' name var
  for name in "$@"; do
    var="${name^^}"
    [[ -n "${!var:-}" ]] || continue
    json="$(jq -c --arg k "$name" --arg v "${!var}" '. + {($k): $v}' <<<"$json")"
  done
  printf '%s' "$json"
}

for role in app mqtt; do
  case "$role" in
    app) added="$(extra bot_seed bot_id stripe_secret_key stripe_webhook_secret apns_key_p8)" ;;
    mqtt) added="$(extra noise_keys)" ;;
  esac
  jq -c --arg r "$role" --argjson add "$added" '.bundle.value[$r] + $add' "$outputs" >"$tmp/$role.json"
  recipient="$(jq -r --arg r "$role" '.hosts.value[$r].host_key' "$outputs")"
  age -r "$recipient" -o "$tmp/$role.age" "$tmp/$role.json"
  r2 cp "$tmp/$role.age" "s3://$bucket/secrets/$ENVIRONMENT/$role.age" \
    --content-type application/octet-stream --cache-control "no-cache, max-age=0"
  echo "$role: $(jq -r 'keys | join(", ")' "$tmp/$role.json")"
done
