#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Builds each host's secret bundle, seals it with age to the host's
# post-quantum recipient (ML-KEM-768 + X25519, derived from AGE_IDENTITY_APP or
# AGE_IDENTITY_MQTT, an `age-keygen -pq` identity), and uploads it to
# <cache bucket>/secrets/<environment>/<role>.age with, beside it in
# <role>.age.sig, the statement
#
#   hqcat-secrets/1 <environment> <role> <release> <sha256 of the .age>
#
# and its signature by the cache key (lib.sh `sign`; needs
# NIX_CACHE_SIGNING_KEY). The host's hqcat-secrets-sync
# (infra/nixos/modules/secrets.nix) installs only a bundle that matches a
# signed statement no older than the last it installed. The bucket is public:
# without the signature anyone able to write to it could hand a host their own
# database URL, and a classical X25519 seal could be opened later by whoever
# records it now and has a quantum computer then.
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
  identity_var="AGE_IDENTITY_${role^^}"
  [[ "${!identity_var:-}" == AGE-SECRET-KEY-PQ-1* ]] || {
    echo "$identity_var is not set to an age post-quantum identity (age-keygen -pq): see docs/runbooks/deploy.md" >&2
    exit 1
  }
  recipient="$(age-keygen -y <<<"${!identity_var}")"
  [[ "$recipient" == age1pq1* ]] || {
    echo "$role: $identity_var does not give a post-quantum recipient" >&2
    exit 1
  }
  age -r "$recipient" -o "$tmp/$role.age" "$tmp/$role.json"
  statement="hqcat-secrets/1 $ENVIRONMENT $role $(date -u +%s) $(sha256sum "$tmp/$role.age" | cut -d' ' -f1)"
  signature="$(sign "$statement")"
  printf '%s\n%s\n' "$statement" "$signature" >"$tmp/$role.age.sig"
  for f in "$role.age" "$role.age.sig"; do
    r2 cp "$tmp/$f" "s3://$bucket/secrets/$ENVIRONMENT/$f" \
      --content-type application/octet-stream --cache-control "no-cache, max-age=0"
  done
  echo "$role: $(jq -r 'keys | join(", ")' "$tmp/$role.json")"
done
