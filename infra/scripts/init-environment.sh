#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# One-time setup of an environment before its first Deploy:
#
#   - creates the GitHub Environment <environment>;
#   - creates the R2 buckets for Terraform state and the Nix cache, and serves
#     the cache bucket on the host in `.cache.url`;
#   - generates and stores BOT_SEED, NOISE_KEYS, AGE_IDENTITY_APP and
#     AGE_IDENTITY_MQTT (each host's age post-quantum identity, which its
#     secret bundle is sealed to) and (if the repository has none)
#     NIX_CACHE_SIGNING_KEY, never overwriting an existing secret;
#   - stores DIGITALOCEAN_TOKEN, CLOUDFLARE_API_TOKEN, R2_ACCESS_KEY_ID and
#     R2_SECRET_ACCESS_KEY from the caller's environment.
#
#   DIGITALOCEAN_TOKEN=… CLOUDFLARE_API_TOKEN=… R2_ACCESS_KEY_ID=… R2_SECRET_ACCESS_KEY=… \
#     infra/scripts/init-environment.sh <environment>
#
# The Cloudflare token needs Zone (DNS, Zone Settings, Workers Routes, SSL and
# Certificates: Edit), Account (Workers Scripts, R2: Edit). Optional secrets
# set by hand afterwards: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, APNS_KEY_P8.
set -euo pipefail

ENVIRONMENT="${1:?usage: init-environment.sh <environment>}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
for tool in gh aws jq openssl nix curl age-keygen; do command -v "$tool" >/dev/null || {
  echo "$tool is required" >&2
  exit 1
}; done
: "${CLOUDFLARE_API_TOKEN:?}" "${R2_ACCESS_KEY_ID:?}" "${R2_SECRET_ACCESS_KEY:?}"

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
account="$(env_get "$ENVIRONMENT" .cloudflare.accountId)"
zone="$(env_get "$ENVIRONMENT" .cloudflare.zone)"
cache_bucket="$(env_get "$ENVIRONMENT" .cache.bucket)"
cache_host="$(env_get "$ENVIRONMENT" .cache.url | sed 's#^https://##; s#/.*##')"

cf() {
  curl -fsS -X "$1" "https://api.cloudflare.com/client/v4$2" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "Content-Type: application/json" "${@:3}"
}

echo "GitHub Environment $ENVIRONMENT"
gh api -X PUT "repos/$repo/environments/$ENVIRONMENT" >/dev/null

for bucket in "$(env_get "$ENVIRONMENT" .stateBucket)" "$cache_bucket"; do
  if r2 ls "s3://$bucket" >/dev/null 2>&1; then
    echo "bucket $bucket exists"
  else
    r2 mb "s3://$bucket"
    echo "bucket $bucket created"
  fi
done

zone_id="$(cf GET "/zones?name=$zone" | jq -r '.result[0].id')"
if cf GET "/accounts/$account/r2/buckets/$cache_bucket/domains/custom" | jq -e --arg d "$cache_host" '.result.domains[]? | select(.domain == $d)' >/dev/null; then
  echo "cache served on $cache_host"
else
  cf POST "/accounts/$account/r2/buckets/$cache_bucket/domains/custom" \
    -d "$(jq -cn --arg d "$cache_host" --arg z "$zone_id" '{domain: $d, zoneId: $z, enabled: true, minTLS: "1.2"}')" >/dev/null
  echo "cache now served on $cache_host"
fi

existing="$(
  gh secret list --env "$ENVIRONMENT" --json name -q '.[].name'
  gh secret list --json name -q '.[].name'
)"
set_secret() {
  if grep -qx "$1" <<<"$existing"; then
    echo "secret $1 exists"
  else
    printf '%s' "$2" | gh secret set "$1" --env "$ENVIRONMENT"
    echo "secret $1 set"
  fi
}

set_secret BOT_SEED "$(openssl rand -hex 32)"
set_secret NOISE_KEYS "$(jq -cn --arg x "$(openssl rand -hex 32)" --arg h "$(openssl rand -hex 32)" \
  '{keys: [{keyId: 1, x25519: $x, hqcSeed: $h}]}')"
for role in APP MQTT; do
  set_secret "AGE_IDENTITY_$role" "$(age-keygen -pq 2>/dev/null | grep '^AGE-SECRET-KEY-PQ-1')"
done
if ! grep -qx NIX_CACHE_SIGNING_KEY <<<"$existing"; then
  key="$(nix key generate-secret --key-name "hqchat-cache-$ENVIRONMENT")"
  set_secret NIX_CACHE_SIGNING_KEY "$key"
  echo "set .cache.publicKey in infra/environments/$ENVIRONMENT.json to: $(nix key convert-secret-to-public <<<"$key")"
fi
for name in DIGITALOCEAN_TOKEN CLOUDFLARE_API_TOKEN R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY; do
  [[ -z "${!name:-}" ]] || set_secret "$name" "${!name}"
done
echo "done: run the Deploy workflow with environment=$ENVIRONMENT"
