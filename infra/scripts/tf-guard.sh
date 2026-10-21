#!/usr/bin/env bash
# Refuses a Terraform plan that destroys what no pipeline can restore, or
# whose loss opens something or quietly breaks it:
#
#   state       droplets' disks, EMQX's volume, the database, the VPC, the
#               published address
#   exposure    the firewalls (a managed database without one accepts any
#               address), the zone settings (their delete reverts TLS to the
#               zone's earlier settings), the DNS records
#   keys        host, WireGuard and origin keys, the database users'
#               passwords: a new one reaches a running host only through a
#               bundle, or not at all
#
# Any delete of those types (including the delete half of a replacement) fails
# unless ALLOW_REPLACE=true. Lists every planned change in $GITHUB_STEP_SUMMARY.
#
#   infra/scripts/tf-guard.sh <plan.json>
set -euo pipefail

plan="${1:?usage: tf-guard.sh <plan.json>}"
protected='[
  "digitalocean_droplet", "digitalocean_volume", "digitalocean_database_cluster",
  "digitalocean_database_db", "digitalocean_reserved_ip", "digitalocean_vpc",
  "digitalocean_firewall", "digitalocean_database_firewall", "cloudflare_zone_settings_override",
  "cloudflare_record", "tls_private_key", "wireguard_asymmetric_key", "random_bytes",
  "digitalocean_database_user"
]'

changes="$(jq -c '[.resource_changes[]? | select(.change.actions != ["no-op"] and .change.actions != ["read"])
  | {address, type, actions: .change.actions}]' "$plan")"
blocked="$(jq -c --argjson p "$protected" '[.[] | select((.type as $t | $p | index($t)) and (.actions | index("delete")))]' <<<"$changes")"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "| change | resource |"
    echo "|---|---|"
    jq -r '.[] | "| \(.actions | join("→")) | `\(.address)` |"' <<<"$changes"
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi

n="$(jq length <<<"$blocked")"
if ((n > 0)); then
  jq -r '.[] | "  \(.actions | join("→")) \(.address)"' <<<"$blocked"
  if [[ "${ALLOW_REPLACE:-false}" == true ]]; then
    echo "ALLOW_REPLACE=true: applying $n destructive change(s) to protected resources"
    exit 0
  fi
  echo "::error::this plan destroys $n protected resource(s); rerun Deploy with allow_replace to accept that"
  exit 1
fi
echo "guard: $(jq length <<<"$changes") change(s), none destructive to protected resources"
