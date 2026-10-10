#!/usr/bin/env bash
# Refuses a Terraform plan that destroys state no pipeline can restore: a
# droplet's disk, EMQX's volume, the database, the published address. Any
# delete of those types (including the delete half of a replacement) fails
# unless ALLOW_REPLACE=true. Lists every planned change in $GITHUB_STEP_SUMMARY.
#
#   infra/scripts/tf-guard.sh <plan.json>
set -euo pipefail

plan="${1:?usage: tf-guard.sh <plan.json>}"
protected='["digitalocean_droplet","digitalocean_volume","digitalocean_database_cluster","digitalocean_database_db","digitalocean_reserved_ip"]'

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
