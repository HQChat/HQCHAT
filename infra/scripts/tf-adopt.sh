#!/usr/bin/env bash
# Imports into the state what a plan would create but already exists under the
# same identity, so an apply over a running account, or after one that failed
# half-way, converges instead of colliding:
#
#   cloudflare_workers_route   a route with the same pattern (any Worker's; the
#                              apply then points it at this environment's)
#   cloudflare_record          a record with the same name and type
#
# Only objects with a unique name are adopted. A reserved IP has none: an
# unassigned one may belong to a stack being torn down.
#
# Prints the number of imports; the caller plans again when it is not 0. Each
# import is listed in $GITHUB_STEP_SUMMARY. Run from the Terraform directory.
#
#   infra/scripts/tf-adopt.sh <plan.json>
set -euo pipefail

plan="${1:?usage: tf-adopt.sh <plan.json>}"
creates="$(jq -c '[.resource_changes[]? | select(.change.actions == ["create"])
  | select(.type | IN("cloudflare_workers_route", "cloudflare_record"))
  | {address, type, after: .change.after}]' "$plan")"
[[ "$(jq length <<<"$creates")" != 0 ]] || {
  echo 0
  exit 0
}

cf() { curl -fsS -H @<(printf 'Authorization: Bearer %s\n' "${CLOUDFLARE_API_TOKEN:?}") "https://api.cloudflare.com/client/v4$1"; }

imported=0
adopt() {
  local address="$1" id="$2" what="$3"
  echo "adopting $what as $address" >&2
  terraform import -input=false -lock-timeout=5m "$address" "$id" >&2
  imported=$((imported + 1))
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "- adopted existing $what as \`$address\`" >>"$GITHUB_STEP_SUMMARY"
  fi
}

while read -r c; do
  address="$(jq -r .address <<<"$c")"
  case "$(jq -r .type <<<"$c")" in
    cloudflare_workers_route)
      zone="$(jq -r .after.zone_id <<<"$c")"
      pattern="$(jq -r .after.pattern <<<"$c")"
      id="$(cf "/zones/$zone/workers/routes" | jq -r --arg p "$pattern" '[.result[] | select(.pattern == $p)][0].id // empty')"
      [[ -z "$id" ]] || adopt "$address" "$zone/$id" "route $pattern"
      ;;
    cloudflare_record)
      zone="$(jq -r .after.zone_id <<<"$c")"
      name="$(jq -r .after.name <<<"$c")"
      type="$(jq -r .after.type <<<"$c")"
      zone_name="$(cf "/zones/$zone" | jq -r .result.name)"
      fqdn="$zone_name"
      [[ "$name" == "@" || "$name" == "$zone_name" ]] || fqdn="${name%".$zone_name"}.$zone_name"
      ids="$(cf "/zones/$zone/dns_records?type=$type&name=$fqdn" | jq -r '[.result[].id] | join(" ")')"
      # Several records of one name and type (round robin) are left to a person.
      if [[ -n "$ids" && "$ids" != *" "* ]]; then adopt "$address" "$zone/$ids" "$type record $fqdn"; fi
      ;;
  esac
done < <(jq -c '.[]' <<<"$creates")

echo "$imported"
