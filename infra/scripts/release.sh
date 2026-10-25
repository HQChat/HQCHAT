#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Moves an environment's channels, which its hosts follow within two minutes
# (infra/nixos/hqcat-host-agent.sh).
#
#   infra/scripts/release.sh <environment> promote <app closure> <mqtt closure> [<sim closure>]
#   infra/scripts/release.sh <environment> rollback <app closure> <mqtt closure> [<sim closure>]
#
# promote prints the closures it replaces (and, in a workflow, sets them as the
# step outputs app_previous, mqtt_previous and sim_previous); rollback moves
# the channels to the closures it is given, an empty one leaving that role
# where it is. The sim closure is given only for an environment with a sim
# node (.sizes.sim). Deploy
# hands rollback what its own promote replaced, never something read back from
# the bucket.
#
# What a host follows is channels/<environment>/<role>.signed: the statement
#
#   hqcat-channel/1 <environment> <role> <release> <store path>
#
# and on the next line its signature by the cache key (lib.sh `sign`; needs
# NIX_CACHE_SIGNING_KEY). <release> goes up with every move, a rollback
# included, and a host refuses one lower than the last it accepted, so an old
# signed pointer cannot be replayed to roll it back. The bare pointer,
# channels/<environment>/<role>, is written beside it for hosts whose agent
# predates the signed one, so that they update to it.
set -euo pipefail

usage="usage: release.sh <environment> promote|rollback <app closure> <mqtt closure> [<sim closure>]"
ENVIRONMENT="${1:?$usage}"
action="${2:?$usage}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
channels="s3://$(env_get "$ENVIRONMENT" .cache.bucket)/channels/$ENVIRONMENT"

read_object() { r2 cp "$channels/$1" - 2>/dev/null || true; }
put() { r2 cp - "$channels/$1" --content-type text/plain --cache-control "no-cache, max-age=0"; }

# "<release> <store path>" of a role's signed pointer, when its signature
# holds and it names this environment and role.
current() {
  local signed statement magic env role release path rest
  signed="$(read_object "$1.signed")"
  statement="$(sed -n 1p <<<"$signed")"
  verify_signed "$statement" "$(sed -n 2p <<<"$signed")" || return 0
  read -r magic env role release path rest <<<"$statement"
  [[ "$magic" == hqcat-channel/1 && "$env" == "$ENVIRONMENT" && "$role" == "$1" && -z "$rest" ]] || return 0
  [[ "$release" =~ ^[0-9]{1,15}$ ]] || return 0
  printf '%s %s' "$release" "$path"
}

write_pointer() {
  local role="$1" path="$2" release last statement signature
  [[ "$path" =~ ^/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._?=-]+$ ]] || {
    echo "$role: not a store path: $path" >&2
    return 1
  }
  read -r last _ <<<"$(current "$role")"
  release="$(date -u +%s)"
  ((release > 10#${last:-0})) || release=$((10#$last + 1))
  statement="hqcat-channel/1 $ENVIRONMENT $role $release $path"
  signature="$(sign "$statement")" || return 1
  printf '%s\n%s\n' "$statement" "$signature" | put "$role.signed"
  printf '%s' "$path" | put "$role"
}

declare -A target=([app]="${3-}" [mqtt]="${4-}" [sim]="${5-}")
roles=(app mqtt)
[[ "$(env_get "$ENVIRONMENT" '.sizes.sim // ""')" == "" ]] || roles+=(sim)
case "$action" in
  promote)
    for role in "${roles[@]}"; do
      [[ -n "${target[$role]}" ]] || {
        echo "$usage" >&2
        exit 2
      }
      read -r _ previous <<<"$(current "$role")"
      # An environment whose channel predates signing has only the bare pointer.
      [[ -n "$previous" ]] || previous="$(read_object "$role")"
      write_pointer "$role" "${target[$role]}"
      echo "$role → ${target[$role]} (was ${previous:-nothing})"
      if [[ -n "${GITHUB_OUTPUT:-}" && "$previous" != "${target[$role]}" ]]; then
        echo "${role}_previous=$previous" >>"$GITHUB_OUTPUT"
      fi
    done
    ;;
  rollback)
    for role in "${roles[@]}"; do
      if [[ -z "${target[$role]}" ]]; then
        echo "$role: no previous release to return to"
        continue
      fi
      write_pointer "$role" "${target[$role]}"
      echo "$role ← ${target[$role]}"
    done
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
