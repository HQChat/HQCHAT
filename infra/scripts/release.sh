#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Moves an environment's channels, which its hosts follow within two minutes
# (infra/nixos/hqcat-host-agent.sh).
#
#   infra/scripts/release.sh <environment> promote <app closure> <mqtt closure>
#   infra/scripts/release.sh <environment> rollback
#
# promote keeps the pointer it replaces as channels/<environment>/<role>.previous;
# rollback puts that back.
set -euo pipefail

ENVIRONMENT="${1:?usage: release.sh <environment> promote <app> <mqtt> | rollback}"
action="${2:?usage: release.sh <environment> promote <app> <mqtt> | rollback}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
channels="s3://$(env_get "$ENVIRONMENT" .cache.bucket)/channels/$ENVIRONMENT"

read_pointer() { r2 cp "$channels/$1" - 2>/dev/null || true; }
write_pointer() { printf '%s' "$2" | r2 cp - "$channels/$1" --content-type text/plain --cache-control "no-cache, max-age=0"; }

case "$action" in
  promote)
    declare -A target=([app]="${3:?app closure}" [mqtt]="${4:?mqtt closure}")
    for role in app mqtt; do
      current="$(read_pointer "$role")"
      if [[ -n "$current" && "$current" != "${target[$role]}" ]]; then write_pointer "$role.previous" "$current"; fi
      write_pointer "$role" "${target[$role]}"
      echo "$role → ${target[$role]}"
    done
    ;;
  rollback)
    for role in app mqtt; do
      previous="$(read_pointer "$role.previous")"
      if [[ -z "$previous" ]]; then
        echo "$role: no previous release to return to"
        continue
      fi
      write_pointer "$role" "$previous"
      echo "$role ← $previous"
    done
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
