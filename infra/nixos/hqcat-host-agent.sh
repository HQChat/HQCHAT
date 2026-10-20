# shellcheck shell=bash
# Body of the hqcat-host-agent writeShellApplication (modules/host-agent.nix).
#
# Syncs the host's secrets, then follows <CACHE_URL>/channels/<ENVIRONMENT>/<ROLE>.signed
# (infra/scripts/release.sh): a statement naming a store path and a release
# number, signed with the cache key (CACHE_PUBLIC_KEY). When it names a store
# path other than the running system, substitutes that signed closure,
# switches to it, and rolls back if the new generation's hqcat-health-check
# does not pass within HEALTH_TIMEOUT seconds. A release that failed here is
# skipped until the channel moves again. A pointer numbered below the last one
# accepted here is refused: whoever can write to the bucket cannot replay an
# older release to roll the host back.
set -euo pipefail

CACHE_URL="${CACHE_URL:?CACHE_URL unset}"
CACHE_PUBLIC_KEY="${CACHE_PUBLIC_KEY:?CACHE_PUBLIC_KEY unset}"
ENVIRONMENT="${ENVIRONMENT:?ENVIRONMENT unset}"
ROLE="${ROLE:?ROLE unset}"
CHANNEL="$ENVIRONMENT/$ROLE"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
STATE_DIR=/var/lib/hqcat-host
mkdir -p "$STATE_DIR"

log() { echo "[hqcat-host-agent] $*"; }

[[ "$ROLE" != base ]] || {
  log "no role in user data; nothing to follow"
  exit 0
}
systemctl start hqcat-secrets-sync.service || log "secrets sync failed; continuing with the installed secrets"

signed="$(curl -fsS --max-time 30 "${CACHE_URL}/channels/${CHANNEL}.signed")" || {
  log "cannot reach ${CACHE_URL}/channels/${CHANNEL}.signed; leaving the host as-is"
  exit 0
}
statement="$(sed -n 1p <<<"$signed")"
read -r magic env role release target rest <<<"$statement"
if [[ "$magic" != hqcat-channel/1 || "$env" != "$ENVIRONMENT" || "$role" != "$ROLE" || -n "$rest" ]] ||
  [[ ! "$release" =~ ^[0-9]{1,15}$ ]] ||
  [[ ! "$target" =~ ^/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._?=-]+$ ]]; then
  log "channel pointer is not a ${CHANNEL} statement: ${statement:0:160}"
  exit 1
fi
hqcat-verify-signed "$CACHE_PUBLIC_KEY" "$statement" "$(sed -n 2p <<<"$signed")" || {
  log "channel pointer is not signed by the cache key; leaving the host as-is"
  exit 1
}
accepted="$(cat "$STATE_DIR/release" 2>/dev/null || echo 0)"
[[ "$accepted" =~ ^[0-9]{1,15}$ ]] || accepted=0
if ((10#$release < 10#$accepted)); then
  log "refusing release $release ($(basename "$target")): release $accepted was accepted here already"
  exit 1
fi
printf '%s\n' "$release" >"$STATE_DIR/release"

current="$(readlink -f /run/current-system)"
if [[ "$target" == "$current" ]]; then
  log "up to date ($(basename "$target"))"
  exit 0
fi
if [[ -f "$STATE_DIR/refused" && "$(cat "$STATE_DIR/refused")" == "$target" ]]; then
  log "skipping $(basename "$target"): it failed its health check here"
  exit 0
fi
log "switching $(basename "$current") -> $(basename "$target")"

nix-store --realise "$target" --add-root "$STATE_DIR/next" >/dev/null
nix-env -p /nix/var/nix/profiles/system --set "$target"

rollback() {
  log "$1; rolling back to $(basename "$current")"
  printf '%s' "$target" >"$STATE_DIR/refused"
  nix-env -p /nix/var/nix/profiles/system --set "$current"
  "$current/bin/switch-to-configuration" switch || log "rollback activation failed: manual intervention required"
  exit 1
}

"$target/bin/switch-to-configuration" switch || rollback "activation failed"

check="$target/sw/bin/hqcat-health-check"
if [[ -x "$check" ]]; then
  deadline=$((SECONDS + HEALTH_TIMEOUT))
  until out="$("$check" 2>&1)"; do
    if ((SECONDS >= deadline)); then
      printf '%s\n' "$out" | sed 's/^/    /'
      rollback "unhealthy after ${HEALTH_TIMEOUT}s"
    fi
    sleep 5
  done
fi

rm -f "$STATE_DIR/refused"
printf '%s %s\n' "$(date -Is)" "$target" >>"$STATE_DIR/history"
log "switched to $(basename "$target")"
nix-collect-garbage --delete-older-than 30d >/dev/null 2>&1 || true
