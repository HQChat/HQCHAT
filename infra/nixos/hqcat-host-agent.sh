# shellcheck shell=bash
# Body of the hqcat-host-agent writeShellApplication (modules/host-agent.nix).
#
# Syncs the host's secrets, then follows <CACHE_URL>/channels/<ENVIRONMENT>/<ROLE>:
# when it names a store path other than the running system, substitutes that
# signed closure, switches to it, and rolls back if the new generation's
# hqcat-health-check does not pass within HEALTH_TIMEOUT seconds. A release
# that failed here is skipped until the channel moves again.
set -euo pipefail

CACHE_URL="${CACHE_URL:?CACHE_URL unset}"
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

pointer="$(curl -fsS --max-time 30 "${CACHE_URL}/channels/${CHANNEL}")" || {
  log "cannot reach ${CACHE_URL}/channels/${CHANNEL}; leaving the host as-is"
  exit 0
}
target="$(printf '%s' "$pointer" | tr -d '[:space:]')"

case "$target" in
  /nix/store/*) ;;
  *)
    log "channel pointer is not a store path: ${target:0:120}"
    exit 1
    ;;
esac

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
