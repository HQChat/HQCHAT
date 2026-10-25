#!/usr/bin/env bash
# Starts a complete local stack (Postgres, EMQX with the deployment's config and
# ACL, the server, noise-gw, the helper bot) and runs the functional scenarios
# against it, then, on macOS, the Swift client (APPLE=0 skips it).
#
#   bash services/server/test/scenarios/run-local.sh        # LOAD=1 adds the load test, SIM=1 the sim node
#
# Needs Docker and the core's Node addon (built with Nix when HQCHAT_NODE is
# unset).
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$(cd ../.. && pwd)"

PG_PORT="${PG_PORT:-55432}"
MQTT_PORT="${MQTT_PORT:-58083}"
SERVER_PORT="${SERVER_PORT:-58080}"
MQTT_INTERNAL_PORT="${MQTT_INTERNAL_PORT:-51884}"
MQTT_TCP_PORT="${MQTT_TCP_PORT:-51883}"
EMQX_API_PORT="${EMQX_API_PORT:-58084}"
HQN_PORT="${HQN_PORT:-58443}"
HQN_HEALTH_PORT="${HQN_HEALTH_PORT:-58444}"
NAME_PG="hqchat-scenarios-pg"
NAME_MQ="hqchat-scenarios-emqx"
WORK="$(mktemp -d)"

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

if ! command -v setsid >/dev/null 2>&1; then
  setsid() { exec perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die "exec: $!"' -- "$@"; }
fi

cleanup() {
  step "Tearing down"
  for pid in "${SERVER_PID:-}" "${GW_PID:-}" "${BOT_PID:-}" "${SIM_PID:-}"; do
    [ -n "$pid" ] || continue
    kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
  docker rm -f "$NAME_PG" "$NAME_MQ" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() {
  local url="$1" log="$2"
  for _ in $(seq 1 30); do
    curl -fsS "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  cat "$log"
  return 1
}

command -v docker >/dev/null || {
  echo "docker is required" >&2
  exit 1
}

step "Core addon"
if [ -z "${HQCHAT_NODE:-}" ]; then
  HQCHAT_NODE="$(nix build "$ROOT#hqchat-node" --no-link --print-out-paths)/lib/hqchat_node.node"
fi
export HQCHAT_NODE

step "Postgres"
docker rm -f "$NAME_PG" >/dev/null 2>&1 || true
docker run -d --name "$NAME_PG" \
  -e POSTGRES_USER=hqcat -e POSTGRES_PASSWORD=hqcat -e POSTGRES_DB=hqcat \
  -p "${PG_PORT}:5432" postgres:17-alpine >/dev/null
until docker exec "$NAME_PG" pg_isready -U hqcat -d hqcat >/dev/null 2>&1; do sleep 1; done
export DATABASE_URL="postgresql://hqcat:hqcat@localhost:${PG_PORT}/hqcat"
npm run --silent migrate

export EMQX_API_URL="http://localhost:${EMQX_API_PORT}"
export EMQX_API_KEY="hqcat-svc"
export EMQX_API_SECRET="scenarios-api-secret"
export AUTH_INIT_IP_LIMIT="${AUTH_INIT_IP_LIMIT:-2000}"
export INVITES_PER_DAY=1000 REPORTS_PER_DAY=1000
BOT_SEED="$(openssl rand -hex 32)"
export BOT_SEED
BOT_ID="$(npm run --silent bot -- --print-id)"

step "Server"
setsid env PORT="$SERVER_PORT" BOT_ID="$BOT_ID" EMQX_INTERNAL_URL="mqtt://127.0.0.1:${MQTT_INTERNAL_PORT}" \
  HQN_ENABLED=1 HQN_PUBLIC_HOST=127.0.0.1 HQN_PUBLIC_PORT="$HQN_PORT" \
  HQN_GATEWAY_KEYS_URL="http://localhost:${HQN_HEALTH_PORT}/keys" \
  npm run server >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_for "http://localhost:${SERVER_PORT}/health" "$WORK/server.log"

step "EMQX (deployment config and ACL)"
sed -e "s|@WS_BIND@|0.0.0.0:8083|; s|@GW_BIND@|0.0.0.0:1883|; s|@INTERNAL_BIND@|0.0.0.0:1884|" \
  -e "s|@API_BIND@|0.0.0.0:18083|; s|@AUTH_URL@|http://host.docker.internal:${SERVER_PORT}|" \
  "$ROOT/infra/emqx/emqx.conf" >"$WORK/emqx.conf"
printf '%s:%s\n' "$EMQX_API_KEY" "$EMQX_API_SECRET" >"$WORK/api-bootstrap"
chmod 644 "$WORK/api-bootstrap" "$WORK/emqx.conf"
docker rm -f "$NAME_MQ" >/dev/null 2>&1 || true
docker run -d --name "$NAME_MQ" \
  --add-host "host.docker.internal:host-gateway" \
  -p "${MQTT_PORT}:8083" -p "${MQTT_TCP_PORT}:1883" -p "${MQTT_INTERNAL_PORT}:1884" -p "${EMQX_API_PORT}:18083" \
  -e EMQX_NODE__COOKIE="$(openssl rand -hex 16)" \
  -e EMQX_API_KEY__BOOTSTRAP_FILE=/opt/emqx/etc/api-bootstrap \
  -v "$WORK/api-bootstrap:/opt/emqx/etc/api-bootstrap:ro" \
  -v "$WORK/emqx.conf:/opt/emqx/etc/emqx.conf:ro" \
  -v "$ROOT/infra/emqx/acl.conf:/opt/emqx/etc/hqchat-acl.conf:ro" \
  emqx/emqx:5.8 >/dev/null
for _ in $(seq 1 40); do
  docker exec "$NAME_MQ" emqx ctl status >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$NAME_MQ" emqx ctl status >/dev/null || {
  docker logs "$NAME_MQ"
  exit 1
}
docker exec "$NAME_MQ" emqx ctl conf show authorization | grep -q 'type = file'
docker exec "$NAME_MQ" emqx ctl conf show mqtt | grep -q 'wildcard_subscription = false'
for _ in $(seq 1 30); do
  docker exec "$NAME_MQ" emqx ctl alarms list 2>/dev/null | grep -qiE "authn|resource" || break
  sleep 2
done

step "noise-gw"
printf '{"keys":[{"keyId":1,"x25519":"%s","hqcSeed":"%s"}]}\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" >"$WORK/noise_keys"
setsid env NOISE_KEYS_FILE="$WORK/noise_keys" NOISE_GW_PORT="$HQN_PORT" NOISE_GW_HEALTH_PORT="$HQN_HEALTH_PORT" \
  EMQX_TCP_HOST=127.0.0.1 EMQX_TCP_PORT="$MQTT_TCP_PORT" \
  npm run gateway >"$WORK/noise-gw.log" 2>&1 &
GW_PID=$!
wait_for "http://localhost:${HQN_HEALTH_PORT}/health" "$WORK/noise-gw.log"

export TEST_BASE_URL="http://localhost:${SERVER_PORT}"
export TEST_MQTT_URL="ws://localhost:${MQTT_PORT}/mqtt"
export TEST_BOT_USERNAME=helper
export SCENARIOS_REQUIRED=1

step "Helper bot"
setsid env BASE_URL="$TEST_BASE_URL" MQTT_URL="$TEST_MQTT_URL" BOT_STATE_DIR="$WORK/bot" \
  BOT_USERNAME=helper \
  npm run bot >"$WORK/bot.log" 2>&1 &
BOT_PID=$!
for _ in $(seq 1 45); do
  grep -q "connected to the broker" "$WORK/bot.log" && break
  sleep 1
done
grep -q "connected to the broker" "$WORK/bot.log" || {
  tail -n 20 "$WORK/bot.log"
  exit 1
}

step "Scenarios"
npm run --silent test:scenarios || {
  tail -n 40 "$WORK/server.log" "$WORK/bot.log"
  exit 1
}

if [ "${APPLE:-1}" != 0 ] && [ "$(uname)" = "Darwin" ] && command -v xcrun >/dev/null; then
  step "The app's store over hqn/1 and WSS"
  bash "$ROOT/apps/apple/e2e/hqn-live/run.sh"
fi

if [ -n "${LOAD:-}" ]; then
  step "Load"
  npm run --silent test:load
fi

if [ -n "${SIM:-}" ]; then
  windows="${SIM_WINDOWS:-1}"
  step "Sim node (three sims, $windows one-minute reports)"
  setsid env BASE_URL="$TEST_BASE_URL" MQTT_URL="$TEST_MQTT_URL" BOT_ID="$BOT_ID" \
    SIM_COUNT=3 SIM_REPORT_MS=60000 SIM_STATE_DIR="$WORK/sim" \
    npm run sim >"$WORK/sim.log" 2>&1 &
  SIM_PID=$!
  report() { docker exec "$NAME_PG" psql -U hqcat -d hqcat -tAc "$1"; }
  for _ in $(seq 1 $((60 * windows + 90))); do
    [ "$(report "SELECT count(*) FROM sim_reports WHERE sim = 'all'")" -ge "$windows" ] && break
    sleep 1
  done
  kill -- -"$SIM_PID" 2>/dev/null || true
  report "SELECT hour, sim, metrics->'counts', metrics->>'uptimePct' FROM sim_reports ORDER BY hour, sim"
  report "SELECT hour, metrics->'ms' FROM sim_reports WHERE sim = 'all' ORDER BY hour"
  [ "$(report "SELECT count(*) FROM sim_reports WHERE sim = 'all' AND (metrics->'counts'->>'connects')::int >= 3")" -ge 1 ] || {
    tail -n 40 "$WORK/sim.log"
    exit 1
  }
  [ "$(report "SELECT count(*) FROM sim_reports WHERE metrics->'counts' ? 'corrupted'")" -eq 0 ]
fi
