#!/usr/bin/env bash
# The single entry point for every check, locally and in CI.
#
#   scripts/check.sh lint              static analysis of every language
#   scripts/check.sh unit              fast tests, no I/O
#   scripts/check.sh integration      server against real Postgres + EMQX (DATABASE_URL, TEST_EMQX_*)
#   scripts/check.sh scenarios        end-to-end user scenarios on a full local stack
#   scripts/check.sh infra             Terraform policy tests and NixOS evaluation
#   scripts/check.sh core              the Rust core: format, lints, tests, the Node addon
#
# Run inside `nix develop` so every tool is the pinned one.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
services="$root/services"
server="$services/server"
site="$root/apps/site"
tf_modules=(terraform)

failures=()
run() {
  local name="$1"
  shift
  printf '\n\033[1m── %s\033[0m\n' "$name"
  if "$@"; then
    echo "ok: $name"
  else
    echo "FAILED: $name"
    failures+=("$name")
  fi
}

finish() {
  if ((${#failures[@]} == 0)); then
    echo -e "\nall checks passed"
    return 0
  fi
  echo -e "\nfailed: ${failures[*]}"
  return 1
}

lint() {
  local shell_files
  mapfile -t shell_files < <(git -C "$root" ls-files '*.sh')

  for w in common server bot; do
    run "typescript $w" bash -c "cd '$services/$w' && npx tsc --noEmit"
  done
  run "biome" biome check "$services/common" "$server" "$services/bot" "$site/src" "$site/test"
  run "shellcheck" bash -c "cd '$root' && shellcheck -S warning -x ${shell_files[*]}"
  run "shfmt" bash -c "cd '$root' && shfmt -d -i 2 -ci ${shell_files[*]}"
  run "actionlint" bash -c "cd '$root' && actionlint"
  run "terraform fmt" terraform -chdir="$root/infra" fmt -check -recursive
  for m in "${tf_modules[@]}"; do
    run "tflint $m" bash -c "cd '$root/infra/$m' && tflint --init >/dev/null && tflint"
  done
  run "nixfmt" bash -c "cd '$root' && git ls-files '*.nix' | xargs nixfmt --check"
  run "statix" statix check "$root"
  run "deadnix" deadnix --fail "$root"
  run "names" "$root/scripts/lint-text.sh" names
  run "comments" "$root/scripts/lint-text.sh" comments
  finish
}

# The core's Node addon the server loads, built by Nix when HQCHAT_NODE is unset.
core_addon() {
  [[ -n "${HQCHAT_NODE:-}" ]] && return 0
  HQCHAT_NODE="$(nix build "$root#hqchat-node" --no-link --print-out-paths)/lib/hqchat_node.node"
  export HQCHAT_NODE
}

unit() {
  core_addon
  run "common unit" bash -c "cd '$services/common' && npm run --silent test:unit"
  run "server unit" bash -c "cd '$server' && npm run --silent test:unit"
  run "bot unit" bash -c "cd '$services/bot' && npm run --silent test:unit"
  run "envelope fuzz" bash -c "cd '$server' && npx tsx test/fuzz/envelope-v3-invariants.ts --iterations 200000 --seed ${FUZZ_SEED:-1}"
  run "http body fuzz" bash -c "cd '$server' && npx tsx test/fuzz/http-body.ts --iterations 400 --seed ${FUZZ_SEED:-1}"
  run "site" bash -c "cd '$site' && node --test test/*.test.mjs"
  run "ios versions" node --test "$root/apps/apple/asc-next.test.mjs"
  finish
}

integration() {
  core_addon
  : "${DATABASE_URL:?integration needs DATABASE_URL}"
  run "migrate" bash -c "cd '$server' && npm run --silent migrate"
  run "server integration" bash -c "cd '$server' && npm run --silent test:integration"
  finish
}

scenarios() {
  core_addon
  run "scenarios" bash "$server/test/scenarios/run-local.sh"
  finish
}

infra() {
  for m in "${tf_modules[@]}"; do
    run "terraform $m" bash -c "cd '$root/infra/$m' && terraform init -input=false -backend=false >/dev/null && terraform validate && terraform test"
  done
  run "nixos eval" bash -c "cd '$root' && nix eval --json .#packages.x86_64-linux --apply 'ps: builtins.mapAttrs (_: p: p.drvPath) ps' >/dev/null"
  finish
}

# The Rust core (core/): every crate's tests, including the shared vectors,
# and the Node addon against them and the TS hqn/1 initiator. Needs
# HQC_SOURCE and the toolchain from `nix develop`, and the server's
# node_modules for the addon tests.
core() {
  local test_lints
  test_lints=$(printf -- '-A clippy::%s ' unwrap_used expect_used panic indexing_slicing string_slice \
    arithmetic_side_effects as_conversions cast_possible_truncation cast_possible_wrap cast_sign_loss \
    print_stdout print_stderr)
  run "rustfmt" bash -c "cd '$root/core' && cargo fmt --check"
  # Library code meets every lint in core/Cargo.toml. Tests may also unwrap,
  # index, cast and do plain arithmetic: a panic there is a failed test.
  run "clippy" bash -c "cd '$root/core' && cargo clippy --workspace --lib --bins --locked -- -D warnings"
  run "clippy tests" bash -c "cd '$root/core' && cargo clippy --workspace --tests --locked -- -D warnings $test_lints"
  run "cargo deny" bash -c "cd '$root/core' && cargo deny --locked check"
  run "core tests" bash -c "cd '$root/core' && cargo test --locked"
  run "node addon" bash -c "'$root/core/hqchat-node/build.sh' && cd '$server' && node --import tsx --test ../../core/hqchat-node/test/*.test.ts"
  # Rust against TypeScript on mutated frames: same verdicts, same bytes.
  run "verdict build" bash -c "cd '$root/core' && cargo build --locked --release -p hqchat-verdict"
  local seed="${FUZZ_SEED:-1}" fuzz="npx tsx test/fuzz"
  run "differential envelope" bash -c "cd '$server' && $fuzz/envelope-v3-differential.ts --iterations 50000 --seed $seed"
  run "differential encode" bash -c "cd '$server' && $fuzz/envelope-v3-encode-differential.ts --iterations 50000 --seed $seed"
  for mode in decode encode round; do
    run "differential handshake $mode" bash -c "cd '$server' && $fuzz/handshake-differential.ts --mode $mode --iterations 10000 --seed $seed"
  done
  for mode in frames msg2; do
    run "differential noise $mode" bash -c "cd '$server' && $fuzz/noise-differential.ts --mode $mode --iterations 10000 --seed $seed"
  done
  finish
}

cmd="${1:?usage: scripts/check.sh lint|unit|integration|scenarios|infra|core}"
shift
case "$cmd" in
  lint) lint "$@" ;;
  unit) unit ;;
  integration) integration ;;
  scenarios) scenarios ;;
  infra) infra ;;
  core) core ;;
  *)
    echo "unknown check: $cmd" >&2
    exit 2
    ;;
esac
