#!/usr/bin/env bash
# The single entry point for every check, locally and in CI.
#
#   scripts/check.sh lint              static analysis of every language
#   scripts/check.sh unit              fast tests, no I/O
#   scripts/check.sh integration      server against real Postgres + EMQX (DATABASE_URL, TEST_EMQX_*)
#   scripts/check.sh scenarios        end-to-end user scenarios on a full local stack
#   scripts/check.sh infra             Terraform policy tests and NixOS evaluation
#
# Run inside `nix develop` so every tool is the pinned one.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
server="$root/services/server"
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

  run "typescript" bash -c "cd '$server' && npx tsc --noEmit"
  run "biome" biome check "$server" "$site/src" "$site/test"
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

# The HQC library the server loads, built from the pinned source when HQC_LIB is unset.
hqc() {
  [[ -n "${HQC_LIB:-}" ]] && return 0
  local ext=so
  [[ "$(uname)" == Darwin ]] && ext=dylib
  HQC_LIB="$(nix build "$root#hqc" --no-link --print-out-paths)/lib/libhqc_wrap.$ext"
  export HQC_LIB
}

unit() {
  hqc
  run "server unit" bash -c "cd '$server' && npm run --silent test:unit"
  run "envelope fuzz" bash -c "cd '$server' && npx tsx test/fuzz/envelope-v3-invariants.ts --iterations 200000 --seed ${FUZZ_SEED:-1}"
  run "http body fuzz" bash -c "cd '$server' && npx tsx test/fuzz/http-body.ts --iterations 400 --seed ${FUZZ_SEED:-1}"
  run "site" bash -c "cd '$site' && node --test test/*.test.mjs"
  run "ios versions" node --test "$root/apps/apple/asc-next.test.mjs"
  finish
}

integration() {
  hqc
  : "${DATABASE_URL:?integration needs DATABASE_URL}"
  run "migrate" bash -c "cd '$server' && npm run --silent migrate"
  run "server integration" bash -c "cd '$server' && npm run --silent test:integration"
  finish
}

scenarios() {
  hqc
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

cmd="${1:?usage: scripts/check.sh lint|unit|integration|scenarios|infra}"
shift
case "$cmd" in
  lint) lint "$@" ;;
  unit) unit ;;
  integration) integration ;;
  scenarios) scenarios ;;
  infra) infra ;;
  *)
    echo "unknown check: $cmd" >&2
    exit 2
    ;;
esac
