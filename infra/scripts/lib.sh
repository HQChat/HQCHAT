# shellcheck shell=bash
# Shared by the deploy scripts: the environment file and R2 access.
#
#   env_json <environment>          path of infra/environments/<environment>.json
#   env_get <environment> <jq>      a field of it
#   r2 <aws s3 args...>             aws s3 against the environment's R2 endpoint
#                                   (needs ENVIRONMENT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY)

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

env_json() {
  local f="$root/infra/environments/$1.json"
  [[ -f "$f" ]] || {
    echo "no environment file $f" >&2
    return 1
  }
  printf '%s' "$f"
}

env_get() { jq -r "$2" "$(env_json "$1")"; }

r2() {
  # --only-show-errors exists on the transfer commands only; ls, mb and rb refuse it.
  local quiet=()
  case "$1" in cp | mv | rm | sync) quiet=(--only-show-errors) ;; esac
  AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID unset}" \
    AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY unset}" \
    AWS_DEFAULT_REGION=auto \
    aws s3 "$@" --endpoint-url "https://$(env_get "${ENVIRONMENT:?}" .cloudflare.accountId).r2.cloudflarestorage.com" ${quiet[@]+"${quiet[@]}"}
}
