# shellcheck shell=bash
# Shared by the deploy scripts: the environment file and R2 access.
#
#   env_json <environment>          path of infra/environments/<environment>.json
#   env_get <environment> <jq>      a field of it
#   r2 <aws s3 args...>             aws s3 against the environment's R2 endpoint
#                                   (needs ENVIRONMENT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY)
#   sign <statement>                its Ed25519 signature, base64, by the Nix cache key
#                                   (needs ENVIRONMENT, NIX_CACHE_SIGNING_KEY)
#   verify_signed <statement> <sig> whether the environment's cache key signed it

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

# The hosts pin the cache's public key already (.cache.publicKey), so the same
# key signs what they fetch besides store paths: their channel pointer and
# secret bundles. A Nix secret key is name:base64(32-byte seed ‖ public key).
sign() {
  local key="${NIX_CACHE_SIGNING_KEY:?NIX_CACHE_SIGNING_KEY unset}" tmp public
  tmp="$(mktemp -d)"
  (
    umask 077
    printf '%s' "${key#*:}" | base64 -d >"$tmp/secret"
    public="${key%%:*}:$(tail -c 32 "$tmp/secret" | base64)"
    [[ "$public" == "$(env_get "${ENVIRONMENT:?}" .cache.publicKey)" ]] || {
      echo "NIX_CACHE_SIGNING_KEY is not the key of .cache.publicKey in $(env_json "$ENVIRONMENT")" >&2
      exit 1
    }
    # The seed as PKCS#8 (RFC 8410), which openssl reads.
    {
      printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
      head -c 32 "$tmp/secret"
    } >"$tmp/key.der"
    printf '%s' "$1" >"$tmp/statement"
    openssl pkeyutl -sign -keyform DER -inkey "$tmp/key.der" -rawin -in "$tmp/statement" | base64 | tr -d '\n'
  ) || {
    rm -rf "$tmp"
    return 1
  }
  rm -rf "$tmp"
}

verify_signed() {
  bash "$root/infra/nixos/hqcat-verify-signed.sh" "$(env_get "${ENVIRONMENT:?}" .cache.publicKey)" "$1" "$2" 2>/dev/null
}
