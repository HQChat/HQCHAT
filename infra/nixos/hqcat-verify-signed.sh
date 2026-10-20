#!/usr/bin/env bash
# Checks a statement signed by the release pipeline (infra/scripts/lib.sh
# `sign`): an Ed25519 signature by the environment's Nix cache key, the key
# the hosts already pin as .cache.publicKey. The hosts run it as
# hqcat-verify-signed (modules/host-agent.nix, modules/secrets.nix) on their
# channel pointer and secret bundles; the release scripts run it on what they
# read back.
#
#   hqcat-verify-signed <public key, name:base64> <statement> <signature, base64>
#
# Exits 0 only for a valid signature over exactly that statement. Every
# statement starts with its own hqcat-<kind>/<version> word, so none can be
# read as another, nor as a store path signature (which starts with "1;").
set -euo pipefail

[[ $# == 3 ]] || {
  echo "usage: hqcat-verify-signed <public key> <statement> <signature>" >&2
  exit 2
}
public="${1#*:}" statement="$2" signature="$3"
[[ "$statement" =~ ^hqcat-[a-z]+/[0-9]+\  ]] || {
  echo "not a signed hqcat statement" >&2
  exit 1
}
[[ "$public" =~ ^[A-Za-z0-9+/]{43}=$ && "$signature" =~ ^[A-Za-z0-9+/]{86}==$ ]] || {
  echo "malformed key or signature" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# The raw 32-byte key as an X.509 SubjectPublicKeyInfo (RFC 8410), which openssl reads.
{
  printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
  printf '%s' "$public" | base64 -d
} >"$tmp/public.der"
printf '%s' "$signature" | base64 -d >"$tmp/signature"
printf '%s' "$statement" >"$tmp/statement"
openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/public.der" -rawin \
  -in "$tmp/statement" -sigfile "$tmp/signature" >/dev/null 2>&1 || {
  echo "bad signature" >&2
  exit 1
}
