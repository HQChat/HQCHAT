# shellcheck shell=bash
# Body of hqcat-netconf (modules/netconf.nix).
set -euo pipefail

md=""
for _ in $(seq 1 90); do
  md="$(curl -fsS --max-time 2 http://169.254.169.254/metadata/v1.json)" && break
  sleep 1
done
[[ -n "$md" ]] || {
  echo "the metadata service did not answer"
  exit 1
}

get() { jq -r "$1 // empty" <<<"$md"; }

prefix() {
  local IFS=. n=0 o
  for o in $1; do
    while ((o)); do
      n=$((n + (o & 1)))
      o=$((o >> 1))
    done
  done
  echo "$n"
}

network() {
  local file="$1" mac="$2"
  shift 2
  {
    printf '[Match]\nMACAddress=%s\n\n[Network]\nLinkLocalAddressing=ipv4\n' "$mac"
    printf '%s\n' "$@"
    printf '\n[Link]\nRequiredForOnline=routable\n'
  } >"/run/systemd/network/$file"
}

# Every value from the metadata goes into a networkd file or host.env, which
# overrides the units' Environment=: a newline in one would add a line of its
# own. Each is checked against what it can be first, and anything else stops
# the configuration.
require() {
  local kind="$1" value="$2" re
  case "$kind" in
    ipv4) re='^([0-9]{1,3}\.){3}[0-9]{1,3}$' ;;
    optional-ipv4)
      [[ -z "$value" ]] && return 0
      re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
      ;;
    mac) re='^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$' ;;
    role) re='^(app|mqtt|sim|base)$' ;;
    *) re='^$' ;;
  esac
  if [[ ! "$value" =~ $re ]]; then
    echo "refusing metadata: $kind ${value@Q}" >&2
    exit 1
  fi
}

mkdir -p /run/systemd/network /run/hqcat

public_ip="$(get '.interfaces.public[0].ipv4.ip_address')"
public_mask="$(get '.interfaces.public[0].ipv4.netmask')"
gateway="$(get '.interfaces.public[0].ipv4.gateway')"
public_mac="$(get '.interfaces.public[0].mac')"
anchor_ip="$(get '.interfaces.public[0].anchor_ipv4.ip_address')"
anchor_mask="$(get '.interfaces.public[0].anchor_ipv4.netmask')"
vpc_ip="$(get '.interfaces.private[0].ipv4.ip_address')"
vpc_mask="$(get '.interfaces.private[0].ipv4.netmask')"
vpc_mac="$(get '.interfaces.private[0].mac')"
nameservers="$(get '.dns.nameservers | join(" ")')"
for v in "$public_ip" "$public_mask" "$gateway"; do require ipv4 "$v"; done
require mac "$public_mac"
require optional-ipv4 "$anchor_ip"
require optional-ipv4 "$vpc_ip"
[[ -z "$anchor_ip" ]] || require ipv4 "$anchor_mask"
if [[ -n "$vpc_ip" ]]; then
  require ipv4 "$vpc_mask"
  require mac "$vpc_mac"
fi
for ns in $nameservers; do require ipv4 "$ns"; done

public=("Address=$public_ip/$(prefix "$public_mask")" "Gateway=$gateway")
[[ -z "$anchor_ip" ]] || public+=("Address=$anchor_ip/$(prefix "$anchor_mask")")
for ns in $nameservers; do public+=("DNS=$ns"); done
network 10-public.network "$public_mac" "${public[@]}"

if [[ -n "$vpc_ip" ]]; then
  network 20-private.network "$vpc_mac" "Address=$vpc_ip/$(prefix "$vpc_mask")"
fi

networkctl reload
for _ in $(seq 1 30); do
  ip route get 1.1.1.1 >/dev/null 2>&1 && break
  sleep 1
done

user_data="$(get '.user_data')"
[[ -n "$user_data" ]] || user_data='{}'
role="$(jq -r '.role // "base"' <<<"$user_data")"
require role "$role"
printf 'ROLE=%s\nPUBLIC_IPV4=%s\nANCHOR_IPV4=%s\nVPC_IPV4=%s\n' \
  "$role" "$public_ip" "$anchor_ip" "$vpc_ip" >/run/hqcat/host.env

host_key="$(jq -r '.hostKey // empty' <<<"$user_data")"
if [[ -n "$host_key" ]]; then
  umask 077
  printf '%s\n' "$host_key" >/run/hqcat/host_key
  if ! cmp -s /run/hqcat/host_key /etc/ssh/ssh_host_ed25519_key; then
    install -D -m 0600 /run/hqcat/host_key /etc/ssh/ssh_host_ed25519_key
    ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key >/etc/ssh/ssh_host_ed25519_key.pub
  fi
  rm -f /run/hqcat/host_key
fi

# The age post-quantum identity the host's secret bundle is sealed to
# (modules/secrets.nix). A droplet created before Terraform handed one over
# has none in its user data and keeps the one installed by hand.
age_identity="$(jq -r '.ageIdentity // empty' <<<"$user_data")"
if [[ -n "$age_identity" ]]; then
  umask 077
  mkdir -p /etc/hqcat
  printf '%s\n' "$age_identity" >/etc/hqcat/age-identity.new
  if cmp -s /etc/hqcat/age-identity.new /etc/hqcat/age-identity; then
    rm -f /etc/hqcat/age-identity.new
  else
    mv -f /etc/hqcat/age-identity.new /etc/hqcat/age-identity
  fi
fi
echo "configured as $role: public $public_ip, anchor ${anchor_ip:-none}, vpc ${vpc_ip:-none}"
