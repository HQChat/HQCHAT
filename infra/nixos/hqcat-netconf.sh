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

mkdir -p /run/systemd/network /run/hqcat

public_ip="$(get '.interfaces.public[0].ipv4.ip_address')"
anchor_ip="$(get '.interfaces.public[0].anchor_ipv4.ip_address')"
vpc_ip="$(get '.interfaces.private[0].ipv4.ip_address')"

public=("Address=$public_ip/$(prefix "$(get '.interfaces.public[0].ipv4.netmask')")"
"Gateway=$(get '.interfaces.public[0].ipv4.gateway')")
[[ -z "$anchor_ip" ]] || public+=("Address=$anchor_ip/$(prefix "$(get '.interfaces.public[0].anchor_ipv4.netmask')")")
for ns in $(get '.dns.nameservers | join(" ")'); do public+=("DNS=$ns"); done
network 10-public.network "$(get '.interfaces.public[0].mac')" "${public[@]}"

if [[ -n "$vpc_ip" ]]; then
  network 20-private.network "$(get '.interfaces.private[0].mac')" \
    "Address=$vpc_ip/$(prefix "$(get '.interfaces.private[0].ipv4.netmask')")"
fi

networkctl reload
for _ in $(seq 1 30); do
  ip route get 1.1.1.1 >/dev/null 2>&1 && break
  sleep 1
done

user_data="$(get '.user_data')"
[[ -n "$user_data" ]] || user_data='{}'
role="$(jq -r '.role // "base"' <<<"$user_data")"
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
echo "configured as $role: public $public_ip, anchor ${anchor_ip:-none}, vpc ${vpc_ip:-none}"
