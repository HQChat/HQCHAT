# nftables. The app host answers 80/443 to Cloudflare only, the broker host
# answers hqn/1 on 443, and the two talk over WireGuard inside the
# environment's VPC. SSH is rate-limited per source address, so a flood from
# (or spoofed as) other addresses cannot use up the admin's share; everything
# else is dropped. Only root may reach the metadata service, whose user data holds the
# host key. The Cloudflare sets start from cloudflare-ips.nix and refresh daily.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cf = import ./cloudflare-ips.nix;
  cfg = config.hqcat;
  inherit (cfg) role;
  wg = cfg.wg.addresses;
  perMinute = toString cfg.hqn.newConnectionsPerMinute;
  wgRules = lib.optionalString (role != "base") (
    ''
      ip saddr ${cfg.environment.vpcRange} udp dport 51820 accept
    ''
    + (
      if role == "app" then
        ''
          iifname "wg0" ip saddr ${wg.mqtt} tcp dport 8090 accept
        ''
      else
        ''
          iifname "wg0" ip saddr ${wg.app} tcp dport { 8083, 1884, 18083, 8081 } accept
        ''
    )
  );
  hqnRules = lib.optionalString (role == "mqtt") ''
    tcp dport 443 ct state new meter hqn_new { ip saddr limit rate ${perMinute}/minute burst ${perMinute} packets } accept
    tcp dport 443 ct state new drop
  '';
  cloudflareRules = lib.optionalString (role == "app") ''
    ip  saddr @cloudflare_v4 tcp dport { 80, 443 } accept
    ip6 saddr @cloudflare_v6 tcp dport { 80, 443 } accept
  '';
in
{
  networking.firewall.enable = false;
  networking.nftables = {
    enable = true;
    ruleset = ''
      table inet filter {
        set cloudflare_v4 {
          type ipv4_addr
          flags interval
          elements = { ${lib.concatStringsSep ", " cf.v4} }
        }
        set cloudflare_v6 {
          type ipv6_addr
          flags interval
          elements = { ${lib.concatStringsSep ", " cf.v6} }
        }

        chain input {
          type filter hook input priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop
          iif lo accept
          ip protocol icmp accept
          ip6 nexthdr ipv6-icmp accept
          tcp dport 22 ct state new meter ssh4_new { ip saddr limit rate 6/minute burst 6 packets } accept
          tcp dport 22 ct state new meter ssh6_new { ip6 saddr limit rate 6/minute burst 6 packets } accept
          ${cloudflareRules}
          ${wgRules}
          ${hqnRules}
        }

        chain forward {
          type filter hook forward priority filter; policy drop;
        }

        chain output {
          type filter hook output priority filter; policy accept;
          ip daddr 169.254.169.254 meta skuid != 0 reject
        }
      }
    '';
  };

  systemd.services.cloudflare-ips-refresh = {
    description = "Refresh the Cloudflare address sets in nftables";
    after = [
      "network-online.target"
      "nftables.service"
    ];
    wants = [ "network-online.target" ];
    serviceConfig = config.hqcat.rootService // {
      Type = "oneshot";
      CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
        "AF_NETLINK"
      ];
    };
    path = with pkgs; [
      curl
      nftables
      coreutils
    ];
    # The body is fetched over the network and goes to nft as root: only a
    # list made entirely of plain CIDRs, none wider than /8 and a plausible
    # number of them, replaces the current set.
    script = ''
      set -euo pipefail
      cidr() {
        local v="$1" addr="''${2%/*}" bits="''${2##*/}"
        [[ "$2" == */* && "$bits" =~ ^[0-9]{1,3}$ ]] || return 1
        if [[ "$v" == 4 ]]; then
          [[ "$addr" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]] &&
            ((10#$bits >= 8 && 10#$bits <= 32))
        else
          [[ "$addr" =~ ^[0-9a-fA-F:]{2,39}$ && "$addr" == *:* ]] && ((10#$bits >= 8 && 10#$bits <= 128))
        fi
      }
      for v in 4 6; do
        list="$(curl -fsS --max-time 20 "https://www.cloudflare.com/ips-v$v")" || {
          echo "cloudflare ips-v$v unreachable; keeping the current set"
          continue
        }
        ranges=()
        ok=1
        while IFS= read -r line; do
          line="$(tr -d '[:space:]' <<<"$line")"
          [[ -n "$line" ]] || continue
          cidr "$v" "$line" || { ok=0; break; }
          ranges+=("$line")
        done <<<"$list"
        if ((ok == 0 || ''${#ranges[@]} < 3 || ''${#ranges[@]} > 200)); then
          echo "cloudflare ips-v$v is not a plausible list of CIDRs (''${#ranges[@]} ranges); keeping the current set"
          continue
        fi
        {
          echo "flush set inet filter cloudflare_v$v"
          echo "add element inet filter cloudflare_v$v { $(IFS=,; echo "''${ranges[*]}") }"
        } | nft -f -
      done
    '';
  };

  systemd.timers.cloudflare-ips-refresh = {
    description = "Daily Cloudflare address-set refresh";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "5min";
      OnUnitActiveSec = "24h";
      RandomizedDelaySec = "30min";
      Persistent = true;
    };
  };
}
