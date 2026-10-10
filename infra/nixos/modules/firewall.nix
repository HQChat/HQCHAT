# nftables. The app host answers 80/443 to Cloudflare only, the broker host
# answers hqn/1 on 443, and the two talk over WireGuard inside the
# environment's VPC. SSH is rate-limited everywhere; everything else is
# dropped. Only root may reach the metadata service, whose user data holds the
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
          tcp dport 22 ct state new limit rate 6/minute burst 6 packets accept
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
    serviceConfig = {
      Type = "oneshot";
      PrivateTmp = true;
      ProtectHome = true;
      NoNewPrivileges = true;
    };
    path = with pkgs; [
      curl
      nftables
      gnused
    ];
    script = ''
      set -euo pipefail
      for v in 4 6; do
        list="$(curl -fsS --max-time 20 "https://www.cloudflare.com/ips-v$v")" || {
          echo "cloudflare ips-v$v unreachable; keeping the current set"
          continue
        }
        [ -n "$list" ] || continue
        {
          echo "flush set inet filter cloudflare_v$v"
          echo -n "add element inet filter cloudflare_v$v { "
          echo -n "$(echo "$list" | sed '/^$/d' | paste -sd, -)"
          echo " }"
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
