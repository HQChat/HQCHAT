# The private link between an app host and its broker: app = 10.200.0.1,
# mqtt = 10.200.0.2. Configured at runtime from the `wireguard` bundle entry,
# `{ privateKey, peerPublicKey, peerEndpoint, presharedKey }`, which the Deploy
# workflow builds from Terraform's keys and the peer's VPC address. The
# preshared key is mixed into every handshake when the bundle has one; both
# hosts get it in the same deploy. The sim node is not on the link.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  addr = {
    app = "10.200.0.1";
    mqtt = "10.200.0.2";
  };
  self = addr.${cfg.role} or null;
  peer = if cfg.role == "app" then addr.mqtt else addr.app;
  port = 51820;
in
{
  options.hqcat.wg.addresses = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    readOnly = true;
    default = addr;
    description = "WireGuard addresses of the app and mqtt hosts.";
  };

  config = lib.mkIf (self != null) {
    environment.systemPackages = [ pkgs.wireguard-tools ];
    # Loaded at boot: the link's unit may not load kernel modules.
    boot.kernelModules = [ "wireguard" ];
    boot.kernel.sysctl."net.ipv4.ip_nonlocal_bind" = 1;
    hqcat.secretConsumers = lib.mkBefore [ "hqcat-wireguard.service" ];

    systemd.services.hqcat-wireguard = {
      description = "WireGuard link to the ${if cfg.role == "app" then "broker" else "app"} host";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      path = with pkgs; [
        iproute2
        wireguard-tools
        jq
      ];
      serviceConfig = cfg.rootService // {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "hqcat-wireguard";
        RuntimeDirectoryMode = "0700";
        ExecStop = "${pkgs.iproute2}/bin/ip link del wg0";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
      };
      script = ''
        set -euo pipefail
        conf=${cfg.secretsDir}/wireguard
        ip link del wg0 2>/dev/null || true
        if [ ! -s "$conf" ]; then
          echo "no WireGuard configuration yet"
          exit 0
        fi
        umask 077
        jq -r .privateKey "$conf" > "$RUNTIME_DIRECTORY/key"
        psk=()
        if [ -n "$(jq -r '.presharedKey // empty' "$conf")" ]; then
          jq -r .presharedKey "$conf" > "$RUNTIME_DIRECTORY/psk"
          psk=(preshared-key "$RUNTIME_DIRECTORY/psk")
        fi
        ip link add wg0 type wireguard
        wg set wg0 listen-port ${toString port} private-key "$RUNTIME_DIRECTORY/key" \
          peer "$(jq -r .peerPublicKey "$conf")" allowed-ips ${peer}/32 "''${psk[@]}" \
          endpoint "$(jq -r .peerEndpoint "$conf"):${toString port}" persistent-keepalive 25
        ip address add ${toString self}/24 dev wg0
        ip link set wg0 up
      '';
    };
  };
}
