# Configures a droplet from DigitalOcean's metadata service, reached over IPv4
# link-local: static addressing for the public, anchor and VPC addresses, the
# role named in user data, the SSH host key Terraform generated for it, and the
# age identity its secret bundle is sealed to (/etc/hqcat/age-identity). Writes
# /run/hqcat/host.env (ROLE, PUBLIC_IPV4, ANCHOR_IPV4, VPC_IPV4).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  netconf = pkgs.writeShellApplication {
    name = "hqcat-netconf";
    runtimeInputs = with pkgs; [
      curl
      jq
      coreutils
      diffutils
      iproute2
      openssh
      systemd
    ];
    text = builtins.readFile ../hqcat-netconf.sh;
  };
in
{
  networking.useDHCP = false;
  networking.useNetworkd = true;

  systemd.network.networks."99-metadata" = {
    matchConfig.Type = "ether";
    networkConfig = {
      LinkLocalAddressing = "ipv4";
      DHCP = "no";
    };
    linkConfig.RequiredForOnline = "no";
  };

  systemd.services.hqcat-netconf = {
    description = "Configure this droplet from DigitalOcean's metadata service";
    after = [ "systemd-networkd.service" ];
    wants = [ "systemd-networkd.service" ];
    before = [
      "network-online.target"
      "sshd.service"
    ];
    wantedBy = [
      "multi-user.target"
      "network-online.target"
    ];
    restartIfChanged = false;
    # Metadata in, network files and keys out: it may write only those, and
    # needs CAP_NET_ADMIN for networkd to accept its reload.
    serviceConfig = config.hqcat.rootService // {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = lib.getExe netconf;
      ReadWritePaths = [
        "/run/systemd/network"
        "/run/hqcat"
        "/etc/ssh"
        "/etc/hqcat"
      ];
      CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
        "AF_NETLINK"
      ];
    };
  };

  systemd.tmpfiles.rules = [
    "d /run/systemd/network 0755 root root -"
    "d /run/hqcat 0755 root root -"
    "d /etc/hqcat 0700 root root -"
  ];

  systemd.services.sshd = {
    after = [ "hqcat-netconf.service" ];
    wants = [ "hqcat-netconf.service" ];
  };
}
