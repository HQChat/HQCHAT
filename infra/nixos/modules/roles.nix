# Everything a host is, independent of the machine it runs on. The NixOS stack
# test imports this file alone; modules/default.nix adds the DigitalOcean platform.
{ lib, ... }:
{
  imports = [
    ./options.nix
    ./hardening.nix
    ./firewall.nix
    ./wireguard.nix
    ./host-agent.nix
    ./health.nix
    ./secrets.nix
    ./mqtt.nix
    ./app.nix
    ./nginx.nix
  ];

  time.timeZone = lib.mkDefault "UTC";
  i18n.defaultLocale = "en_US.UTF-8";
  environment.defaultPackages = lib.mkForce [ ];
  documentation.nixos.enable = false;
}
