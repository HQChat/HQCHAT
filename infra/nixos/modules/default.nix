# A DigitalOcean droplet: ./roles.nix (everything independent of the machine,
# which the stack test boots on its own) plus the platform.
{
  imports = [
    ./roles.nix
    ./hardware.nix
    ./netconf.nix
  ];
}
