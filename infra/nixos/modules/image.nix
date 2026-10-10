# The droplet image: this configuration as a compressed qcow2 disk that
# DigitalOcean imports as a custom image.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
{
  system.build.digitalOceanImage = import (modulesPath + "/../lib/make-disk-image.nix") {
    inherit config lib pkgs;
    name = "hqchat-${config.hqcat.environment.name}-image";
    format = "qcow2-compressed";
    partitionTableType = "legacy";
    diskSize = "auto";
    additionalSpace = "1024M";
  };
}
