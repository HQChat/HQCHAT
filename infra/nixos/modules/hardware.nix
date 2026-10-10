# A DigitalOcean droplet booted from the image built by ./image.nix: BIOS GRUB
# on /dev/vda, root labelled `nixos`, grown to the droplet's disk on boot.
{ modulesPath, ... }:
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];

  boot.loader.grub = {
    enable = true;
    device = "/dev/vda";
  };
  boot.growPartition = true;
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_scsi"
    "virtio_blk"
    "virtio_net"
  ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
    autoResize = true;
  };

  zramSwap.enable = true;
}
