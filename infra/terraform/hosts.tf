# The two droplets. They boot the environment's base image and read their role
# and SSH host key from user data (infra/nixos/hqcat-netconf.sh), then switch to
# their role's closure. Image, user data and keys are creation-time inputs:
# changing them later must not replace a running droplet.
resource "digitalocean_droplet" "host" {
  for_each          = local.roles
  name              = "${local.name}-${each.key}"
  region            = local.env.region
  size              = local.env.sizes[each.key]
  image             = digitalocean_custom_image.base.id
  vpc_uuid          = digitalocean_vpc.this.id
  ssh_keys          = local.admin_fingerprints
  tags              = [digitalocean_tag.this["env"].name, digitalocean_tag.this[each.key].name]
  graceful_shutdown = true
  user_data = jsonencode({
    role    = each.key
    hostKey = tls_private_key.host[each.key].private_key_openssh
  })

  lifecycle {
    ignore_changes = [image, user_data, ssh_keys]
  }
}

# EMQX's data (sessions, retained presence), found by its label on the broker.
resource "digitalocean_volume" "emqx" {
  name                     = "${local.name}-emqx"
  region                   = local.env.region
  size                     = local.env.sizes.emqxVolumeGb
  initial_filesystem_type  = "ext4"
  initial_filesystem_label = "emqx-data"
  tags                     = [digitalocean_tag.this["env"].name]
}

resource "digitalocean_volume_attachment" "emqx" {
  droplet_id = digitalocean_droplet.host["mqtt"].id
  volume_id  = digitalocean_volume.emqx.id
}

# The hqn/1 gateway's public address: published in DNS, unlike the origin's.
resource "digitalocean_reserved_ip" "hqn" {
  region = local.env.region
}

# A droplet takes one action at a time: assigning the IP while the volume is
# being attached fails with "Droplet already has a pending event".
resource "digitalocean_reserved_ip_assignment" "hqn" {
  ip_address = digitalocean_reserved_ip.hqn.ip_address
  droplet_id = digitalocean_droplet.host["mqtt"].id
  depends_on = [digitalocean_volume_attachment.emqx]
}
