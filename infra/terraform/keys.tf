# Credentials generated here and delivered to the hosts: each host's SSH host
# key (in user data), and in the secret bundles the WireGuard key pairs and
# preshared key and the EMQX admin-API secret shared by both hosts. A bundle is sealed to the
# host's age post-quantum identity instead (var.age_identities), which
# Terraform cannot generate.

resource "tls_private_key" "host" {
  for_each  = local.roles
  algorithm = "ED25519"
}

resource "wireguard_asymmetric_key" "host" {
  for_each = local.roles
}

# Mixed into the link's handshake on both ends, so the tunnel (authn hook
# bodies, the admin API and internal MQTT secrets) is not open to whoever
# later breaks X25519 alone.
resource "random_bytes" "wireguard_psk" {
  length = 32
}

resource "random_password" "emqx_api_secret" {
  length  = 48
  special = false
}

# The admin keys in infra/nixos/admin.nix, registered in the account so a new
# droplet carries them in its metadata. A key the account already has is
# reused; DigitalOcean refuses duplicates.
locals {
  admin_keys = [
    for m in regexall("\"(ssh-(?:ed25519|rsa) [A-Za-z0-9+/=]+)[^\"]*\"", file("${path.module}/../nixos/admin.nix")) : m[0]
  ]
  registered_keys = {
    for k in data.digitalocean_ssh_keys.all.ssh_keys :
    join(" ", slice(split(" ", trimspace(k.public_key)), 0, 2)) => k.fingerprint
  }
  admin_fingerprints = [
    for k in local.admin_keys :
    lookup(local.registered_keys, k, try(digitalocean_ssh_key.admin[k].fingerprint, null))
  ]
}

data "digitalocean_ssh_keys" "all" {}

resource "digitalocean_ssh_key" "admin" {
  for_each   = toset([for k in local.admin_keys : k if !contains(keys(local.registered_keys), k)])
  name       = "${local.name}-admin-${substr(sha256(each.value), 0, 8)}"
  public_key = each.value
}
