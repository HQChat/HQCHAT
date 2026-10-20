# The outer layer; each host's nftables (infra/nixos/modules/firewall.nix) is
# the inner one and says the same. Rules name droplets by tag, so they hold for
# whatever droplets the environment has.
#
#   app   80/443 from Cloudflare only; 22 from the environment's adminSshSources,
#         or from anywhere when it names none (rate-limited per source and
#         key-only on the host)
#   mqtt  443 (hqn/1) from anywhere; 22 from the app host only
#   both  WireGuard from each other

data "cloudflare_ip_ranges" "edge" {}

locals {
  cloudflare_ranges = concat(data.cloudflare_ip_ranges.edge.ipv4_cidr_blocks, data.cloudflare_ip_ranges.edge.ipv6_cidr_blocks)
  anywhere          = ["0.0.0.0/0", "::/0"]
  ssh_sources       = try(local.env.adminSshSources, local.anywhere)
}

resource "digitalocean_firewall" "app" {
  name = "${local.name}-app"
  tags = [digitalocean_tag.this["app"].name]

  dynamic "inbound_rule" {
    for_each = ["80", "443"]
    content {
      protocol         = "tcp"
      port_range       = inbound_rule.value
      source_addresses = local.cloudflare_ranges
    }
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = local.ssh_sources
  }
  inbound_rule {
    protocol    = "udp"
    port_range  = "51820"
    source_tags = [digitalocean_tag.this["mqtt"].name]
  }
  inbound_rule {
    protocol         = "icmp"
    source_addresses = local.anywhere
  }

  dynamic "outbound_rule" {
    for_each = ["tcp", "udp"]
    content {
      protocol              = outbound_rule.value
      port_range            = "1-65535"
      destination_addresses = local.anywhere
    }
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = local.anywhere
  }
}

resource "digitalocean_firewall" "mqtt" {
  name = "${local.name}-mqtt"
  tags = [digitalocean_tag.this["mqtt"].name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = local.anywhere
  }
  inbound_rule {
    protocol    = "tcp"
    port_range  = "22"
    source_tags = [digitalocean_tag.this["app"].name]
  }
  inbound_rule {
    protocol    = "udp"
    port_range  = "51820"
    source_tags = [digitalocean_tag.this["app"].name]
  }
  inbound_rule {
    protocol         = "icmp"
    source_addresses = local.anywhere
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "443"
    destination_addresses = local.anywhere
  }
  dynamic "outbound_rule" {
    for_each = ["tcp", "udp"]
    content {
      protocol              = outbound_rule.value
      port_range            = "53"
      destination_addresses = local.anywhere
    }
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "123"
    destination_addresses = local.anywhere
  }
  outbound_rule {
    protocol         = "udp"
    port_range       = "51820"
    destination_tags = [digitalocean_tag.this["app"].name]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = local.anywhere
  }
}
