# What an environment must never be, asserted against a mocked apply: no
# credentials, no network.
#
#   cd infra/terraform && terraform init -backend=false && terraform test

mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = {
      id = "00000000000000000000000000000000"
    }
  }
  mock_data "cloudflare_ip_ranges" {
    defaults = {
      ipv4_cidr_blocks = ["173.245.48.0/20"]
      ipv6_cidr_blocks = ["2400:cb00::/32"]
    }
  }
}

mock_provider "digitalocean" {
  mock_data "digitalocean_ssh_keys" {
    defaults = {
      ssh_keys = []
    }
  }
  mock_resource "digitalocean_droplet" {
    defaults = {
      id                   = "424242"
      ipv4_address         = "203.0.113.10"
      ipv4_address_private = "10.110.0.2"
    }
  }
  mock_resource "digitalocean_reserved_ip" {
    defaults = {
      ip_address = "198.51.100.20"
    }
  }
  mock_resource "digitalocean_database_connection_pool" {
    defaults = {
      private_uri = "postgresql://app:pw@private-db:25061/hqchat?sslmode=require"
    }
  }
  mock_resource "digitalocean_database_cluster" {
    defaults = {
      port = 25060
    }
  }
}

variables {
  image_url  = "https://cache.example.test/images/production/x.qcow2"
  image_name = "hqchat-production-x"
}

run "production" {
  command = apply

  variables {
    environment = "production"
    age_identities = {
      app  = "AGE-SECRET-KEY-PQ-1APPTEST"
      mqtt = "AGE-SECRET-KEY-PQ-1MQTTTEST"
    }
  }

  assert {
    condition = alltrue([
      for r in digitalocean_firewall.app.inbound_rule : toset(r.source_addresses) == toset(local.cloudflare_ranges)
      if contains(["80", "443"], coalesce(r.port_range, "-"))
    ])
    error_message = "The origin's 80/443 must admit Cloudflare and nothing else."
  }
  assert {
    condition = length([
      for r in digitalocean_firewall.mqtt.inbound_rule : r
      if contains(coalesce(r.source_addresses, []), "0.0.0.0/0") && r.protocol != "icmp"
    ]) == 1
    error_message = "Exactly one broker rule may admit the whole internet: hqn/1 on 443."
  }
  assert {
    condition = alltrue([
      for r in digitalocean_firewall.mqtt.inbound_rule :
      !contains(["1883", "1884", "8083", "18083", "4370", "5369", "8081"], coalesce(r.port_range, "-"))
    ])
    error_message = "EMQX's listeners, Erlang distribution and noise-gw's health port must never be published."
  }
  assert {
    condition = alltrue([
      for r in digitalocean_firewall.mqtt.inbound_rule : toset(r.source_tags) == toset(["hqchat-production-app"])
      if r.port_range == "22" || r.protocol == "udp"
    ])
    error_message = "SSH and WireGuard reach the broker from the app host only."
  }
  assert {
    condition     = [for r in digitalocean_database_firewall.pg.rule : "${r.type}:${r.value}"] == ["tag:hqchat-production-app"]
    error_message = "Only the app host may reach the database."
  }
  assert {
    condition     = alltrue([for r in cloudflare_record.origin : r.proxied])
    error_message = "Origin records must be proxied; the origin's address is never published."
  }
  assert {
    condition     = !cloudflare_record.hqn.proxied && cloudflare_record.hqn.content != digitalocean_droplet.host["app"].ipv4_address
    error_message = "The hqn/1 record is DNS-only and must not name the origin."
  }
  assert {
    condition     = cloudflare_zone_settings_override.this[0].settings[0].ssl == "strict" && cloudflare_zone_settings_override.this[0].settings[0].zero_rtt == "off"
    error_message = "TLS to the origin must be verified (strict), and 0-RTT stays off."
  }
  assert {
    condition     = alltrue([for k, _ in cloudflare_workers_route.site : !strcontains(k, "*")])
    error_message = "Worker routes are exact paths; a glob would route the API to the site."
  }
  assert {
    condition     = toset(cloudflare_origin_ca_certificate.origin.hostnames) == toset(["hqchat.app", "www.hqchat.app", "api.hqchat.app"])
    error_message = "The origin certificate must cover every proxied hostname, the apps' API host included."
  }
  assert {
    condition     = cloudflare_record.origin["api.hqchat.app"].name == "api" && cloudflare_record.origin["api.hqchat.app"].proxied
    error_message = "The API host the apps call (Deployment.swift serverHost) must resolve, proxied, to the origin."
  }
  assert {
    condition     = alltrue([for k, _ in cloudflare_workers_route.site : !startswith(k, "api.")])
    error_message = "No Worker route on the API host: the apps' requests must reach the server."
  }
  assert {
    condition     = alltrue([for role, d in digitalocean_droplet.host : jsondecode(d.user_data).role == role && length(d.ssh_keys) > 0])
    error_message = "Each droplet names its role in user data and carries the admin keys."
  }
  assert {
    condition     = alltrue([for role, d in digitalocean_droplet.host : startswith(jsondecode(d.user_data).ageIdentity, "AGE-SECRET-KEY-PQ-1${upper(role)}")])
    error_message = "Each droplet gets its own role's age identity, which its secret bundle is sealed to."
  }
  assert {
    condition     = tostring(digitalocean_reserved_ip_assignment.hqn.droplet_id) == digitalocean_droplet.host["mqtt"].id
    error_message = "The reserved IP belongs to the broker."
  }
}

run "rescue_leaves_the_zone_alone" {
  command = plan

  variables {
    environment = "rescue"
  }

  assert {
    condition     = length(cloudflare_zone_settings_override.this) == 0 && length(cloudflare_workers_script.site) == 0
    error_message = "Only the environment that owns the zone sets its zone-wide settings and deploys the site."
  }
  assert {
    condition     = keys(cloudflare_record.origin) == ["rescue.hqchat.app"]
    error_message = "The rescue origin publishes its own hostname only."
  }
}
