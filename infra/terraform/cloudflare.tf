# DNS, the zone's TLS settings, the site Worker and the origin certificate.
# The origin is proxied; the hqn/1 gateway is DNS-only on its own reserved IP.

data "cloudflare_zone" "this" {
  name = local.env.cloudflare.zone
}

locals {
  zone_id = data.cloudflare_zone.this.id
  # The site's hostnames carry the Worker routes; the API host (the one the apps
  # call) reaches the same origin but never the Worker.
  site_hosts   = concat([local.env.domain], local.env.siteDomains)
  origin_hosts = concat(local.site_hosts, compact([try(local.env.apiHost, "")]))
  record       = { for h in local.origin_hosts : h => h == local.env.cloudflare.zone ? "@" : trimsuffix(h, ".${local.env.cloudflare.zone}") }
  worker_paths = ["/", "/crypto", "/privacy", "/terms", "/eula", "/support", "/donate", "/robots.txt", "/sitemap.xml"]
}

resource "cloudflare_record" "origin" {
  for_each = local.record
  zone_id  = local.zone_id
  name     = each.value
  type     = "A"
  content  = digitalocean_droplet.host["app"].ipv4_address
  proxied  = true
  ttl      = 1
  comment  = "${local.name} origin"
}

resource "cloudflare_record" "hqn" {
  zone_id = local.zone_id
  name    = trimsuffix(local.env.hqnHost, ".${local.env.cloudflare.zone}")
  type    = "A"
  content = digitalocean_reserved_ip.hqn.ip_address
  proxied = false
  ttl     = 300
  comment = "${local.name} hqn/1 gateway"
}

resource "cloudflare_zone_settings_override" "this" {
  count   = local.env.cloudflare.zoneSettings ? 1 : 0
  zone_id = local.zone_id
  settings {
    ssl                      = "strict"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    websockets               = "on"
    brotli                   = "on"
    http3                    = "on"
    zero_rtt                 = "off"
    security_level           = "medium"
    browser_check            = "on"
    security_header {
      enabled            = true
      max_age            = 31536000
      include_subdomains = true
      preload            = true
      nosniff            = true
    }
  }
}

# Exact paths only: the same host serves the API, and a glob would route it to the Worker.
resource "cloudflare_workers_script" "site" {
  count              = local.env.cloudflare.site ? 1 : 0
  account_id         = local.env.cloudflare.accountId
  name               = "hqchat-site"
  content            = file("${path.module}/../../apps/site/src/index.js")
  module             = true
  compatibility_date = "2025-01-01"
}

resource "cloudflare_workers_route" "site" {
  for_each = local.env.cloudflare.site ? {
    for pair in setproduct(local.site_hosts, local.worker_paths) : "${pair[0]}${pair[1]}" => pair
  } : {}
  zone_id     = local.zone_id
  pattern     = each.key
  script_name = cloudflare_workers_script.site[0].name
}

resource "tls_private_key" "origin" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "origin" {
  private_key_pem = tls_private_key.origin.private_key_pem
  subject {
    common_name = local.env.domain
  }
  dns_names = keys(local.record)
}

resource "cloudflare_origin_ca_certificate" "origin" {
  csr                = tls_cert_request.origin.cert_request_pem
  hostnames          = keys(local.record)
  request_type       = "origin-ecc"
  requested_validity = 5475
}
