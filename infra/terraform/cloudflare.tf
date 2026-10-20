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
  # Marked sensitive so a plan or apply log never shows the origin's address.
  content = sensitive(digitalocean_droplet.host["app"].ipv4_address)
  proxied = true
  ttl     = 1
  comment = "${local.name} origin"
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
    min_tls_version          = "1.3"
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

# Zone-wide records and rules belong to the environment that owns the zone
# settings, like the settings themselves.
locals {
  zone_owner = local.env.cloudflare.zoneSettings
  # The CAs Cloudflare's edge certificates come from; Cloudflare adds its own
  # CAA entries for them too. The origin certificate is Cloudflare's private
  # Origin CA and is not subject to CAA.
  caa_issuers = try(local.env.cloudflare.caaIssuers, ["letsencrypt.org", "pki.goog", "ssl.com"])
}

# DNSSEC for the zone; the DS record at the registrar is set by hand.
resource "cloudflare_zone_dnssec" "this" {
  count   = local.zone_owner ? 1 : 0
  zone_id = local.zone_id
}

# Only these CAs may issue for the zone: the apps trust any public CA for the
# API host, so a mis-issued certificate is otherwise accepted.
resource "cloudflare_record" "caa" {
  for_each = local.zone_owner ? toset(local.caa_issuers) : toset([])
  zone_id  = local.zone_id
  name     = "@"
  type     = "CAA"
  ttl      = 3600
  comment  = "${local.name} CAA"
  data {
    flags = 0
    tag   = "issue"
    value = each.value
  }
}

# Per-address limits at the edge for sign-in and the username lookup, on top
# of the origin's own. Rate-limiting rules depend on the Cloudflare plan, so
# an environment turns them on (cloudflare.rateLimit); the free plan allows
# one rule with a 10 s period and a 10 s block.
resource "cloudflare_ruleset" "rate_limit" {
  count   = local.zone_owner && try(local.env.cloudflare.rateLimit, false) ? 1 : 0
  zone_id = local.zone_id
  name    = "${local.name} rate limits"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    description = "sign-in and username lookup"
    expression  = "(starts_with(http.request.uri.path, \"/auth/\") or http.request.uri.path eq \"/users\")"
    action      = "block"
    enabled     = true
    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 10
      requests_per_period = 50
      mitigation_timeout  = 10
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
