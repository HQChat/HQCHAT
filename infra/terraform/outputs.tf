output "domain" {
  description = "The environment's public hostname."
  value       = local.env.domain
}

output "api_host" {
  description = "The hostname the apps call, or the domain when the environment names none."
  value       = try(local.env.apiHost, local.env.domain)
}

# Sensitive: the app host's public address is the origin, which is never
# published (every name for it is proxied by Cloudflare), and an apply prints
# every non-sensitive output to the public Actions log.
output "hosts" {
  description = "role → droplet id, public and VPC addresses, and SSH host public key."
  sensitive   = true
  value = {
    for role, d in digitalocean_droplet.host : role => {
      id          = d.id
      public_ipv4 = d.ipv4_address
      vpc_ipv4    = d.ipv4_address_private
      host_key    = trimspace(tls_private_key.host[role].public_key_openssh)
    }
  }
}

output "hqn_ipv4" {
  description = "The hqn/1 gateway's reserved IP."
  value       = digitalocean_reserved_ip.hqn.ip_address
}

output "bundle" {
  description = "role → the secret bundle entries Terraform owns (merged with the GitHub secrets by infra/scripts/publish-secrets.sh)."
  sensitive   = true
  value = merge(
    {
      app = {
        database_url        = local.database_url
        database_url_direct = local.database_url_direct
        pg_ca_cert          = data.digitalocean_database_ca.pg.certificate
        emqx_api_secret     = random_password.emqx_api_secret.result
        origin_cert         = cloudflare_origin_ca_certificate.origin.certificate
        origin_key          = tls_private_key.origin.private_key_pem
        wireguard = jsonencode({
          privateKey    = wireguard_asymmetric_key.host["app"].private_key
          peerPublicKey = wireguard_asymmetric_key.host["mqtt"].public_key
          peerEndpoint  = digitalocean_droplet.host["mqtt"].ipv4_address_private
          presharedKey  = random_bytes.wireguard_psk.base64
        })
      }
      mqtt = {
        emqx_api_secret = random_password.emqx_api_secret.result
        wireguard = jsonencode({
          privateKey    = wireguard_asymmetric_key.host["mqtt"].private_key
          peerPublicKey = wireguard_asymmetric_key.host["app"].public_key
          peerEndpoint  = digitalocean_droplet.host["app"].ipv4_address_private
          presharedKey  = random_bytes.wireguard_psk.base64
        })
      }
    },
    local.sim ? {
      sim = {
        database_url_sim = local.database_url_sim
        pg_ca_cert       = data.digitalocean_database_ca.pg.certificate
      }
    } : {},
  )
}
