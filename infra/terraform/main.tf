# One environment (infra/environments/<environment>.json) from nothing: its
# network, droplets booted from the environment's NixOS image, the broker's
# volume and public address, firewalls, the managed Postgres, DNS, the site
# Worker and the origin certificate.
#
#   infra/scripts/terraform.sh <environment> plan|apply

provider "digitalocean" {}
provider "cloudflare" {}

variable "environment" {
  description = "Name of the environment file under infra/environments."
  type        = string
}

variable "image_url" {
  description = "Public URL of the environment's NixOS image (qcow2), as the Deploy workflow uploaded it."
  type        = string
}

variable "image_name" {
  description = "Name of that image; a new name imports a new image. Existing droplets keep theirs."
  type        = string
}

variable "age_identities" {
  description = "role → the host's age post-quantum identity (AGE-SECRET-KEY-PQ-1…), which opens its secret bundle; handed to a new droplet in user data."
  type        = map(string)
  sensitive   = true
  default     = {}
}

locals {
  env  = jsondecode(file("${path.module}/../environments/${var.environment}.json"))
  name = "hqchat-${local.env.name}"
  # The sim node (docs/runbooks/sim.md) runs only where the environment sizes it.
  sim   = lookup(local.env.sizes, "sim", null) != null
  roles = toset(concat(["app", "mqtt"], local.sim ? ["sim"] : []))
  tags  = merge({ env = local.name }, { for r in local.roles : r => "${local.name}-${r}" })
}

resource "digitalocean_vpc" "this" {
  name     = local.name
  region   = local.env.region
  ip_range = local.env.vpcRange
}

resource "digitalocean_tag" "this" {
  for_each = local.tags
  name     = each.value
}

resource "digitalocean_custom_image" "base" {
  name         = var.image_name
  url          = var.image_url
  regions      = [local.env.region]
  distribution = "Unknown"
  description  = "NixOS base image for ${local.name}"
  tags         = [digitalocean_tag.this["env"].name]
}
