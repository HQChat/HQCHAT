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

locals {
  env  = jsondecode(file("${path.module}/../environments/${var.environment}.json"))
  name = "hqchat-${local.env.name}"
  tags = {
    env  = local.name
    app  = "${local.name}-app"
    mqtt = "${local.name}-mqtt"
  }
  roles = toset(["app", "mqtt"])
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
