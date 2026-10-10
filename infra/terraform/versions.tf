terraform {
  required_version = ">= 1.9.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.102"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
    wireguard = {
      source  = "OJFord/wireguard"
      version = "~> 0.4"
    }
  }

  # State lives in the environment's R2 bucket under <environment>/terraform.tfstate;
  # infra/scripts/terraform.sh passes the backend configuration.
  backend "s3" {}
}
