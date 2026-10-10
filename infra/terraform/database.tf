# Managed Postgres in the environment's VPC, reachable only from the app host
# (by tag). The services connect through a transaction-mode pool as `app`;
# migrations use the cluster admin on the direct endpoint.
resource "digitalocean_database_cluster" "pg" {
  name                 = local.name
  engine               = "pg"
  version              = "17"
  size                 = local.env.sizes.database
  region               = local.env.region
  node_count           = 1
  private_network_uuid = digitalocean_vpc.this.id
  tags                 = [digitalocean_tag.this["env"].name]

  maintenance_window {
    day  = "sunday"
    hour = "03:00:00"
  }
}

resource "digitalocean_database_firewall" "pg" {
  cluster_id = digitalocean_database_cluster.pg.id
  rule {
    type  = "tag"
    value = digitalocean_tag.this["app"].name
  }
}

resource "digitalocean_database_db" "app" {
  cluster_id = digitalocean_database_cluster.pg.id
  name       = "hqchat"
}

resource "digitalocean_database_user" "app" {
  cluster_id = digitalocean_database_cluster.pg.id
  name       = "app"
  lifecycle {
    ignore_changes = [settings]
  }
}

resource "digitalocean_database_connection_pool" "app" {
  cluster_id = digitalocean_database_cluster.pg.id
  name       = "hqchat"
  mode       = "transaction"
  size       = 15
  db_name    = digitalocean_database_db.app.name
  user       = digitalocean_database_user.app.name
}

data "digitalocean_database_ca" "pg" {
  cluster_id = digitalocean_database_cluster.pg.id
}

locals {
  database_url = replace(digitalocean_database_connection_pool.app.private_uri, "sslmode=require", "sslmode=verify-full")
  database_url_direct = format(
    "postgresql://%s:%s@%s:%d/%s?sslmode=verify-full",
    digitalocean_database_cluster.pg.user,
    digitalocean_database_cluster.pg.password,
    digitalocean_database_cluster.pg.private_host,
    digitalocean_database_cluster.pg.port,
    digitalocean_database_db.app.name,
  )
}
