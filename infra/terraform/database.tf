# Managed Postgres in the environment's VPC, reachable only from the app host
# and the sim node (by tag). The services connect through a transaction-mode
# pool as `app`, the sim node through its own as `hqcat_sim`; migrations use
# the cluster admin on the direct endpoint.
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
  dynamic "rule" {
    for_each = [for r in ["app", "sim"] : r if contains(local.roles, r)]
    content {
      type  = "tag"
      value = digitalocean_tag.this[rule.value].name
    }
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

# The sim node's login. The migrations grant it SELECT and INSERT on
# sim_reports (005_sim_reports.sql, SIM_ROLE) and nothing else; the app host's
# hqcat-db-migrate repeats that grant on every run.
resource "digitalocean_database_user" "sim" {
  count      = local.sim ? 1 : 0
  cluster_id = digitalocean_database_cluster.pg.id
  name       = "hqcat_sim"
  lifecycle {
    ignore_changes = [settings]
  }
}

resource "digitalocean_database_connection_pool" "sim" {
  count      = local.sim ? 1 : 0
  cluster_id = digitalocean_database_cluster.pg.id
  name       = "hqchat_sim"
  mode       = "transaction"
  size       = 2
  db_name    = digitalocean_database_db.app.name
  user       = digitalocean_database_user.sim[0].name
}

data "digitalocean_database_ca" "pg" {
  cluster_id = digitalocean_database_cluster.pg.id
}

locals {
  database_url = replace(digitalocean_database_connection_pool.app.private_uri, "sslmode=require", "sslmode=verify-full")
  database_url_sim = local.sim ? replace(
    digitalocean_database_connection_pool.sim[0].private_uri, "sslmode=require", "sslmode=verify-full"
  ) : null
  database_url_direct = format(
    "postgresql://%s:%s@%s:%d/%s?sslmode=verify-full",
    digitalocean_database_cluster.pg.user,
    digitalocean_database_cluster.pg.password,
    digitalocean_database_cluster.pg.private_host,
    digitalocean_database_cluster.pg.port,
    digitalocean_database_db.app.name,
  )
}
