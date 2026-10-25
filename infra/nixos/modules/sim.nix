# The sim node (docs/runbooks/sim.md): hqcat-sim runs SIM_COUNT synthetic
# accounts that reach the service through its public front door, as a phone
# does, and writes an hourly health report to sim_reports.
#
#   hqcat-sim ──► https://<apiHost> (Cloudflare → nginx on the app host), WSS
#                 at /mqtt there; hqn/1 to the host the server offers (the
#                 broker's reserved IP)
#   hqcat-sim ──► its own Postgres pool in the VPC, as hqcat_sim
#
# It is not on the WireGuard link and publishes no port. Its seeds are
# credentials, from hqcat.secretsDir like every secret, never the Nix store.
{
  config,
  lib,
  ...
}:
let
  cfg = config.hqcat;
  env = cfg.environment;

  bundleEntries = [
    "database_url_sim"
    "pg_ca_cert"
    "sim_seeds"
    "bot_id"
  ];
in
lib.mkIf (cfg.role == "sim") {
  systemd.tmpfiles.rules = map (n: "f ${cfg.secretsDir}/${n} 0600 root root -") bundleEntries;

  hqcat.secretConsumers = [ "hqcat-sim.service" ];

  # Started without its seeds, each sim would mint one of its own and claim
  # its handle under an identity no deploy can bring back.
  systemd.services.hqcat-sim = lib.recursiveUpdate (cfg.service.unit {
    description = "HQChat sim node: synthetic accounts and their hourly health report";
    program = "hqcat-sim";
    mem = "768M";
    warn = 560;
    crit = 680;
    creds = bundleEntries;
    env = {
      BASE_URL = "https://${lib.toLower (env.apiHost or env.domain)}";
      BOT_ID_FILE = "%d/bot_id";
      SIM_SEEDS_FILE = "%d/sim_seeds";
      SIM_PREFIX = "echo_";
      SIM_COUNT = "10";
      SIM_STATE_DIR = "/var/lib/hqcat-sim";
      DATABASE_URL_FILE = "%d/database_url_sim";
      PGSSLROOTCERT = "%d/pg_ca_cert";
    };
    extra = {
      StateDirectory = "hqcat-sim";
      StateDirectoryMode = "0700";
    };
  }) { unitConfig.ConditionFileNotEmpty = map (n: "${cfg.secretsDir}/${n}") bundleEntries; };
}
