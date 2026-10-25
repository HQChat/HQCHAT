# The app host's services as hardened systemd units, run from pkgs.hqcat-server:
#
#   nginx ─► 127.0.0.1:8090 hqcat-server ◄── wg: the broker's authn hooks
#            hqcat-server ──► wg: EMQX admin API (18083), internal listener (1884)
#            hqcat-bot ──► hqcat-server (loopback), EMQX WebSocket (wg)
#
# hqcat-db-migrate runs before the server, the server before the bot.
# Configuration comes from the environment file; secrets from hqcat.secretsDir
# reach each unit through LoadCredential (units.nix).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  env = cfg.environment;
  wg = cfg.wg.addresses;
  server = pkgs.hqcat-server;
  secrets = cfg.secretsDir;
  inherit (env) donations;
  sim = env.sizes ? sim;
  simRole = "hqcat_sim";

  # The connection goes to psql in PG* variables, never in its arguments,
  # where any process on the host could read the admin password.
  simGrant = pkgs.writeShellApplication {
    name = "hqcat-sim-grant";
    runtimeInputs = [ pkgs.postgresql ];
    text = ''
      re='^postgresql://([^:/@]+):([^@]+)@([^:/@]+):([0-9]+)/([^?/]+)\?sslmode=verify-full$'
      [[ "$(cat "$CREDENTIALS_DIRECTORY/database_url_direct")" =~ $re ]] || {
        echo "database_url_direct is not the URL Terraform writes; sim_reports grant skipped" >&2
        exit 1
      }
      export PGUSER="''${BASH_REMATCH[1]}" PGPASSWORD="''${BASH_REMATCH[2]}" PGHOST="''${BASH_REMATCH[3]}"
      export PGPORT="''${BASH_REMATCH[4]}" PGDATABASE="''${BASH_REMATCH[5]}" PGSSLMODE=verify-full
      export PGSSLROOTCERT="$CREDENTIALS_DIRECTORY/pg_ca_cert"
      psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
      DO $$
      BEGIN
        IF to_regclass('public.sim_reports') IS NOT NULL
          AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${simRole}') THEN
          GRANT SELECT, INSERT ON public.sim_reports TO ${simRole};
        END IF;
      END
      $$;
      SQL
    '';
  };

  bundleEntries = [
    "database_url"
    "database_url_direct"
    "pg_ca_cert"
    "stripe_secret_key"
    "stripe_webhook_secret"
    "apns_key_p8"
    "emqx_api_secret"
    "bot_seed"
    "bot_id"
  ];

  inherit (cfg.service) unit;
  cred = cfg.service.credential;
  common = cfg.service.environment;

  # Where the bot reaches the server, and so the origin its sign-in proves.
  botBaseUrl = "http://127.0.0.1:8090";

  database = {
    DATABASE_URL_FILE = "%d/database_url";
    PGSSLROOTCERT = "%d/pg_ca_cert";
  };

  donationEnv =
    if donations == null then
      { DONATIONS_ENABLED = "0"; }
    else
      {
        DONATIONS_ENABLED = "1";
        STRIPE_SECRET_KEY_FILE = "%d/stripe_secret_key";
        STRIPE_WEBHOOK_SECRET_FILE = "%d/stripe_webhook_secret";
        STRIPE_DONATION_PRICE_IDS = lib.concatStringsSep "," donations.monthlyPriceIds;
        STRIPE_DONATION_ONCE_PRICE_ID = donations.oncePriceId;
      };

  serverCreds = [
    "database_url"
    "pg_ca_cert"
    "stripe_secret_key"
    "stripe_webhook_secret"
    "apns_key_p8"
    "emqx_api_secret"
    "bot_id"
  ];

  serverEnv =
    database
    // donationEnv
    // {
      PORT = "8090";
      LISTEN_HOST = "127.0.0.1,${wg.app}";
      SERVER_VERSION = server.version;
      PUBLIC_BASE_URL = "https://${env.domain}";
      # The origins a sign-in proof may be bound to: the apps' API host and the
      # bot's own (its BASE_URL below).
      AUTH_ORIGINS = "https://${lib.toLower (env.apiHost or env.domain)},${botBaseUrl}";
      BOT_ID_FILE = "%d/bot_id";
      EMQX_API_URL = "http://${wg.mqtt}:18083";
      EMQX_API_KEY = "hqcat-svc";
      EMQX_API_SECRET_FILE = "%d/emqx_api_secret";
      EMQX_INTERNAL_URL = "mqtt://${wg.mqtt}:1884";
      HQN_ENABLED = "1";
      HQN_PUBLIC_HOST = env.hqnHost;
      HQN_PUBLIC_PORT = "443";
      HQN_GATEWAY_KEYS_URL = "http://${wg.mqtt}:8081/keys";
      APNS_KEY_ID = env.apns.keyId;
      APNS_TEAM_ID = env.apns.teamId;
      APNS_TOPIC_IOS = env.apns.topicIos;
      APNS_TOPIC_MACOS = env.apns.topicMacos;
      APNS_KEY_P8_FILE = "%d/apns_key_p8";
    };

  # Operator tools (scripts/reports.ts, scripts/check-push.ts) run as a
  # transient unit with the server's environment, credentials and sandbox:
  #   hqcat-ops reports [<report-id> <disposition>]
  #   hqcat-ops check-push <username>
  sandboxProp = v: if builtins.isBool v then (if v then "yes" else "no") else toString v;
  sandboxArgs = lib.concatStringsSep " " (
    lib.concatLists (
      lib.mapAttrsToList
        (k: v: map (x: "-p ${lib.escapeShellArg "${k}=${sandboxProp x}"}") (lib.toList v))
        (
          removeAttrs cfg.hardenedService [
            "Restart"
            "RestartSec"
          ]
        )
    )
  );
  exportLine =
    k: v:
    if lib.hasPrefix "%d/" v then
      "export ${k}=\"$CREDENTIALS_DIRECTORY/${lib.removePrefix "%d/" v}\"\n"
    else
      "export ${k}=${lib.escapeShellArg v}\n";

  opsEnv = pkgs.writeShellScript "hqcat-ops-env" ''
    ${lib.concatStrings (lib.mapAttrsToList exportLine (common // serverEnv))}
    tool="$1"
    shift
    exec ${server}/bin/hqcat-"$tool" "$@"
  '';

  ops = pkgs.writeShellApplication {
    name = "hqcat-ops";
    text = ''
      tool="''${1:?usage: hqcat-ops reports|check-push [args...]}"
      shift
      case "$tool" in
        reports | check-push) ;;
        *)
          echo "unknown tool: $tool" >&2
          exit 2
          ;;
      esac
      exec systemd-run --pty --wait --collect --quiet ${sandboxArgs} \
        ${lib.concatMapStringsSep " " (c: "-p LoadCredential=${cred c}") serverCreds} \
        ${opsEnv} "$tool" "$@"
    '';
  };
in
lib.mkIf (cfg.role == "app") {
  environment.systemPackages = [ ops ];

  systemd.tmpfiles.rules = map (n: "f ${secrets}/${n} 0600 root root -") bundleEntries;

  hqcat.secretConsumers = [
    "hqcat-origin-cert.service"
    "nginx.service"
    "hqcat-db-migrate.service"
    "hqcat-server.service"
    "hqcat-bot.service"
  ];

  systemd.services.hqcat-db-migrate = {
    description = "Bring the database schema up to date";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    environment =
      common
      // database
      // {
        DATABASE_URL_DIRECT_FILE = "%d/database_url_direct";
        APP_ROLE = "app";
      }
      // lib.optionalAttrs sim {
        # The sim node's login (infra/terraform/database.tf), which
        # 005_sim_reports.sql grants SELECT and INSERT on sim_reports.
        SIM_ROLE = simRole;
      };
    serviceConfig = cfg.hardenedService // {
      Type = "oneshot";
      RemainAfterExit = true;
      Restart = "no";
      ExecStart = lib.getExe' server "hqcat-migrate";
      # The same grant again, for a database whose 005 ran before the role
      # existed (granting the connecting user then): idempotent, and a no-op
      # until both the table and the role are there. A failure is logged and
      # leaves the server to start: the sim node's report is not worth an outage.
      ExecStartPost = lib.mkIf sim "-${lib.getExe simGrant}";
      LoadCredential = map cred [
        "database_url_direct"
        "pg_ca_cert"
      ];
      MemoryMax = "256M";
    };
  };

  systemd.services.hqcat-server = unit {
    description = "HQChat server: auth, REST API, push bridge, broker watch";
    program = "hqcat-server";
    mem = "1G";
    warn = 780;
    crit = 930;
    creds = serverCreds;
    afterUnits = [ "hqcat-db-migrate.service" ];
    env = serverEnv;
  };

  systemd.services.hqcat-bot = unit {
    description = "HQChat helper bot";
    program = "hqcat-bot";
    mem = "512M";
    warn = 380;
    crit = 460;
    creds = [ "bot_seed" ];
    env = {
      BASE_URL = botBaseUrl;
      MQTT_URL = "ws://${wg.mqtt}:8083/mqtt";
      BOT_USERNAME = "helper";
      BOT_STATE_DIR = "/var/lib/hqcat-bot";
      BOT_SEED_FILE = "%d/bot_seed";
    };
    afterUnits = [ "hqcat-server.service" ];
    extra = {
      StateDirectory = "hqcat-bot";
      StateDirectoryMode = "0700";
    };
  };
}
