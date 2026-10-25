# The hardened unit every hqcat program runs in (pkgs.hqcat-server's
# `hqcat-<name>`), shared by the roles that run them: app.nix and sim.nix.
# Secrets from hqcat.secretsDir reach a unit through LoadCredential as
# $CREDENTIALS_DIRECTORY/<name>, which its environment names as `%d/<name>`.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.hqcat;
  env = cfg.environment;
  server = pkgs.hqcat-server;

  common = {
    NODE_ENV = "production";
    # nginx resolves CF-Connecting-IP (set_real_ip_from Cloudflare only) and
    # passes the result as X-Real-IP: the one client address the server's
    # per-address limits may believe.
    TRUSTED_PROXY = "x-real-ip";
    LOG_LEVEL = "info";
    SENTRY_ENVIRONMENT = env.name;
    SENTRY_DSN = env.sentryDsn;
  };

  credential = name: "${name}:${cfg.secretsDir}/${name}";

  unit =
    {
      description,
      program,
      env,
      creds,
      mem,
      warn,
      crit,
      extra ? { },
      afterUnits ? [ ],
    }:
    let
      environment =
        common
        // {
          HEALTH_RSS_WARN_MB = toString warn;
          HEALTH_RSS_CRIT_MB = toString crit;
        }
        // env;
    in
    {
      inherit description environment;
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ] ++ afterUnits;
      wants = [ "network-online.target" ];
      requires = afterUnits;
      serviceConfig =
        cfg.hardenedService
        // {
          ExecStart = lib.getExe' server program;
          LoadCredential = map credential creds;
          MemoryMax = mem;
        }
        // extra;
    };
in
{
  options.hqcat.service = {
    environment = mkOption {
      type = types.attrsOf types.anything;
      readOnly = true;
      default = common;
      description = "The environment every hqcat program starts with.";
    };

    credential = mkOption {
      type = types.functionTo types.str;
      readOnly = true;
      default = credential;
      description = "name → the LoadCredential entry for that file of hqcat.secretsDir.";
    };

    unit = mkOption {
      type = types.functionTo (types.attrsOf types.anything);
      readOnly = true;
      default = unit;
      description = ''
        { description, program, env, creds, mem, warn, crit, extra?, afterUnits? }
        → a systemd service running `hqcat-<program>` in hqcat.hardenedService
        with these credentials, a memory ceiling and the health monitor's RSS
        thresholds; it starts after and requires `afterUnits`.
      '';
    };
  };
}
