# Pull-based updates: every two minutes the host fetches its secrets and then
# its channel pointer, <cache>/channels/<environment>/<role>.signed, and
# switches to the signed closure it names, gated by the new generation's
# hqcat-health-check. The pointer is signed with the cache key and numbered,
# so an older one is refused. It never evaluates or builds.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  env = config.hqcat.environment;

  hostAgent = pkgs.writeShellApplication {
    name = "hqcat-host-agent";
    runtimeInputs = with pkgs; [
      curl
      nix
      coreutils
      gnused
      systemd
      (callPackage ../pkgs/hqcat-verify-signed.nix { })
    ];
    text = builtins.readFile ../hqcat-host-agent.sh;
  };
in
{
  nix.settings = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    substituters = [
      env.cache.url
      "https://cache.nixos.org"
    ];
    trusted-public-keys = [
      env.cache.publicKey
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    ];
    max-jobs = 0;
    builders-use-substitutes = true;
  };

  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 30d";
  };
  nix.optimise = {
    automatic = true;
    dates = [ "weekly" ];
  };

  environment.systemPackages = [ hostAgent ];

  systemd.services.hqcat-host-agent = {
    description = "Pull and activate the published NixOS closure for this host";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    restartIfChanged = false;
    stopIfChanged = false;
    environment = {
      HEALTH_TIMEOUT = "300";
      CACHE_URL = env.cache.url;
      CACHE_PUBLIC_KEY = env.cache.publicKey;
      ENVIRONMENT = env.name;
    };
    serviceConfig = {
      Type = "oneshot";
      EnvironmentFile = "/run/hqcat/host.env";
      ExecStart = lib.getExe hostAgent;
      TimeoutStartSec = 1800;
    };
  };

  systemd.timers.hqcat-host-agent = {
    description = "Check for a new published host configuration";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "1min";
      OnUnitActiveSec = "2min";
      RandomizedDelaySec = "20s";
      Persistent = true;
      Unit = "hqcat-host-agent.service";
    };
  };

  systemd.tmpfiles.rules = [ "d /var/lib/hqcat-host 0700 root root -" ];
}
