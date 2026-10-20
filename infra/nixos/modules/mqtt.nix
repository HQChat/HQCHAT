# The broker host (hqcat.role = "mqtt"): EMQX in podman from an image pinned
# in the closure, and noise-gw, the hqn/1 gateway, on the one public port.
#
#   users    ── hqn/1 ──► :443 noise-gw ─► 127.0.0.1:1883 EMQX
#   app host ── wg0  ──► 8083 WebSocket, 1884 internal, 18083 admin API, 8081 gateway keys
#   EMQX     ── wg0  ──► app host :8090 authn hooks
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  wg = cfg.wg.addresses;
  env = cfg.environment;
  secrets = cfg.secretsDir;
  server = pkgs.hqcat-server;
  emqxUid = 1000;

  template = builtins.readFile ../../emqx/emqx.conf;
  placeholders = {
    "@WS_BIND@" = "${wg.mqtt}:8083";
    "@GW_BIND@" = "127.0.0.1:1883";
    "@INTERNAL_BIND@" = "${wg.mqtt}:1884";
    "@API_BIND@" = "${wg.mqtt}:18083";
    "@AUTH_URL@" = "http://${wg.app}:8090";
  };
  rendered =
    builtins.replaceStrings (builtins.attrNames placeholders) (builtins.attrValues placeholders)
      template;
  emqxConf = pkgs.writeText "emqx.conf" (
    rendered
    + ''

      rpc { listen_address = "127.0.0.1" }
    ''
  );

  image = pkgs.dockerTools.pullImage {
    imageName = "emqx/emqx";
    imageDigest = "sha256:a1e3d10fa1dcc8c94325b815a93b5b5974253a97cb36470b44e47d5d3ef9cd13";
    hash = "sha256-qcPocoTNrVXAnxumjl+nyDOU/4kTtKPdeGgF9fD8gqA=";
    finalImageName = "emqx/emqx";
    finalImageTag = "5.8.6";
    os = "linux";
    arch = "amd64";
  };
in
lib.mkIf (cfg.role == "mqtt") {
  assertions = [
    {
      assertion = lib.all (p: lib.hasInfix p template && !(lib.hasInfix p rendered)) (
        builtins.attrNames placeholders
      );
      message = "emqx.conf and mqtt.nix disagree on the @PLACEHOLDER@ set.";
    }
    {
      assertion = lib.hasInfix "mqtt { wildcard_subscription = false }" template;
      message = "emqx.conf must keep client wildcard subscriptions off; the ACL depends on it.";
    }
    {
      assertion = lib.all (s: lib.hasInfix s template) [
        "mqtt.max_packet_size = "
        "mqtt.max_subscriptions = "
        "delayed { enable = false }"
      ];
      message = "emqx.conf must cap packets and subscriptions and keep delayed publish off: any client may publish to any inbox.";
    }
    {
      assertion = !(lib.hasInfix "cookie =" template);
      message = "emqx.conf must not carry a cookie; it is generated per host.";
    }
  ];

  # The Terraform-formatted volume, by label so a reinstall never formats it.
  fileSystems."/var/lib/emqx" = {
    device = "/dev/disk/by-label/emqx-data";
    fsType = "ext4";
    options = [
      "nofail"
      "x-systemd.device-timeout=30s"
    ];
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/emqx 0750 ${toString emqxUid} ${toString emqxUid} -"
    "d /var/lib/hqcat-emqx 0700 root root -"
    "f ${secrets}/emqx_api_secret 0600 root root -"
    "f ${secrets}/noise_keys 0600 root root -"
  ];

  hqcat.secretConsumers = [
    "hqcat-emqx-secrets.service"
    "podman-emqx.service"
    "hqcat-noise-gw.service"
  ];

  # The Erlang cookie and dashboard password are generated here once; the admin
  # API key comes from the secret bundle (shared with the app host).
  systemd.services.hqcat-emqx-secrets = {
    description = "Render EMQX's cookie, dashboard password and admin API key";
    before = [ "podman-emqx.service" ];
    requiredBy = [ "podman-emqx.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      RuntimeDirectory = "hqcat-emqx";
      RuntimeDirectoryMode = "0750";
      RuntimeDirectoryPreserve = "yes";
    };
    path = [
      pkgs.coreutils
      pkgs.openssl
    ];
    script = ''
      set -eu
      umask 077
      for f in cookie dashboard_password; do
        [ -s /var/lib/hqcat-emqx/$f ] || openssl rand -hex 32 > /var/lib/hqcat-emqx/$f
      done
      {
        printf 'EMQX_NODE__COOKIE=%s\n' "$(cat /var/lib/hqcat-emqx/cookie)"
        printf 'EMQX_DASHBOARD__DEFAULT_PASSWORD=%s\n' "$(cat /var/lib/hqcat-emqx/dashboard_password)"
      } > /run/hqcat-emqx/emqx.env

      if [ -s ${secrets}/emqx_api_secret ]; then
        printf 'hqcat-svc:%s\n' "$(cat ${secrets}/emqx_api_secret)" > /run/hqcat-emqx/api_bootstrap
      else
        echo "${secrets}/emqx_api_secret is missing: the admin API has no key"
        : > /run/hqcat-emqx/api_bootstrap
      fi
      chown ${toString emqxUid} /run/hqcat-emqx /run/hqcat-emqx/api_bootstrap
      chmod 0400 /run/hqcat-emqx/api_bootstrap
    '';
  };

  virtualisation.podman.enable = true;
  virtualisation.oci-containers = {
    backend = "podman";
    containers.emqx = {
      image = "emqx/emqx:5.8.6";
      imageFile = image;
      environment = {
        EMQX_NODE__NAME = "emqx@127.0.0.1";
        # A single node: Erlang distribution (4370) listens on loopback only,
        # as rpc does, never on every address of the host network.
        ERL_FLAGS = "-kernel inet_dist_use_interface {127,0,0,1}";
        EMQX_API_KEY__BOOTSTRAP_FILE = "/run/hqcat-emqx/api_bootstrap";
      };
      environmentFiles = [ "/run/hqcat-emqx/emqx.env" ];
      volumes = [
        "${emqxConf}:/opt/emqx/etc/emqx.conf:ro"
        "${../../emqx/acl.conf}:/opt/emqx/etc/hqchat-acl.conf:ro"
        "/var/lib/emqx:/opt/emqx/data"
        "/run/hqcat-emqx/api_bootstrap:/run/hqcat-emqx/api_bootstrap:ro"
      ];
      extraOptions = [
        "--network=host"
        "--read-only"
        "--tmpfs=/opt/emqx/log"
        "--tmpfs=/tmp"
        "--cap-drop=all"
        "--security-opt=no-new-privileges"
        "--memory=1g"
      ];
    };
  };

  systemd.services.podman-emqx = {
    after = [
      "network-online.target"
      "hqcat-emqx-secrets.service"
      "var-lib-emqx.mount"
    ];
    wants = [
      "network-online.target"
      "var-lib-emqx.mount"
    ];
    # A freshly formatted volume's root belongs to root, and the tmpfiles rule
    # above can run before the mount, owning only the directory underneath.
    # EMQX (uid ${toString emqxUid} in the container) then cannot create data/configs.
    preStart = lib.mkBefore ''
      ${pkgs.coreutils}/bin/chown ${toString emqxUid}:${toString emqxUid} /var/lib/emqx
      ${pkgs.coreutils}/bin/chmod 0750 /var/lib/emqx
    '';
  };

  systemd.services.hqcat-noise-gw = {
    description = "hqn/1 gateway (noise-gw)";
    wantedBy = [ "multi-user.target" ];
    after = [
      "network-online.target"
      "podman-emqx.service"
    ];
    wants = [ "network-online.target" ];
    unitConfig.ConditionFileNotEmpty = "${secrets}/noise_keys";
    environment = {
      NODE_ENV = "production";
      NOISE_GW_PORT = "443";
      NOISE_GW_HEALTH_HOST = "127.0.0.1,${wg.mqtt}";
      NOISE_GW_HEALTH_PORT = "8081";
      NOISE_KEYS_FILE = "%d/noise_keys";
      EMQX_TCP_HOST = "127.0.0.1";
      EMQX_TCP_PORT = "1883";
      SENTRY_ENVIRONMENT = env.name;
      SENTRY_DSN = env.sentryDsn;
      LOG_LEVEL = "info";
      HEALTH_RSS_WARN_MB = "380";
      HEALTH_RSS_CRIT_MB = "460";
    };
    serviceConfig = cfg.hardenedService // {
      ExecStart = lib.getExe' server "hqcat-noise-gw";
      LoadCredential = [ "noise_keys:${secrets}/noise_keys" ];
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      CPUQuota = "200%";
      MemoryMax = "512M";
    };
  };
}
