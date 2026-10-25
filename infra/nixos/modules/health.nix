# `hqcat-health-check`: exit 0 when every unit of this host's role is active and
# answers its health endpoint. Shipped in the closure it judges; the host agent
# runs the new generation's check after a switch and rolls back on failure.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  secrets = cfg.secretsDir;

  units =
    if cfg.role == "base" then
      [ ]
    else if cfg.role == "mqtt" then
      [
        "podman-emqx"
        "hqcat-wireguard"
      ]
    else if cfg.role == "sim" then
      [ "hqcat-sim" ]
    else
      [
        "hqcat-wireguard"
        "nginx"
        "hqcat-db-migrate"
        "hqcat-server"
        "hqcat-bot"
      ];

  endpoints = lib.optionals (cfg.role == "app") [ 8090 ];

  check = pkgs.writeShellApplication {
    name = "hqcat-health-check";
    runtimeInputs = [
      pkgs.curl
      pkgs.systemd
      pkgs.podman
    ];
    text = ''
      ok=0
      units=(${lib.escapeShellArgs units})
      endpoints=(${toString endpoints})
      for u in "''${units[@]}"; do
        systemctl is-active --quiet "$u.service" || { echo "unit $u is $(systemctl is-active "$u.service")"; ok=1; }
      done
      for p in "''${endpoints[@]}"; do
        curl -fsS --max-time 5 "http://127.0.0.1:$p/health" >/dev/null || { echo "127.0.0.1:$p/health failed"; ok=1; }
      done
      ${lib.optionalString (cfg.role == "mqtt") ''
        podman exec emqx emqx ctl status >/dev/null 2>&1 || { echo "emqx ctl status failed"; ok=1; }
        if [ -s ${secrets}/noise_keys ]; then
          curl -fsS --max-time 5 http://127.0.0.1:8081/health >/dev/null || { echo "noise-gw health failed"; ok=1; }
        fi
      ''}
      exit "$ok"
    '';
  };
in
{
  environment.systemPackages = [ check ];
}
