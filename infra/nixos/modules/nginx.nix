# The app host's only public listener: TLS with the Cloudflare Origin certificate,
# per-IP rate limits keyed on CF-Connecting-IP, and routing to the services and
# to the broker's WebSocket listener over WireGuard.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  env = cfg.environment;
  cf = import ./cloudflare-ips.nix;
  wg = cfg.wg.addresses;
  certDir = "/etc/ssl/cloudflare";

  fwd = ''
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  '';

  upstream = "http://127.0.0.1:8090";

  apiPaths = [
    "/friends"
    "/username"
    "/users"
    "/push"
    "/account"
    "/stripe"
    "/supporters"
  ];
  apiLocation = {
    proxyPass = upstream;
    extraConfig = ''
      limit_req zone=api burst=40 nodelay;
      ${fwd}
    '';
  };
in
lib.mkIf (cfg.role == "app") {
  services.nginx = {
    enable = true;
    recommendedOptimisation = true;
    recommendedTlsSettings = false;

    commonHttpConfig = ''
      limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
      map $request_method $checkout_limit_key {
          POST    $binary_remote_addr;
          default "";
      }
      limit_req_zone $checkout_limit_key zone=checkout:10m rate=10r/m;
      # The broker's WebSocket: a client opens one connection and keeps it, and
      # every opening costs the auth service a database lookup.
      limit_req_zone $binary_remote_addr zone=mqtt:10m rate=2r/s;
      limit_conn_zone $binary_remote_addr zone=mqtt_conn:10m;

      ${lib.concatMapStringsSep "\n" (r: "set_real_ip_from ${r};") (cf.v4 ++ cf.v6)}
      real_ip_header CF-Connecting-IP;
    '';

    virtualHosts.${env.domain} = {
      forceSSL = true;
      serverAliases = env.siteDomains ++ lib.optional (env ? apiHost) env.apiHost;
      sslCertificate = "${certDir}/origin.pem";
      sslCertificateKey = "${certDir}/origin.key";

      extraConfig = ''
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;
        client_max_body_size 1m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "no-referrer" always;
      '';

      locations = {
        "/mqtt" = {
          proxyPass = "http://${wg.mqtt}:8083";
          proxyWebsockets = true;
          extraConfig = ''
            limit_req zone=mqtt burst=20 nodelay;
            limit_conn mqtt_conn 50;
            ${fwd}
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
          '';
        };

        "/auth/" = {
          proxyPass = upstream;
          extraConfig = ''
            limit_req zone=api burst=40 nodelay;
            ${fwd}
          '';
        };

        "/donate" = {
          proxyPass = upstream;
          extraConfig = ''
            limit_req zone=api burst=40 nodelay;
            limit_req zone=checkout burst=3 nodelay;
            ${fwd}
          '';
        };

        "/" = apiLocation;
      }
      // lib.genAttrs apiPaths (_: apiLocation);
    };
  };

  users.users.nginx.extraGroups = [ "ssl-cert" ];
  users.groups.ssl-cert = { };

  systemd.tmpfiles.rules = [
    "d ${certDir} 0750 root ssl-cert -"
    "z ${certDir}/origin.pem 0644 root ssl-cert -"
    "z ${certDir}/origin.key 0640 root ssl-cert -"
  ];

  # Installs the Cloudflare origin certificate from the secret bundle, or a
  # self-signed placeholder until it arrives (Cloudflare then answers 526).
  systemd.services.hqcat-origin-cert = {
    description = "Install the origin TLS certificate for nginx";
    wantedBy = [ "multi-user.target" ];
    before = [ "nginx.service" ];
    requiredBy = [ "nginx.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    path = with pkgs; [
      openssl
      coreutils
    ];
    script = ''
      set -euo pipefail
      mkdir -p ${certDir}
      if [ -s ${cfg.secretsDir}/origin_cert ] && [ -s ${cfg.secretsDir}/origin_key ]; then
        install -m 0644 -g ssl-cert ${cfg.secretsDir}/origin_cert ${certDir}/origin.pem
        install -m 0640 -g ssl-cert ${cfg.secretsDir}/origin_key ${certDir}/origin.key
      elif [ ! -s ${certDir}/origin.pem ] || [ ! -s ${certDir}/origin.key ]; then
        echo "no origin certificate yet: generating a self-signed placeholder"
        openssl req -x509 -nodes -newkey rsa:2048 -days 30 -subj "/CN=${env.domain}" \
          -keyout ${certDir}/origin.key -out ${certDir}/origin.pem 2>/dev/null
        chown root:ssl-cert ${certDir}/origin.pem ${certDir}/origin.key
        chmod 0644 ${certDir}/origin.pem
        chmod 0640 ${certDir}/origin.key
      fi
    '';
  };
}
