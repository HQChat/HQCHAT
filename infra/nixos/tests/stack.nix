# Both roles on two VMs joined by WireGuard: the real host modules, firewall and
# listeners, with a local PostgreSQL standing in for the managed cluster. What
# netconf and the secret bundle deliver on a droplet is written directly. Every
# key and password here is a throwaway.
#
#   nix build .#checks.x86_64-linux.stack -L      # needs KVM
{ pkgs, lib, ... }:
let
  keys = {
    app = {
      private = "6H622m3RcR/ZuhEFzFnxHCvMBkYov/lhOSxpN2/twHQ=";
      public = "fa7PZr4RzdwzCPU6clA3JbtX7Ueav6v1QqkMIEDAYFQ=";
    };
    mqtt = {
      private = "0MfwnGJzt3lXqBBBUrl8YuuuG2AM1rUjmXIEVbBHsGQ=";
      public = "vaKCHaA+kdymfC/LGlvow/3Z1BNYRkHg4Jnhjt1s7w8=";
    };
  };
  apiSecret = "test-emqx-api-secret-0123456789abcdef";
  dbUrl = "postgresql://hqcat@127.0.0.1:5432/hqcat";

  addr = {
    app = "192.168.1.1";
    mqtt = "192.168.1.2";
  };

  environment = lib.importJSON ../../environments/production.json // {
    domain = "test.invalid";
    siteDomains = [ ];
    vpcRange = "192.168.1.0/24";
    sentryDsn = "";
    donations = null;
    apns = {
      keyId = "";
      teamId = "";
      topicIos = "";
      topicMacos = "";
    };
  };

  secret = name: value: {
    "hqcat/secrets/${name}" = {
      text = value;
      mode = "0600";
    };
  };

  common =
    role:
    { ... }:
    {
      imports = [
        ../modules/roles.nix
        ../admin.nix
      ];
      hqcat = {
        inherit role environment;
      };
      networking.useNetworkd = true;
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      systemd.services.hqcat-host-env = {
        wantedBy = [ "multi-user.target" ];
        before = [ "hqcat-wireguard.service" ];
        serviceConfig.Type = "oneshot";
        script = "mkdir -p /run/hqcat && echo ROLE=${role} > /run/hqcat/host.env";
      };

      systemd.timers.hqcat-host-agent.enable = false;
      systemd.timers.hqcat-secrets-sync.enable = false;
      systemd.timers.cloudflare-ips-refresh.enable = false;

      environment.systemPackages = [ pkgs.netcat-openbsd ];
      environment.etc =
        secret "emqx_api_secret" apiSecret
        // secret "wireguard" (
          builtins.toJSON {
            privateKey = keys.${role}.private;
            peerPublicKey = if role == "app" then keys.mqtt.public else keys.app.public;
            peerEndpoint = if role == "app" then addr.mqtt else addr.app;
          }
        );
    };
in
{
  name = "hqcat-stack";

  nodes.app =
    { ... }:
    {
      imports = [ (common "app") ];

      services.postgresql = {
        enable = true;
        package = pkgs.postgresql_17;
        ensureDatabases = [ "hqcat" ];
        ensureUsers = [
          {
            name = "hqcat";
            ensureDBOwnership = true;
            ensureClauses.superuser = true;
          }
          { name = "app"; }
        ];
        authentication = lib.mkForce ''
          local all all trust
          host  all all 127.0.0.1/32 trust
        '';
      };
      systemd.services.hqcat-db-migrate = {
        after = [ "postgresql.service" ];
        requires = [ "postgresql.service" ];
      };

      environment.etc = secret "database_url" dbUrl // secret "database_url_direct" dbUrl;
    };

  nodes.mqtt =
    { lib, ... }:
    {
      imports = [ (common "mqtt") ];
      fileSystems."/var/lib/emqx" = lib.mkForce {
        device = "tmpfs";
        fsType = "tmpfs";
        options = [ "mode=0750" ];
      };
    };

  testScript = ''
    start_all()

    with subtest("the broker comes up"):
        mqtt.wait_for_unit("podman-emqx.service")
        mqtt.wait_until_succeeds("podman exec emqx emqx ctl status", timeout=300)

    def wg_diagnostics():
        for m in (app, mqtt):
            print(m.execute(
                "wg show; ip -br addr; networkctl --no-pager status wg0; "
                "journalctl --no-pager -b -u systemd-networkd -u hqcat-wg-key | tail -30; "
                "nft list chain inet filter input"
            )[1])

    with subtest("the WireGuard link carries both directions"):
        try:
            app.wait_until_succeeds("ping -c1 -W2 10.200.0.2", timeout=120)
            mqtt.succeed("ping -c1 -W2 10.200.0.1")
        except Exception:
            wg_diagnostics()
            raise

    with subtest("the app services migrate and answer"):
        app.wait_for_unit("hqcat-db-migrate.service")
        app.wait_until_succeeds("curl -fsS 127.0.0.1:8090/health", timeout=240)

    # `emqx ctl status` passes once the node runs; the admin listener and the
    # bootstrapped API key come up a moment later.
    with subtest("the admin API answers the key over wg, and nothing else"):
        app.wait_until_succeeds(
            "curl -fsS -u hqcat-svc:${apiSecret} http://10.200.0.2:18083/api/v5/nodes | grep -q running",
            timeout=120,
        )
        app.fail("curl -fsS -o /dev/null -u hqcat-svc:wrong http://10.200.0.2:18083/api/v5/nodes")

    with subtest("clients get through auth's hooks over wg"):
        app.wait_until_succeeds("journalctl -u hqcat-server | grep -q 'push. connected to EMQX'", timeout=240)
        app.wait_until_succeeds("journalctl -u hqcat-bot | grep -q 'connected to the broker'", timeout=300)

    with subtest("nginx's /mqtt reaches the broker"):
        out = app.succeed(
            "curl -sk --http1.1 -o /dev/null -w '%{http_code}' https://127.0.0.1/mqtt -H 'Host: test.invalid' "
            "-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' "
            "-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: mqtt' --max-time 5 || true"
        )
        assert out.strip() == "101", f"expected a WebSocket upgrade through nginx, got {out!r}"

    with subtest("hqn/1: noise-gw on the broker's one public port"):
        mqtt.succeed(
            "${lib.getExe' pkgs.hqcat-server "hqcat-noise-gw-keys"} --key-id 1 "
            "--secret /etc/hqcat/secrets/noise_keys --public /root/noise_public.json"
        )
        mqtt.succeed("systemctl start hqcat-noise-gw")
        mqtt.wait_until_succeeds("curl -fsS 127.0.0.1:8081/health", timeout=60)
        app.succeed("curl -fsS http://10.200.0.2:8081/keys | grep -q keyId")
        app.succeed("nc -z -w3 ${addr.mqtt} 443")

    with subtest("nothing of the broker's is reachable outside wg"):
        for port in (1883, 1884, 8083, 18083, 4370, 5369, 8081):
            app.fail(f"nc -z -w3 ${addr.mqtt} {port}")
        mqtt.fail("nc -z -w3 ${addr.app} 8090")

    def listeners(machine):
        return [l.split()[3] for l in machine.succeed("ss -ltnH").strip().splitlines()]

    def loopback(host):
        return host.startswith("127.") or host.startswith("[::1]")

    with subtest("the broker listens only on loopback, wg, and 443"):
        for a in listeners(mqtt):
            host, port = a.rsplit(":", 1)
            ok = (
                loopback(host)
                or host == "10.200.0.2"
                or port == "443"
                or port == "22"
                or port == "4370"
            )
            assert ok, f"unexpected listener on the broker: {a}"

    with subtest("the app host listens only on loopback, wg:8090, nginx and postgres"):
        for a in listeners(app):
            host, port = a.rsplit(":", 1)
            ok = (
                loopback(host)
                or (host == "10.200.0.1" and port == "8090")
                or port in ("80", "443", "22")
            )
            assert ok, f"unexpected listener on the app host: {a}"

    with subtest("each closure's own health check passes"):
        app.succeed("hqcat-health-check")
        mqtt.succeed("hqcat-health-check")
  '';
}
