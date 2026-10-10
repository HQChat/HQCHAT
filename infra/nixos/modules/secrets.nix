# Pulls this host's secret bundle, <cache>/secrets/<environment>/<role>.age
# (published by the Deploy workflow, encrypted to the host's SSH key), installs
# each entry as a file under hqcat.secretsDir, and restarts the units that read
# a changed file. Entries absent from the bundle are left untouched.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
  dir = cfg.secretsDir;

  sync = pkgs.writeShellApplication {
    name = "hqcat-secrets-sync";
    runtimeInputs = with pkgs; [
      curl
      age
      jq
      coreutils
      diffutils
      systemd
    ];
    text = ''
      [[ "''${ROLE:-base}" != base ]] || exit 0
      url="${cfg.environment.cache.url}/secrets/${cfg.environment.name}/$ROLE.age"
      tmp="$(mktemp -d)"
      trap 'rm -rf "$tmp"' EXIT

      code="$(curl -sS --max-time 30 -o "$tmp/bundle.age" -w '%{http_code}' "$url" || echo 000)"
      if [[ "$code" != 200 ]]; then
        echo "no bundle at $url (HTTP $code); secrets unchanged"
        exit 0
      fi

      umask 077
      age -d -i /etc/ssh/ssh_host_ed25519_key -o "$tmp/bundle.json" "$tmp/bundle.age" || {
        echo "the bundle does not decrypt with this host's key"
        exit 1
      }

      mkdir -p ${dir}
      changed=0
      while IFS= read -r name; do
        [[ "$name" =~ ^[a-z0-9_]+$ ]] || { echo "skipping unsafe name: $name"; continue; }
        jq -j --arg k "$name" '.[$k]' "$tmp/bundle.json" > "$tmp/value"
        if [[ -f "${dir}/$name" ]] && cmp -s "$tmp/value" "${dir}/$name"; then continue; fi
        install -m 0600 -o root -g root "$tmp/value" "${dir}/$name.new"
        mv -f "${dir}/$name.new" "${dir}/$name"
        echo "updated $name"
        changed=1
      done < <(jq -r 'keys[]' "$tmp/bundle.json")

      if [[ "$changed" == 1 ]]; then
        for unit in ${lib.escapeShellArgs cfg.secretConsumers}; do
          systemctl cat "$unit" >/dev/null 2>&1 && systemctl restart "$unit" || true
        done
      fi
    '';
  };
in
{
  options.hqcat.secretConsumers = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    description = "Units restarted, in order, when the secret bundle changes.";
  };

  config = {
    environment.systemPackages = [ sync ];

    systemd.tmpfiles.rules = [
      "d /etc/hqcat 0700 root root -"
      "d ${dir} 0700 root root -"
    ];

    systemd.services.hqcat-secrets-sync = {
      description = "Fetch and install this host's secrets from the release cache";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      restartIfChanged = false;
      serviceConfig = {
        Type = "oneshot";
        EnvironmentFile = "/run/hqcat/host.env";
        ExecStart = lib.getExe sync;
      };
    };

    systemd.timers.hqcat-secrets-sync = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "2min";
        RandomizedDelaySec = "20s";
        Unit = "hqcat-secrets-sync.service";
      };
    };
  };
}
