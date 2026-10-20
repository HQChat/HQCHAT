# Pulls this host's secret bundle, <cache>/secrets/<environment>/<role>.age
# (published by the Deploy workflow: infra/scripts/publish-secrets.sh), installs
# each entry as a file under hqcat.secretsDir, and restarts the units that read
# a changed file. Entries absent from the bundle are left untouched.
#
# The bucket is public and anyone able to write to it is not trusted: a bundle
# is opened only when <role>.age.sig is a statement signed with the cache key,
# for this environment and role, naming the bundle's SHA-256 and a release no
# older than the last one installed here. It is sealed to the host's age
# post-quantum identity (/etc/hqcat/age-identity, from user data or installed
# by hand), never to a classical key.
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
      gnused
      systemd
      (callPackage ../pkgs/hqcat-verify-signed.nix { })
    ];
    text = ''
      [[ "''${ROLE:-base}" != base ]] || exit 0
      environment=${lib.escapeShellArg cfg.environment.name}
      url="${cfg.environment.cache.url}/secrets/$environment/$ROLE.age"
      identity=/etc/hqcat/age-identity
      state=/var/lib/hqcat-host/secrets-release
      tmp="$(mktemp -d)"
      trap 'rm -rf "$tmp"' EXIT

      code="$(curl -sS --max-time 30 -o "$tmp/bundle.age" -w '%{http_code}' "$url" || echo 000)"
      if [[ "$code" != 200 ]]; then
        echo "no bundle at $url (HTTP $code); secrets unchanged"
        exit 0
      fi
      curl -fsS --max-time 30 -o "$tmp/bundle.sig" "$url.sig" || {
        echo "no signature at $url.sig; secrets unchanged"
        exit 1
      }

      statement="$(sed -n 1p "$tmp/bundle.sig")"
      read -r magic s_env s_role release digest rest <<<"$statement"
      if [[ "$magic" != hqcat-secrets/1 || "$s_env" != "$environment" || "$s_role" != "$ROLE" || -n "$rest" ]] ||
        [[ ! "$release" =~ ^[0-9]{1,15}$ || "$digest" != "$(sha256sum "$tmp/bundle.age" | cut -d' ' -f1)" ]]; then
        echo "the bundle does not match its statement ($statement); secrets unchanged"
        exit 1
      fi
      hqcat-verify-signed ${lib.escapeShellArg cfg.environment.cache.publicKey} "$statement" "$(sed -n 2p "$tmp/bundle.sig")" || {
        echo "the bundle is not signed by the cache key; secrets unchanged"
        exit 1
      }
      installed="$(cat "$state" 2>/dev/null || echo 0)"
      [[ "$installed" =~ ^[0-9]{1,15}$ ]] || installed=0
      if ((10#$release < 10#$installed)); then
        echo "refusing bundle release $release: release $installed is installed here already"
        exit 1
      fi

      [[ -s "$identity" ]] || {
        echo "no age identity at $identity; secrets unchanged (docs/runbooks/deploy.md)"
        exit 1
      }
      umask 077
      age -d -i "$identity" -o "$tmp/bundle.json" "$tmp/bundle.age" || {
        echo "the bundle does not decrypt with this host's age identity"
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

      mkdir -p "$(dirname "$state")"
      printf '%s\n' "$release" >"$state"

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
