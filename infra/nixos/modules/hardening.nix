# SSH, fail2ban, kernel sysctls, and the systemd sandbox every hqcat service runs in.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.hqcat;
in
{
  options.hqcat.hardenedService = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    readOnly = true;
    description = "systemd serviceConfig shared by every hqcat service: dynamic user, read-only system, no privileges.";
    default = {
      DynamicUser = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      NoNewPrivileges = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      CapabilityBoundingSet = "";
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
      SystemCallArchitectures = "native";
      SystemCallFilter = [
        "@system-service"
        "~@privileged"
      ];
      ProtectProc = "invisible";
      LimitCORE = 0;
      UMask = "0077";
      Restart = "on-failure";
      RestartSec = 2;
    };
  };

  # The root oneshots that turn fetched or metadata input into host state
  # (secrets, network files, keys, firewall sets) are root because they write
  # root's files, not because they need root's reach: each adds only the paths
  # it writes (ReadWritePaths) and the capabilities it uses.
  options.hqcat.rootService = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    readOnly = true;
    description = "systemd serviceConfig shared by the root setup units: read-only system, no capabilities unless added.";
    default = {
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      NoNewPrivileges = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      ProtectProc = "invisible";
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      CapabilityBoundingSet = "";
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" ];
      LimitCORE = 0;
      UMask = "0077";
    };
  };

  config = {
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "prohibit-password";
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = cfg.admin.totp;
        PermitEmptyPasswords = false;
        X11Forwarding = false;
        MaxAuthTries = 3;
        LoginGraceTime = 30;
        ClientAliveInterval = 300;
        ClientAliveCountMax = 2;
        # Hybrid post-quantum key exchange only (OpenSSH 9.9+ or 9.0+ clients),
        # AES-256-GCM and SHA-512: no classical-only fallback. OpenSSH offers no
        # ML-KEM-1024 or ML-DSA host key, which CNSA 2.0 asks for.
        KexAlgorithms = [
          "mlkem768x25519-sha256"
          "sntrup761x25519-sha512"
          "sntrup761x25519-sha512@openssh.com"
        ];
        Ciphers = [ "aes256-gcm@openssh.com" ];
        Macs = [ "hmac-sha2-512-etm@openssh.com" ];
      };
      hostKeys = [
        {
          path = "/etc/ssh/ssh_host_ed25519_key";
          type = "ed25519";
        }
      ];
      extraConfig = lib.mkMerge [
        "AllowUsers root\n"
        (lib.mkIf cfg.admin.totp "AuthenticationMethods publickey,keyboard-interactive:pam\n")
      ];
    };

    # Only root talks to the nix-daemon: no service user can add store paths
    # or substitute closures through it.
    nix.settings.allowed-users = [ "root" ];

    users.users.root.openssh.authorizedKeys.keys = cfg.admin.sshKeys;
    users.users.root.hashedPassword = "!";
    users.mutableUsers = lib.mkDefault false;

    security.pam.services.sshd.googleAuthenticator.enable = lib.mkIf cfg.admin.totp true;
    environment.systemPackages = [ pkgs.google-authenticator ];

    assertions = [
      {
        assertion = cfg.admin.sshKeys != [ ];
        message = "hqcat.admin.sshKeys is empty: the host would have no way in.";
      }
    ];

    services.resolved.settings.Resolve.LLMNR = "false";

    services.fail2ban = {
      enable = true;
      maxretry = 5;
      bantime = "1h";
      bantime-increment.enable = true;
    };

    system.autoUpgrade.enable = false;

    # An interface takes redirects when either `all` or its own value says so,
    # and new interfaces copy `default`: both are set.
    boot.kernel.sysctl = {
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.secure_redirects" = 0;
      "net.ipv4.conf.default.secure_redirects" = 0;
      "net.ipv6.conf.all.accept_redirects" = 0;
      "net.ipv6.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.send_redirects" = 0;
      "net.ipv4.conf.default.send_redirects" = 0;
      "net.ipv4.conf.all.accept_source_route" = 0;
      "net.ipv4.conf.default.accept_source_route" = 0;
      "net.ipv6.conf.all.accept_source_route" = 0;
      "net.ipv6.conf.default.accept_source_route" = 0;
      "net.ipv4.conf.all.log_martians" = 1;
      "net.ipv4.conf.default.log_martians" = 1;
      "net.ipv4.tcp_syncookies" = 1;
      "kernel.dmesg_restrict" = 1;
      "kernel.kptr_restrict" = 2;
      "kernel.unprivileged_bpf_disabled" = 1;
      "net.core.bpf_jit_harden" = 2;
      "kernel.kexec_load_disabled" = 1;
      "kernel.sysrq" = 0;
      "kernel.yama.ptrace_scope" = 2;
      "fs.suid_dumpable" = 0;
      "fs.protected_fifos" = 2;
      "fs.protected_regular" = 2;
    };

    # A crash of the server, gateway or bot would write its memory (database
    # URL, gateway keys, bot seed, push key) to disc: no core dumps are kept.
    systemd.coredump.settings.Coredump = {
      Storage = "none";
      ProcessSizeMax = 0;
    };

    # Changes to the secrets, SSH's keys and configuration, and the system
    # profile are recorded. The log stays on the host until a sink is chosen.
    security.auditd.enable = true;
    security.audit = {
      enable = true;
      rules = [
        "-w /etc/hqcat -p wa -k hqcat-secrets"
        "-w /etc/ssh -p wa -k sshd"
        "-w /nix/var/nix/profiles -p wa -k system-profile"
        "-w /root/.ssh -p wa -k admin-keys"
      ];
    };

    security.sudo.execWheelOnly = true;
  };
}
