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
      UMask = "0077";
      Restart = "on-failure";
      RestartSec = 2;
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

    boot.kernel.sysctl = {
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv6.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.all.send_redirects" = 0;
      "net.ipv4.conf.all.accept_source_route" = 0;
      "net.ipv4.tcp_syncookies" = 1;
      "kernel.dmesg_restrict" = 1;
      "kernel.kptr_restrict" = 2;
    };

    security.sudo.execWheelOnly = true;
  };
}
