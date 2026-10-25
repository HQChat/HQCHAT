# What distinguishes one host from another: its environment and its role.
{ lib, ... }:
let
  inherit (lib) mkOption types;
in
{
  options.hqcat = {
    role = mkOption {
      type = types.enum [
        "base"
        "app"
        "mqtt"
        "sim"
      ];
      default = "base";
      description = ''
        `base` is the image every droplet first boots: it learns its role from
        user data and switches to that role's closure. `app` runs nginx and the
        services; `mqtt` runs EMQX and the hqn/1 gateway; `sim` runs the sim
        node's synthetic accounts (docs/runbooks/sim.md).
      '';
    };

    environment = mkOption {
      type = types.attrsOf types.anything;
      description = "The deployment environment (infra/environments/<name>.json).";
    };

    secretsDir = mkOption {
      type = types.str;
      readOnly = true;
      default = "/etc/hqcat/secrets";
      description = "Where the secret bundle's entries are installed, one file each.";
    };

    hqn.newConnectionsPerMinute = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "New hqn/1 connections admitted per source address per minute.";
    };

    admin = {
      sshKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Public keys allowed to log in as root; the only way into the machine.";
      };
      totp = lib.mkEnableOption "a TOTP second factor on SSH; enrol with `google-authenticator` before enabling";
    };
  };
}
