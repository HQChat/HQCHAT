# The server, the hqn/1 gateway and their tools (services/server).
{ callPackage, version }:
callPackage ./hqcat-workspace.nix {
  inherit version;
  pname = "hqcat-server";
  workspace = "server";
  entrypoints = {
    server = "src/server/main.ts";
    noise-gw = "src/gateway/main.ts";
    migrate = "src/server/db/migrate.ts";
    noise-gw-keys = "scripts/noise-gw-keys.ts";
    reports = "scripts/reports.ts";
    check-push = "scripts/check-push.ts";
  };
  description = "HQChat server and hqn/1 gateway";
}
