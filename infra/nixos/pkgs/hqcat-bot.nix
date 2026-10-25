# The helper bot (services/bot): a client of the server, not part of it.
{ callPackage, version }:
callPackage ./hqcat-workspace.nix {
  inherit version;
  pname = "hqcat-bot";
  workspace = "bot";
  entrypoints.bot = "src/bot.ts";
  description = "HQChat helper bot";
}
