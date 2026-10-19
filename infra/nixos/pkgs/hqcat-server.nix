# The HQChat server tree as one package; every program is a wrapper running
# its TypeScript entrypoint through tsx (`hqcat-<name>`).
{
  lib,
  buildNpmPackage,
  nodejs_22,
  makeWrapper,
  hqchat-node,
  version,
}:
let
  root = ../../../services/server;

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/package.json")
      (root + "/package-lock.json")
      (root + "/tsconfig.json")
      (root + "/src")
      (root + "/scripts")
    ];
  };

  entrypoints = {
    server = "src/server/main.ts";
    bot = "src/bot/bot.ts";
    noise-gw = "src/gateway/main.ts";
    migrate = "src/server/db/migrate.ts";
    noise-gw-keys = "scripts/noise-gw-keys.ts";
    reports = "scripts/reports.ts";
    check-push = "scripts/check-push.ts";
  };
in
buildNpmPackage {
  pname = "hqcat-server";
  inherit version;
  inherit src;

  nodejs = nodejs_22;
  npmDepsHash = "sha256-VjOWGJQH7E2cLRz5jI4Vb01b855R/xzDSNK+F9zx09A=";

  dontNpmBuild = true;

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    pkg=$out/lib/node_modules/hqchat-server

    mkdir -p $out/bin
    ${lib.concatStrings (
      lib.mapAttrsToList (name: entry: ''
        makeWrapper ${nodejs_22}/bin/node $out/bin/hqcat-${name} \
          --chdir "$pkg" \
          --set-default NODE_ENV production \
          --set-default HQCHAT_NODE "${hqchat-node}/lib/hqchat_node.node" \
          --add-flags "--import tsx $pkg/${entry}"
        test -f "$pkg/${entry}"
      '') entrypoints
    )}
  '';

  passthru = { inherit entrypoints; };

  meta = {
    description = "HQChat server, helper bot and hqn/1 gateway";
    license = lib.licenses.agpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "hqcat-server";
  };
}
