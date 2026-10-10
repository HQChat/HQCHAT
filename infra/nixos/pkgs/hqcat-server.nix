# The HQChat server tree as one package; every program is a wrapper running
# its TypeScript entrypoint through tsx (`hqcat-<name>`).
{
  lib,
  buildNpmPackage,
  nodejs_22,
  makeWrapper,
  hqc,
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
  npmDepsHash = "sha256-JJqT3enuDtBmPbElTp+djOcBu5Wl7qzlQZwHgUmvwZY=";

  dontNpmBuild = true;

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    pkg=$out/lib/node_modules/hqchat-server

    if [ -d "$pkg/node_modules/koffi/build/koffi" ]; then
      find "$pkg/node_modules/koffi/build/koffi" -mindepth 1 -maxdepth 1 -type d \
        ! -name linux_x64 -exec rm -rf {} +
    fi

    mkdir -p $out/bin
    ${lib.concatStrings (
      lib.mapAttrsToList (name: entry: ''
        makeWrapper ${nodejs_22}/bin/node $out/bin/hqcat-${name} \
          --chdir "$pkg" \
          --set-default NODE_ENV production \
          --set-default HQC_LIB "${hqc}/lib/libhqc_wrap.so" \
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
