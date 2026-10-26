# One npm workspace of services/ (server or bot) with services/common, as one
# package; every program is a wrapper running its TypeScript entrypoint through
# tsx (`hqcat-<name>`).
#
# `npm ci --workspace` installs that workspace's dependency tree and nothing
# else, so the server's closure holds none of the bot's packages and the bot's
# none of the server's. Both read the one services/package-lock.json, so they
# share npmDepsHash.
{
  lib,
  buildNpmPackage,
  nodejs_22,
  makeWrapper,
  hqchat-node,
  version,
  pname,
  workspace,
  entrypoints,
  description,
}:
let
  root = ../../../services;
  others = lib.filter (w: w != workspace) [
    "server"
    "bot"
  ];
  optional = path: lib.optional (lib.pathExists path) path;

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions (
      [
        (root + "/package.json")
        (root + "/package-lock.json")
        (root + "/common/package.json")
        (root + "/common/tsconfig.json")
        (root + "/common/src")
        (root + "/${workspace}/package.json")
        (root + "/${workspace}/tsconfig.json")
        (root + "/${workspace}/src")
      ]
      ++ optional (root + "/${workspace}/scripts")
      # npm ci checks the lockfile against every workspace's manifest.
      ++ map (w: root + "/${w}/package.json") others
    );
  };
in
buildNpmPackage {
  inherit pname version src;

  nodejs = nodejs_22;
  npmDepsHash = "sha256-DQVGNhkjSpVJ5xb/SrdVhsRj9Sap4hcGqLH7h+S7tdM=";
  npmInstallFlags = [ "--workspace=${workspace}" ];

  dontNpmBuild = true;

  nativeBuildInputs = [ makeWrapper ];

  # The hook would copy the workspace alone, leaving node_modules/@hqchat/common
  # pointing at a folder it did not copy: the tree goes whole instead.
  installPhase = ''
    runHook preInstall

    npm prune --omit=dev --no-save --workspace=${workspace}
    pkg=$out/lib/hqchat-services
    mkdir -p $pkg $out/bin
    cp -r package.json node_modules common ${workspace} $pkg/
    # Links to the workspaces this package leaves out.
    find $pkg/node_modules -xtype l -delete

    ${lib.concatStrings (
      lib.mapAttrsToList (name: entry: ''
        makeWrapper ${nodejs_22}/bin/node $out/bin/hqcat-${name} \
          --chdir "$pkg/${workspace}" \
          --set-default NODE_ENV production \
          --set-default HQCHAT_NODE "${hqchat-node}/lib/hqchat_node.node" \
          --add-flags "--import tsx $pkg/${workspace}/${entry}"
        test -f "$pkg/${workspace}/${entry}"
      '') entrypoints
    )}

    runHook postInstall
  '';

  passthru = { inherit entrypoints workspace; };

  meta = {
    inherit description;
    license = lib.licenses.agpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "hqcat-${workspace}";
  };
}
