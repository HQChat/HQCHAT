# The core's Node addon (hqchat-node): lib/hqchat_node.node, which the server,
# the gateway and the bot load through HQCHAT_NODE. HQC is compiled from the
# same prepared tree as every other target (native/hqc), and the build runs
# the HQC known-answer tests before installing.
{
  lib,
  rustPlatform,
  hqc,
}:
let
  root = ../.;
in
rustPlatform.buildRustPackage {
  pname = "hqchat-node";
  version = "0.1.0";

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/hqc-sys")
      (root + "/hqc")
      (root + "/hqchat-protocol/Cargo.toml")
      (root + "/hqchat-protocol/src")
      (root + "/hqchat-engine/Cargo.toml")
      (root + "/hqchat-engine/src")
      (root + "/hqchat-node/Cargo.toml")
      (root + "/hqchat-node/build.rs")
      (root + "/hqchat-node/src")
      # A workspace member: cargo reads its manifest even when not building it.
      (root + "/hqchat-ffi/Cargo.toml")
      (root + "/hqchat-ffi/src")
    ];
  };

  cargoLock.lockFile = root + "/Cargo.lock";

  HQC_SOURCE = hqc.source;

  cargoBuildFlags = [
    "-p"
    "hqchat-node"
  ];
  # The KATs need nothing outside the core; the vector tests read the
  # server's helpers and run in scripts/check.sh core instead.
  cargoTestFlags = [
    "-p"
    "hqc"
    "-p"
    "hqc-sys"
  ];

  # A cdylib, not a binary: install it under the name Node loads.
  installPhase = ''
    runHook preInstall
    lib=$(find target -path '*/release/*' -name 'libhqchat_node.*' \( -name '*.so' -o -name '*.dylib' \) | head -n1)
    test -n "$lib"
    install -Dm444 "$lib" $out/lib/hqchat_node.node
    runHook postInstall
  '';

  meta = {
    description = "The HQChat core for Node: protocol, hqn/1 gateway and Engine";
    license = lib.licenses.agpl3Only;
    platforms = [
      "x86_64-linux"
      "aarch64-darwin"
    ];
  };
}
