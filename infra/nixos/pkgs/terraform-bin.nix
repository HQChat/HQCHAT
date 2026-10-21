# Terraform from HashiCorp's release zips, for the dev shell and for Deploy
# (`nix shell .#terraform`), so the binary that holds the cloud credentials
# and the state is the one pinned here by hash. The nixpkgs package is
# unfree, so cache.nixos.org has no binary of it and every fresh store
# compiled it from source: about five minutes per CI run. The release binary
# is static Go, so it needs no patching.
#
# To bump it, check terraform_<version>_SHA256SUMS against its .sig with
# HashiCorp's release key (https://www.hashicorp.com/security), then take each
# zip's hash from it, converted with `nix hash convert --hash-algo sha256 <hex>`.
{
  lib,
  stdenvNoCC,
  fetchurl,
  unzip,
}:
let
  version = "1.15.6";
  platforms = {
    x86_64-linux = {
      os = "linux_amd64";
      hash = "sha256-pxUNOw4bXEZq1C6MSZlUo8VGRfi1azhfoCXTT36I+qk=";
    };
    aarch64-darwin = {
      os = "darwin_arm64";
      hash = "sha256-jUxnkadEMyvHyjlixhqy7Y5dJacpnxdvXt/7nLUl6F8=";
    };
  };
  release =
    platforms.${stdenvNoCC.hostPlatform.system}
      or (throw "terraform-bin: no release pinned for ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "terraform";
  inherit version;
  src = fetchurl {
    url = "https://releases.hashicorp.com/terraform/${version}/terraform_${version}_${release.os}.zip";
    inherit (release) hash;
  };
  nativeBuildInputs = [ unzip ];
  sourceRoot = ".";
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    install -Dm755 terraform $out/bin/terraform
  '';
  doInstallCheck = true;
  installCheckPhase = ''
    $out/bin/terraform version | grep -q "Terraform v${version}"
  '';
  meta = {
    description = "Terraform ${version}, HashiCorp's release binary";
    homepage = "https://www.terraform.io";
    license = lib.licenses.bsl11;
    mainProgram = "terraform";
    platforms = lib.attrNames platforms;
  };
}
