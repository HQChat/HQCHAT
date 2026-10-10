# The HQC-256 KEM wrapper (src/low_wrap.c) over the reference implementation at
# the commit pinned in HQC_UPSTREAM.txt: one shared library, libhqc_wrap,
# exporting hqc_kem_{keypair,enc,dec}_wrap. `passthru.source` is the patched
# upstream tree with the wrapper added, which build-apple.sh compiles for the
# Apple targets.
{
  lib,
  stdenv,
  fetchgit,
}:
let
  pin =
    key:
    lib.removePrefix "${key}=" (
      lib.findFirst (lib.hasPrefix "${key}=") (throw "HQC_UPSTREAM.txt has no ${key}") (
        lib.splitString "\n" (builtins.readFile ./HQC_UPSTREAM.txt)
      )
    );
  ext = stdenv.hostPlatform.extensions.sharedLibrary;

  source = stdenv.mkDerivation {
    name = "hqc-source-${builtins.substring 0 7 (pin "PINNED_COMMIT")}";
    src = fetchgit {
      url = pin "REPO";
      rev = pin "PINNED_COMMIT";
      hash = pin "HASH";
    };
    # prepare-source.sh guards the x86 intrinsics headers and adds the wrapper;
    # build-apple.sh runs the same script, so every target compiles these bytes.
    installPhase = ''
      bash ${./prepare-source.sh} . $out ${./src}
    '';
  };

  includes = [
    "src/common"
    "src/common/hqc-5"
    "src/ref"
    "src/ref/hqc-5"
    "lib/fips202"
    "."
  ];
in
stdenv.mkDerivation {
  pname = "hqc";
  version = builtins.substring 0 7 (pin "PINNED_COMMIT");
  src = source;

  buildPhase = ''
    runHook preBuild
    for f in src/common/*.c src/ref/*.c lib/fips202/fips202.c low_wrap.c; do
      $CC -O2 -fPIC -DHQC_ARCH_REF=1 ${lib.concatMapStringsSep " " (i: "-I${i}") includes} \
        -include hqc_portability.h -c "$f" -o "$(basename "$f" .c).o"
    done
    $CC -shared ${lib.optionalString stdenv.hostPlatform.isDarwin "-install_name $out/lib/libhqc_wrap${ext}"} *.o -o libhqc_wrap${ext}
    runHook postBuild
  '';

  doCheck = true;
  checkPhase = ''
    $CC -O2 -I${./include} ${./test/main.c} ./libhqc_wrap${ext} -o selftest
    ${lib.optionalString stdenv.hostPlatform.isDarwin "DYLD_LIBRARY_PATH=$PWD"} ./selftest
  '';

  installPhase = ''
    install -Dm755 libhqc_wrap${ext} $out/lib/libhqc_wrap${ext}
    install -Dm644 ${./include/public_wrapper.h} $out/include/public_wrapper.h
  '';

  passthru = { inherit source; };

  meta = {
    description = "HQC-256 KEM wrapper over the HQC reference implementation";
    license = lib.licenses.mit;
    platforms = lib.platforms.unix;
  };
}
