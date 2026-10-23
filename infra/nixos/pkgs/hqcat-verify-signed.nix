# hqcat-verify-signed: checks a statement the release pipeline signed with the
# cache key (../hqcat-verify-signed.sh).
{
  writeShellApplication,
  openssl,
  coreutils,
}:
writeShellApplication {
  name = "hqcat-verify-signed";
  runtimeInputs = [
    openssl
    coreutils
  ];
  text = builtins.readFile ../hqcat-verify-signed.sh;
}
