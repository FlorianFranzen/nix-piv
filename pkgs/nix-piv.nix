# The nix-piv CLI: sign Nix store paths with a PIV slot key, print a card's public keys.
{ lib, stdenvNoCC, python3, yubikey-manager, src }:

let
  python = python3.withPackages (_: [ yubikey-manager ]);
in
stdenvNoCC.mkDerivation {
  pname = "nix-piv";
  version = "0.1.0";
  dontUnpack = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 ${src} $out/bin/nix-piv
    sed -i '1s|.*|#!${python}/bin/python3|' $out/bin/nix-piv
    runHook postInstall
  '';

  # `nix` comes from PATH on purpose: it must match the daemon it talks to.
  meta = {
    description = "A PIV smartcard as the identity of a Nix build server";
    mainProgram = "nix-piv";
    license = lib.licenses.mit;
  };
}
