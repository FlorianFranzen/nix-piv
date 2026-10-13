# The trussed piv-authenticator as a vpcd virtual smartcard, for the tests. Built from the
# fork's feat/version-gating branch: PIV_VPICC_VERSION=4.3.7 makes it behave like a
# YubiKey 4 (no GET METADATA, 3DES management key only, no Ed25519), PIV_VPICC_STATE_DIR
# keeps its state across restarts.
{ lib, rustPlatform, src, lockFile }:

rustPlatform.buildRustPackage {
  pname = "piv-vpicc";
  version = "0.7.0-version-gating";
  inherit src;

  cargoLock = {
    inherit lockFile;
    allowBuiltinFetchGit = true;
  };
  postPatch = ''
    cp ${lockFile} Cargo.lock
  '';

  nativeBuildInputs = [ rustPlatform.bindgenHook ];
  cargoBuildFlags = [ "--example" "vpicc" ];
  doCheck = false;

  installPhase = ''
    runHook preInstall
    install -Dm755 "$(find target -path '*/release/examples/vpicc' -type f | head -1)" $out/bin/piv-vpicc
    runHook postInstall
  '';

  meta = {
    description = "trussed PIV authenticator as a vpcd virtual smartcard";
    mainProgram = "piv-vpicc";
    license = with lib.licenses; [ asl20 mit ];
  };
}
