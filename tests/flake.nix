{
  description = "nix-piv VM tests: a build server whose identity is a YubiKey-4-like PIV card";

  # Determinate Nix (to verify ECDSA P-384 cache signatures) comes from its public cache;
  # run with `--accept-flake-config`
  nixConfig = {
    extra-substituters = [ "https://install.determinate.systems" ];
    extra-trusted-public-keys = [ "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM=" ];
  };

  inputs = {
    nix-piv.url = "path:..";
    nixpkgs.follows = "nix-piv/nixpkgs";

    # The trussed piv-authenticator as a virtual card; feat/version-gating makes it behave
    # like the firmware version it reports (4.3.7 = YubiKey 4)
    piv-authenticator = {
      url = "github:FlorianFranzen/piv-authenticator/feat/version-gating";
      flake = false;
    };

    # Provisioning with keys derived from a seed (P-384, 3DES management key and
    # --management-key-touch are on the piv-certificate-chain branch)
    mind-the-gap.url = "github:gliology/mind-the-gap/piv-certificate-chain";

    # The only Nix that verifies ECDSA P-384 store path signatures (experimental `cnsa`)
    determinate-nix.url = "https://flakehub.com/f/DeterminateSystems/nix-src/3.23.1.tar.gz";
  };

  outputs =
    {
      self,
      nix-piv,
      nixpkgs,
      piv-authenticator,
      mind-the-gap,
      determinate-nix,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      nixos-lib = import (pkgs.path + "/nixos/lib") { };
      packages = nix-piv.lib.mkPackages pkgs;
      piv-vpicc = pkgs.callPackage ./piv-vpicc.nix {
        src = piv-authenticator;
        lockFile = ./piv-authenticator.lock;
      };
      builderTest =
        variant:
        (nixos-lib.runTest {
          hostPkgs = pkgs;
          imports = [
            (import ./builder.nix {
              inherit pkgs variant piv-vpicc;
              inherit (packages) nix-piv nix-piv-provision nix-piv-seal-pin;
              determinate = determinate-nix.packages.${system}.default;
              mind-the-gap = if variant == "mtg" then mind-the-gap.packages.${system}.mind-the-gap else null;
            })
          ];
        }).config.result;
    in
    {
      packages.${system} = { inherit piv-vpicc; };
      checks.${system} = {
        builder-random = builderTest "random";
        builder-mtg = builderTest "mtg";
      };
    };
}
