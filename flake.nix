{
  description = "A PIV smartcard as the identity of a Nix build server: remote-builder SSH, git commit signing and binary cache signatures from one card";

  # Determinate Nix (only used by the tests, to verify ECDSA P-384 cache signatures) comes
  # from its public cache; `nix flake check` needs `--accept-flake-config` for these
  nixConfig = {
    extra-substituters = [ "https://install.determinate.systems" ];
    extra-trusted-public-keys = [ "cache.flakehub.com-3:hJuILl5sVK4iKm86JzgdXW12Y2Hwd5G07qKtHTOcDCM=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    # Test-only inputs below.

    # The trussed piv-authenticator as a virtual card; the feat/version-gating branch makes
    # it behave like the firmware version it reports (4.3.7 = YubiKey 4)
    piv-authenticator = {
      url = "github:FlorianFranzen/piv-authenticator/feat/version-gating";
      flake = false;
    };

    # Provisioning with keys derived from a seed (the piv-yubikey4 branch adds P-384, the
    # 3DES management key and --management-key-touch)
    mind-the-gap.url = "github:FlorianFranzen/mind-the-gap/piv-yubikey4";

    # The only Nix that verifies ECDSA P-384 store path signatures (experimental `cnsa`)
    determinate-nix.url = "https://flakehub.com/f/DeterminateSystems/nix-src/3.23.1.tar.gz";
  };

  outputs =
    {
      self,
      nixpkgs,
      piv-authenticator,
      mind-the-gap,
      determinate-nix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      mkPackages = pkgs: rec {
        nix-piv = pkgs.callPackage ./pkgs/nix-piv.nix { src = ./nix_piv.py; };
        nix-piv-provision = pkgs.callPackage ./pkgs/nix-piv-provision.nix { inherit nix-piv; };
        nix-piv-seal-pin = pkgs.callPackage ./pkgs/nix-piv-seal-pin.nix { };
        piv-vpicc = pkgs.callPackage ./pkgs/piv-vpicc.nix {
          src = piv-authenticator;
          lockFile = ./piv-authenticator.lock;
        };
        default = nix-piv;
      };
    in
    {
      packages = forEachSystem (system: mkPackages nixpkgs.legacyPackages.${system});

      nixosModules = {
        agent = ./modules/agent.nix;
        cache-signer = ./modules/cache-signer.nix;
        # tests only: a virtual PIV card behind pcscd
        virtual-card = ./modules/virtual-card.nix;
        default = {
          imports = [
            ./modules/agent.nix
            ./modules/cache-signer.nix
          ];
        };
      };

      checks = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          nixos-lib = import (pkgs.path + "/nixos/lib") { };
          packages = mkPackages pkgs;
          builderTest =
            variant:
            (nixos-lib.runTest {
              hostPkgs = pkgs;
              imports = [
                (import ./tests/builder.nix {
                  inherit pkgs variant;
                  inherit (packages)
                    piv-vpicc
                    nix-piv
                    nix-piv-provision
                    nix-piv-seal-pin
                    ;
                  determinate = determinate-nix.packages.${system}.default;
                  mind-the-gap = if variant == "mtg" then mind-the-gap.packages.${system}.mind-the-gap else null;
                })
              ];
            }).config.result;
        in
        {
          builder-random = builderTest "random";
          builder-mtg = builderTest "mtg";
        }
        // packages
      );

      devShells = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          packages = mkPackages pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = [
              packages.nix-piv
              packages.nix-piv-provision
              packages.nix-piv-seal-pin
              pkgs.yubikey-manager
              pkgs.opensc
              pkgs.pcsc-tools
            ];
          };
        }
      );
    };
}
