{
  description = "A PIV smartcard as the identity of a Nix build server: remote-builder SSH, git commit signing and binary cache signatures from one card";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  # The VM tests live in ./tests, a separate flake: their inputs (the virtual card, mind-the-gap,
  # Determinate Nix) stay out of the lock files of configurations that use this flake.
  outputs =
    { self, nixpkgs }:
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
        default = nix-piv;
      };
    in
    {
      lib.mkPackages = mkPackages;

      packages = forEachSystem (system: mkPackages nixpkgs.legacyPackages.${system});

      nixosModules = {
        agent = ./modules/agent.nix;
        cache-signer = ./modules/cache-signer.nix;
        default = {
          imports = [
            ./modules/agent.nix
            ./modules/cache-signer.nix
          ];
        };
      };

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
