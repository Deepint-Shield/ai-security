{
  description = "DeepIntShield's Nix Flake";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/staging-next";
  };

  # Flake outputs
  outputs =
    { self, ... }@inputs:
    let
      # The systems supported for this flake's outputs
      supportedSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper for providing system-specific attributes
      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            # Provides a system-specific, configured Nixpkgs
            pkgs = import inputs.nixpkgs {
              inherit system;
              # Enable using unfree packages
              config.allowUnfree = true;
            };
          }
        );
    in
    {
      nixosModules = {
        deepintshield =
          { pkgs, lib, ... }:
          {
            imports = [ ./nix/modules/deepintshield.nix ];
            services.deepintshield.package = lib.mkDefault self.packages.${pkgs.system}.deepintshield-http;
          };
      };

      packages = forEachSupportedSystem (
        {
          pkgs,
          system,
        }:
        let
          version = "1.4.9";

          deepintshield-ui = pkgs.callPackage ./nix/packages/deepintshield-ui.nix {
            src = self;
            inherit version;
          };
        in
        {
          deepintshield-ui = deepintshield-ui;

          deepintshield-http = pkgs.callPackage ./nix/packages/deepintshield-http.nix {
            inherit inputs;
            src = self;
            inherit version;
            inherit deepintshield-ui;
          };

          default = self.packages.${system}.deepintshield-http;
        }
      );

      apps = forEachSupportedSystem (
        { system, ... }:
        {
          deepintshield-http = {
            type = "app";
            program = "${self.packages.${system}.deepintshield-http}/bin/deepintshield-http";
          };

          default = self.apps.${system}.deepintshield-http;
        }
      );

      # To activate the default environment:
      # nix develop
      # Or if you use direnv:
      # direnv allow
      devShells = forEachSupportedSystem (
        { pkgs, ... }:
        {
          # Run `nix develop` to activate this environment or `direnv allow` if you have direnv installed
          default = import ./nix/devshells/default.nix { inherit pkgs; };
        }
      );
    };
}
