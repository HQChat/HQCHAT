{
  description = "HQChat: the server package, the NixOS hosts that run it, and the development toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      inherit (nixpkgs) lib;
      hostSystem = "x86_64-linux";
      devSystems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];

      overlay = final: _prev: {
        hqc = final.callPackage ./native/hqc/package.nix { };
        hqcat-server = final.callPackage ./infra/nixos/pkgs/hqcat-server.nix {
          version = self.rev or self.dirtyRev or "dev";
        };
      };
      pkgs = import nixpkgs {
        system = hostSystem;
        overlays = [ overlay ];
      };

      environments = map (lib.removeSuffix ".json") (
        lib.filter (lib.hasSuffix ".json") (lib.attrNames (builtins.readDir ./infra/environments))
      );
      roles = [
        "app"
        "mqtt"
      ];

      mkSystem =
        env: role:
        lib.nixosSystem {
          system = hostSystem;
          modules = [
            { nixpkgs.overlays = [ overlay ]; }
            ./infra/nixos/modules
            ./infra/nixos/admin.nix
            {
              hqcat.environment = lib.importJSON ./infra/environments/${env}.json;
              hqcat.role = role;
              networking.hostName = "hqchat-${env}-${role}";
              system.stateVersion = "26.05";
            }
          ]
          ++ lib.optional (role == "base") ./infra/nixos/modules/image.nix;
        };

      systems = lib.listToAttrs (
        lib.concatMap (
          env:
          map (role: {
            name = "${env}-${role}";
            value = mkSystem env role;
          }) ([ "base" ] ++ roles)
        ) environments
      );

      devShellFor =
        system:
        let
          p = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = pkg: lib.getName pkg == "terraform";
          };
        in
        p.mkShellNoCC {
          # The prepared HQC tree that core/hqc-sys compiles: the same bytes as
          # the Nix library and the Apple builds.
          HQC_SOURCE = (p.callPackage ./native/hqc/package.nix { }).source;
          packages =
            with p;
            [
              rustc
              cargo
              clippy
              rustfmt
              cargo-deny
            ]
            # cc for core/hqc-sys; macOS uses the Xcode toolchain already on PATH.
            ++ lib.optional stdenv.hostPlatform.isLinux gcc
            ++ [
              nodejs_22
              (callPackage ./infra/nixos/pkgs/terraform-bin.nix { })
              tflint
              shellcheck
              shfmt
              actionlint
              biome
              nixfmt
              statix
              deadnix
              jq
              age
              awscli2
              gitleaks
            ];
        };
    in
    {
      nixosConfigurations = systems;

      overlays.default = overlay;

      packages =
        lib.genAttrs devSystems (system: {
          hqc = nixpkgs.legacyPackages.${system}.callPackage ./native/hqc/package.nix { };
        })
        // {
          ${hostSystem} = {
            inherit (pkgs) hqc hqcat-server;
          }
          // lib.listToAttrs (
            lib.concatMap (
              env:
              [
                {
                  name = "image-${env}";
                  value = systems."${env}-base".config.system.build.digitalOceanImage;
                }
              ]
              ++ map (role: {
                name = "toplevel-${env}-${role}";
                value = systems."${env}-${role}".config.system.build.toplevel;
              }) roles
            ) environments
          );
        };

      checks.${hostSystem}.stack = pkgs.testers.runNixOSTest ./infra/nixos/tests/stack.nix;

      devShells = lib.genAttrs devSystems (system: {
        default = devShellFor system;
      });

      formatter = lib.genAttrs devSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
