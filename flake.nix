{
  description = "SSH agent bridge backed by org.freedesktop.secrets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {self, nixpkgs, fenix, ...}: let
    forAllSystems = nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-linux"];
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      oo7-ssh-agent = pkgs.rustPlatform.buildRustPackage {
        pname = "oo7-ssh-agent";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [pkgs.pkg-config];
        buildInputs = [pkgs.dbus pkgs.dbus.lib];
        doCheck = false;
      };
      default = self.packages.${system}.oo7-ssh-agent;
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.stable.withComponents [
        "cargo" "clippy" "rust-src" "rustc" "rustfmt"
      ];
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = [
          toolchain
          fenix.packages.${system}.rust-analyzer
          pkgs.pkg-config
          pkgs.cargo-expand
          pkgs.dbus
          pkgs.dbus.lib
        ];
      };
    });
  };
}
