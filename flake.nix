{
  description = "SSH agent bridge backed by org.freedesktop.secrets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {self, nixpkgs, ...}: let
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
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          cargo clippy rustc rustfmt rust-analyzer
          pkg-config cargo-expand
          dbus dbus.lib
        ];
        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });
  };
}
