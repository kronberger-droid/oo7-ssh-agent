{
  description = "SSH agent bridge backed by org.freedesktop.secrets";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [rust-overlay.overlays.default];
        };

        rustTools = {
          stable = pkgs.rust-bin.stable."1.89.0".default.override {
            extensions = ["rust-src"];
          };
          analyzer = pkgs.rust-bin.stable."1.89.0".rust-analyzer;
        };

        devTools = with pkgs; [
          cargo-expand
          pkg-config
        ];

        # Runtime/build dependencies for D-Bus (required by oo7/zbus)
        dbusDeps = with pkgs; [
          dbus
          dbus.lib
        ];
      in {
        packages = {
          oo7-ssh-agent = pkgs.rustPlatform.buildRustPackage {
            pname = "oo7-ssh-agent";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = with pkgs; [pkg-config];
            buildInputs = dbusDeps;

            doCheck = false;
          };

          default = self.packages.${system}.oo7-ssh-agent;
        };

        devShells.default = pkgs.mkShell {
          name = "oo7-ssh-agent-dev";
          buildInputs =
            [
              rustTools.stable
              rustTools.analyzer
            ]
            ++ devTools
            ++ dbusDeps;

          shellHook = ''
            echo "oo7-ssh-agent dev shell — $(rustc --version)"
            export CARGO_HOME="$HOME/.cargo"
            export RUSTUP_HOME="$HOME/.rustup"
            mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
          '';
        };
      }
    );
}
