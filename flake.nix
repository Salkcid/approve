{
  description = "Rust development environment for approve";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, rust-overlay, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
        in
        f pkgs (pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        }));
    in
    {
      devShells = forSystems (pkgs: rust: {
        default = pkgs.mkShell {
          packages = [ rust pkgs.cargo-mutants pkgs.openssh ];
          # Use the committed hooks; .githooks/pre-commit runs lint, the APPROVE_SSH
          # build's clippy and tests, and mutants.
          shellHook = ''
            git config core.hooksPath .githooks
          '';
        };
      });

      # `nix flake check` enforces formatting, the [lints] table in Cargo.toml,
      # that every viable mutant is caught by the test suite, and that clippy
      # and the tests also pass for a build with APPROVE_SSH set.
      # The crate has no dependencies, so cargo runs offline without vendoring.
      checks = forSystems (pkgs: rust: {
        lint = pkgs.runCommand "approve-lint" { nativeBuildInputs = [ rust ]; } ''
          cp -r ${./.} src && chmod -R u+w src && cd src
          export CARGO_HOME=$TMPDIR/cargo
          cargo fmt --check
          cargo clippy --offline --all-targets --all-features -- -D warnings
          touch $out
        '';
        mutants = pkgs.runCommand "approve-mutants" {
          nativeBuildInputs = [ rust pkgs.cargo-mutants ];
        } ''
          cp -r ${./.} src && chmod -R u+w src && cd src
          export CARGO_HOME=$TMPDIR/cargo
          cargo mutants --no-shuffle --jobs 4
          touch $out
        '';
        # option_env!("APPROVE_SSH") makes this a different build: it enables
        # the parent-executable check, which lint and mutants never compile.
        ssh = pkgs.runCommand "approve-ssh" {
          nativeBuildInputs = [ rust pkgs.openssh ];
          APPROVE_SSH = "${pkgs.openssh}/bin/ssh";
        } ''
          cp -r ${./.} src && chmod -R u+w src && cd src
          export CARGO_HOME=$TMPDIR/cargo
          cargo clippy --offline --all-targets --all-features -- -D warnings
          cargo test --offline
          touch $out
        '';
      });
    };
}
