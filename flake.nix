{
  description = "approve: review sudo and SSH askpass prompts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
        in
        # Keep in step with rust-version in Cargo.toml. To upgrade, bump both
        # (and `nix flake update rust-overlay` if it lacks the new release).
        f pkgs (pkgs.rust-bin.stable."1.100.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        }));
    in
    {
      # Built with the same toolchain as the dev shell and the checks, so the
      # system gets exactly what was tested. Consumers should not make this
      # input follow their nixpkgs: that swaps in their (possibly older) rustc.
      # Override `expectedSsh` to pin SSH mode to a specific ssh binary.
      packages = forSystems (pkgs: rust: {
        default = pkgs.callPackage ./package.nix {
          rustPlatform = pkgs.makeRustPlatform { cargo = rust; rustc = rust; };
        };
      });

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
        # The derivation consumers install, including its test run.
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
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
