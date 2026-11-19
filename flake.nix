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
    in
    {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rust = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = [ rust ];
          };
        });
    };
}
