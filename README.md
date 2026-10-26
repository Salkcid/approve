# approve

A CLI wrapper for reviewing an agent's explanation and observed execution facts
in the existing sudo password dialog. See [SPEC.md](SPEC.md) for the v1 design.

## Development

The development environment uses stable Rust packages from nixpkgs, pinned by
`flake.lock`. Nix supplies `rustc`, `cargo`, `rustfmt`, `clippy`, `rust-analyzer`,
and the default compiler/linker support from `pkgs.mkShell`.

With Nix, direnv, and nix-direnv installed, enter the project directory and trust
the reviewed `.envrc` once:

```sh
cd /path/to/approve
direnv allow
```

The shell integration loads the environment automatically. Alternatively, enter
it explicitly with `nix develop`.

There is no Cargo application yet. Once the binary is implemented, check and run
it from this environment:

```sh
cargo check
cargo fmt --check
cargo clippy
cargo run -- -d 'Show the current user' -- id
```

The run example is the planned CLI interface and will request sudo approval.

To update the pinned Rust toolchain and other shell dependencies within the
configured stable nixpkgs release:

```sh
nix flake update nixpkgs
direnv reload
```

Review and commit the updated `flake.lock`. To move to another stable nixpkgs
release, change the input branch in `flake.nix`, then run the same update command.
No NixOS rebuild is needed.
