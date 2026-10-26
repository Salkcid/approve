# approve

A CLI wrapper for reviewing an agent's explanation and observed execution facts
together with password entry in a Zenity dialog. See [SPEC.md](SPEC.md) for the
v1 design.

This is a Linux desktop tool for a local user whose sudo policy requires a
password. It needs `sudo`, Zenity, and a graphical session. The approval dialog
shows the submitted arguments and a snapshot of the calling process; it cannot
verify the full behavior of a script or a mutable executable.

The project-local `approve-askpass` adapter uses Zenity's hidden-entry dialog.
Zenity 4.2.2's password dialog ignores `--text`, so it cannot show the review
details. Only the sudo child receives the adapter's `SUDO_ASKPASS`;
global sudo and SSH askpass settings are untouched. The adapter executes Zenity
directly, leaving password handling to Zenity and sudo.

## Install and use

Install both binaries from a checkout with Rust and Cargo available:

```sh
cargo install --locked --path .
approve -d 'Show the current user' -- id
```

The example requests sudo approval. Callers omit `sudo` and pass command
arguments after `--`; an explicit shell is needed for shell syntax. Zenity must
be on `PATH`, or set `APPROVE_ZENITY` to its absolute executable path.

## Development

The development environment uses stable Rust packages from nixpkgs, pinned by
`flake.lock`. Nix supplies `rustc`, `cargo`, `rustfmt`, `clippy`, `rust-analyzer`,
Zenity, and the default compiler/linker support from `pkgs.mkShell`.

With Nix, direnv, and nix-direnv installed, enter the project directory and trust
the reviewed `.envrc` once:

```sh
cd /path/to/approve
direnv allow
```

The shell integration loads the environment automatically. Alternatively, enter
it explicitly with `nix develop`.

Build both binaries before running the CLI; `cargo run` alone does not build
the askpass adapter:

```sh
cargo build --bins
cargo test --offline
cargo fmt --check
cargo clippy --all-targets -- -D warnings
./target/debug/approve -d 'Show the current user' -- id
```

Quoted display values escape control characters, non-ASCII characters, and
invalid UTF-8 bytes. The submitted argument bytes are passed unchanged to sudo.
Prompts wrap at 100 columns and are rejected above a conservative 4096-byte /
40-line budget. The process snapshot includes the caller and up to two ancestors;
origin entries that do not fit are omitted with a notice, preserving the full
request details. These limits still require checking the dialog on the intended
desktop and display scaling.

The automated tests use stand-ins for sudo and Zenity; they require no root
access, GUI interaction, or passwords. They cover argument and stream
preservation, exit status, prompt escaping, size rejection, and adapter
cancellation. Real authentication and dialog layout require manual checks on
the intended desktop, outside sandboxes that set `NoNewPrivs`.

For a harmless manual acceptance check, run from the development shell:

```sh
cargo build --bins
check_dir=$(mktemp -d)
# Choose Cancel: the marker must remain absent.
./target/debug/approve -d 'Test cancellation' -- /bin/sh -c \
  'printf authorized > "$1"; printf "stdout\\n"; printf "stderr\\n" >&2; exit 37' \
  test "$check_dir/marker"
test ! -e "$check_dir/marker"
# Authorize: inspect the facts, then expect output, status 37, and the marker.
./target/debug/approve -d 'Test authorization' -- /bin/sh -c \
  'printf authorized > "$1"; printf "stdout\\n"; printf "stderr\\n" >&2; exit 37' \
  test "$check_dir/marker"
status=$?
test "$status" -eq 37 && test -f "$check_dir/marker"
# Even with cached credentials, this must open the context/password dialog.
sudo -v
./target/debug/approve -d 'Test cached credentials' -- id
# Inspect literal markup, percent signs, quotes, spaces, and escaped newlines.
./target/debug/approve -d 'Test literal values: <b>_reason_</b> %u' -- \
  printf '<%s>\n' 'two words' 'a"quote' 'line
break' '%p%u%%' '<b>_literal_ & text</b>'
```

These approval guarantees cover a normal user with password-requiring sudo.
Root and password-exempt sudo rules may skip askpass. The dialog shows the
submitted command and a process snapshot; it does not establish an application's
identity or describe everything a script may do.

To update the pinned Rust toolchain and other shell dependencies within the
configured stable nixpkgs release:

```sh
nix flake update nixpkgs
direnv reload
```

Review and commit the updated `flake.lock`. To move to another stable nixpkgs
release, change the input branch in `flake.nix`, then run the same update command.
No NixOS rebuild is needed.

## License

MIT. See [LICENSE](LICENSE).
