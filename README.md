# approve

A CLI wrapper for reviewing an agent's explanation and observed execution facts
together with password entry in an askpass dialog. See [SPEC.md](SPEC.md) for the
v1 design.

This is a Linux desktop tool for a local user whose sudo policy requires a
password. It needs `sudo`, [askpass v0.1](https://github.com/Salkcid/askpass),
and a Wayland session. The approval dialog shows the submitted arguments and a snapshot of the calling process; it cannot
verify the full behavior of a script or a mutable executable.

The project-local `approve-askpass` adapter executes `askpass --review` with
structured request fields. Only the sudo child receives `SUDO_ASKPASS`,
`APPROVE_ASKPASS`, and a length-prefixed review in `APPROVE_REVIEW`; global sudo
and SSH askpass settings are untouched. The adapter removes the review transport
from the dialog's environment and replaces itself with askpass. Password output
flows directly from askpass into sudo's pipe.

## Install and use

Build askpass separately in its GTK 4 development environment, then install both
approve binaries from this checkout with Rust and Cargo available:

```sh
cd ~/projects/askpass
nix develop -c cargo build --release
cd ~/projects/approve
cargo install --locked --path .
```

Put `askpass` on `PATH`, or set `APPROVE_ASKPASS` to its absolute executable path.
For example, use the sibling checkout directly:

```sh
export APPROVE_ASKPASS="$HOME/projects/askpass/target/release/askpass"
approve -d 'Show the current user' -- id
```

The example requests sudo approval. Callers omit `sudo` and pass command
arguments after `--`; an explicit shell is needed for shell syntax. See askpass’s
README for the optional Niri floating-window rule.

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

Build both binaries before running the CLI; `cargo run` alone does not build
the askpass adapter:

```sh
cargo build --bins
cargo test --offline
cargo fmt --check
cargo clippy --all-targets -- -D warnings
./target/debug/approve -d 'Show the current user' -- id
```

Display values use reversible ASCII notation: backslashes, quotes, control
characters, non-ASCII characters, and invalid UTF-8 bytes are escaped. Askpass
displays command arguments without outer quotes, escapes spaces as `\ ` and
backslashes as `\\`, and displays empty arguments as `\0`. Command arguments
therefore show another layer of backslash escaping. The working directory is
displayed literally as supplied by approve, with no further escaping. The original
command argument bytes are passed unchanged to sudo. Requests exceeding askpass
v0.1's 16 KiB option/value budget are rejected before sudo runs; no values are
truncated. The scrollable dialog replaces the old fixed line and width limits.

The process snapshot includes at most the caller and two ancestors, nearest
first. Collection stops when the parent is unavailable or outside the PID
namespace; inaccessible executable paths are marked unavailable. This is a
bounded snapshot, not a complete ancestry report. All collected entries must fit
the request budget.

The automated tests use stand-ins for sudo and askpass; they require no root
access, GUI interaction, or passwords. They cover structured transport, exact
budget boundaries, argument and stream preservation, exit status, malformed
requests, executable lookup, and cancellation through the adapter. Real
authentication and dialog layout require manual checks in a Wayland session,
outside sandboxes that set `NoNewPrivs`.

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
