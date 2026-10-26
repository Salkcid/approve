# approve v1

A CLI wrapper that lets the user review an agent's explanation and independently
collected execution facts together with password entry in a Zenity dialog.

## Interface

```sh
approve -d 'Rebuild NixOS to reduce Waybar height' -- \
  nixos-rebuild switch --flake /home/qy1n/nixos#laptop
```

- Require a nonempty description and a command after `--`.
- Run the command as root through sudo; callers omit `sudo`.
- Accept an argument array, not a shell command string. Do not use `eval` or
  implicitly invoke a shell. Explicit shell invocations remain possible.

## Dialog content

Clearly separate **caller-provided explanation** from **observed facts**:

- Requested command, preserving argument boundaries through readable quoting.
- Working directory obtained from the process, not `$PWD`.
- Calling user's UID and username; requested target user (`root`).
- Caller PID, executable path, and process ancestry where accessible.

Do not accept caller-supplied origin labels as facts. Mark inaccessible or missing
ancestry information as unavailable; do not infer an application identity.
Ancestry is supporting context: show the immediate caller and at most two further
ancestors, nearest first. Omit whole origin entries when necessary to fit the
dialog and explicitly disclose omissions. Preserve the full explanation,
command, working directory, and calling user; reject if those required details
and the omission notice cannot fit.
Escape control characters and display content literally. Never silently truncate
the command; reject requests that cannot be displayed adequately.

Illustrative combined dialog (exact title, buttons, and layout may follow the
installed askpass helper). Show the requested program separately from sudo's
prompt transport options:

```text
Administrator access requested

Reason supplied by caller:
  Rebuild NixOS to reduce Waybar height

Command:
  nixos-rebuild switch --flake /home/qy1n/nixos#laptop

Working directory:
  /home/qy1n/nixos

Calling user: qy1n (UID 1000)
Run as: root

Origin:
  [observed PIDs, executable paths, and process chain]

Password: [                              ]

[Cancel]                         [Authorize]
```

## Authorization and execution

- Use a project-local `approve-askpass` adapter, selected through `SUDO_ASKPASS`
  for this sudo invocation only. The adapter executes Zenity's hidden-entry
  dialog with the context and password field together. The installed Zenity
  4.2.2 `--password` dialog ignores `--text`, so the installed helper cannot
  provide the required context display.
- Build a combined context/password prompt and invoke
  `sudo -k -A -p <prompt> -- <command> <arguments...>`.
- Escape literal `%` characters for sudo's prompt substitution rules.
- Protect backslashes and underscores from Zenity's escape and mnemonic
  processing. Its hidden-entry label displays markup-like text literally.
- Quote values with ASCII display notation: `\n`, `\r`, `\t`, `\\`, `\"`,
  `\u{...}` for other control and non-ASCII characters, and `\xNN` for invalid
  UTF-8 bytes. Wrap display lines at 100 columns and reject prompts over 4096
  bytes before wrapping or 40 lines after wrapping; never truncate values.
- Use the same command argument array for display and execution. Preserve the
  working directory and standard streams, subject to sudo's normal policy.
- Password submission authorizes the request; sudo verifies the password.
  Cancellation or authentication failure must prevent command execution.
- The CLI must not collect, store, or log passwords. The adapter replaces itself
  with Zenity; password output flows directly from Zenity to sudo's askpass pipe.
  Return sudo's exit status.
- Do not change global sudo configuration, replace SSH askpass, or add a second
  confirmation dialog. `-k` bypasses cached credentials for this invocation.

## Scope and limits

- Support this laptop's normal user and password-requiring sudo configuration.
  Password-exempt rules and invocation as root are outside v1's approval guarantee:
  sudo may skip askpass in those cases.
- Only requests made through `approve` are covered; enforcing its use is out of scope.
- Display the submitted command, not a claim about sudo's resolved executable or
  the complete behavior of scripts, shells, or mutable files.
- No sudo plugin, custom GUI implementation, or agent conversation integration
  in v1. The adapter uses the existing Zenity hidden-entry dialog.
- Require `approve-askpass` beside the CLI and Zenity on `PATH` (or an absolute
  executable path in `APPROVE_ZENITY`). Local usernames come from `/etc/passwd`;
  missing names are reported as unavailable. Ancestry is a best-effort Linux
  `/proc` snapshot, limited to the caller plus two ancestors with any remaining
  chain disclosed. Origin details also share the remaining display budget.

## Acceptance checks

- The dialog shows the explanation and collected facts together with password entry.
- A valid cached sudo credential does not suppress the dialog for a supported request.
- Cancel prevents a harmless test command from creating its output file; authorization
  allows it, and its exit status and output reach the caller.
- Spaces, quotes, newlines, `%`, and markup-like arguments remain distinguishable
  in the display and reach the command unchanged.
