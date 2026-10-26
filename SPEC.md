# approve v1

A CLI wrapper that lets the user review an agent's explanation and independently
collected execution facts in the existing sudo password dialog.

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

- Reuse the installed `SUDO_ASKPASS` helper and its Zenity password dialog.
- Build a combined context/password prompt and invoke
  `sudo -k -A -p <prompt> -- <command> <arguments...>`.
- Escape literal `%` characters for sudo's prompt substitution rules.
- Use the same command argument array for display and execution. Preserve the
  working directory and standard streams, subject to sudo's normal policy.
- Password submission authorizes the request; sudo verifies the password.
  Cancellation or authentication failure must prevent command execution.
- The wrapper must not collect, store, or log passwords. Return sudo's exit status.
- Do not change global sudo configuration, replace SSH askpass, or add a second
  confirmation dialog. `-k` bypasses cached credentials for this invocation.

## Scope and limits

- Support this laptop's normal user and password-requiring sudo configuration.
  Password-exempt rules and invocation as root are outside v1's approval guarantee:
  sudo may skip askpass in those cases.
- Only requests made through `approve` are covered; enforcing its use is out of scope.
- Display the submitted command, not a claim about sudo's resolved executable or
  the complete behavior of scripts, shells, or mutable files.
- No sudo plugin, custom password GUI, or agent conversation integration in v1.

## Acceptance checks

- The dialog shows the explanation and collected facts together with password entry.
- A valid cached sudo credential does not suppress the dialog for a supported request.
- Cancel prevents a harmless test command from creating its output file; authorization
  allows it, and its exit status and output reach the caller.
- Spaces, quotes, newlines, `%`, and markup-like arguments remain distinguishable
  in the display and reach the command unchanged.
