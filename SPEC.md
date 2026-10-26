# approve v1

A CLI wrapper that lets the user review an agent's explanation and independently
collected execution facts together with password entry in an askpass dialog.

## Interface

```sh
approve -d 'Rebuild NixOS to apply configuration changes' -- \
  nixos-rebuild switch --flake /home/alice/nixos#desktop
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
Ancestry is supporting context: collect the immediate caller and at most two
further ancestors, nearest first. Stop at inaccessible parents or PID namespace
boundaries. Mark an inaccessible executable as unavailable. The bounded snapshot
is not a complete ancestry report. Preserve all collected entries and required
request details; reject the request if they exceed the backend's budget.
Escape control characters and display content literally. Never silently truncate
the command; reject requests that cannot be displayed adequately.

Illustrative combined dialog body (window title: "Administrator access requested";
exact buttons and layout may follow the installed askpass helper). Show the
requested program separately from sudo's prompt transport options:

```text
Reason supplied by caller:
  Rebuild NixOS to apply configuration changes

Command:
  nixos-rebuild switch --flake /home/alice/nixos#desktop

Working directory:
  /home/alice/nixos

Calling user: alice (UID 1000)
Run as: root

Origin:
  [observed PIDs, executable paths, and process chain]

Password: [                              ]

[Cancel]                         [Authorize]
```

## Authorization and execution

- Use a project-local `approve-askpass` adapter, selected through `SUDO_ASKPASS`
  for this sudo invocation only. Resolve the separate askpass v0.1 executable
  from `PATH` or an absolute executable `APPROVE_ASKPASS` override before sudo.
- Invoke `sudo -k -A -p 'Password: ' -- <command> <arguments...>`. Review data
  does not use sudo's prompt substitution mechanism.
- Pass structured `--review` arguments through child-only `APPROVE_REVIEW` as
  length-prefixed UTF-8 fields. Validate the transport and fields in the adapter,
  then execute askpass directly with an argument array and remove the transport
  from the dialog's environment. Never interpret data as shell code.
- Convert display values to reversible ASCII notation without outer quotes:
  `\n`, `\r`, `\t`, `\\`, `\"`, `\u{...}` for control/non-ASCII characters,
  and `\xNN` for invalid UTF-8 bytes. Askpass displays command arguments without
  outer quotes, escapes spaces as `\ ` and backslashes as `\\`, and displays
  empty arguments as `\0`, adding a further display escaping layer to commands.
  The working directory is displayed literally as supplied by approve, with no
  further escaping.
- Reject requests whose option names and values exceed askpass v0.1's 16 KiB
  UTF-8 byte budget. Preserve argument boundaries, including empty arguments and
  values beginning with dashes. The dialog scrolls; no fixed line limit applies.
- Use the same command argument array for display and execution. Preserve the
  working directory and standard streams, subject to sudo's normal policy.
- Password submission authorizes the request; sudo verifies the password.
  Cancellation or authentication failure must prevent command execution.
- The CLI must not collect, store, or log passwords. The adapter replaces itself
  with askpass; password output flows directly from askpass to sudo's askpass pipe.
  Return sudo's exit status.
- Do not change global sudo configuration, replace SSH askpass, or add a second
  confirmation dialog. `-k` bypasses cached credentials for this invocation.

## Scope and limits

- Support a normal local user with password-requiring sudo on Linux.
  Password-exempt rules and invocation as root are outside v1's approval guarantee:
  sudo may skip askpass in those cases.
- Only requests made through `approve` are covered; enforcing its use is out of scope.
- Display the submitted command, not a claim about sudo's resolved executable or
  the complete behavior of scripts, shells, or mutable files.
- No sudo plugin, custom GUI implementation, or agent conversation integration
  in v1. The dialog backend is the separate askpass executable.
- Require `approve-askpass` beside the CLI, askpass v0.1 on `PATH` (or an absolute
  executable path in `APPROVE_ASKPASS`), and a Wayland session. Local usernames
  come from `/etc/passwd`; missing names are reported as unavailable. Ancestry is
  a best-effort Linux `/proc` snapshot limited to the caller plus two ancestors.

## Acceptance checks

- The dialog shows the explanation and collected facts together with password entry.
- A valid cached sudo credential does not suppress the dialog for a supported request.
- Cancel prevents a harmless test command from creating its output file; authorization
  allows it, and its exit status and output reach the caller.
- Spaces, quotes, newlines, `%`, and markup-like arguments remain distinguishable
  in the display and reach the command unchanged.
