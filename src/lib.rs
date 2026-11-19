use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const USAGE: &str = "Usage: approve [--ssh] -d <description> -- <command> [arguments...]";
// askpass v0.1 counts the UTF-8 bytes of all option names and values.
pub const MAX_REVIEW_BYTES: usize = 16 * 1024;
pub const REVIEW_ENV: &str = "APPROVE_REVIEW";
// The ssh executable the Nix package expects to request passphrases. It is
// fixed at build time because the wrapped command controls the runtime
// environment that ssh and the adapter inherit.
pub const EXPECTED_SSH: Option<&str> = option_env!("APPROVE_SSH");

/// How the command obtains authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Run the command as root through `sudo -A`.
    Sudo,
    /// Run the command directly; ssh asks for key passphrases through the adapter.
    Ssh,
}

#[derive(Debug)]
pub struct Request {
    pub mode: Mode,
    pub description: OsString,
    pub command: Vec<OsString>,
}

impl Request {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter().peekable();
        let mode = if args.peek().map(OsString::as_os_str) == Some(OsStr::new("--ssh")) {
            args.next();
            Mode::Ssh
        } else {
            Mode::Sudo
        };
        if args.next().as_deref() != Some(OsStr::new("-d")) {
            return Err("a description must follow -d".into());
        }
        let description = args.next().ok_or("missing description")?;
        if description.as_bytes().is_empty()
            || description.as_bytes().iter().all(u8::is_ascii_whitespace)
        {
            return Err("description must not be empty or whitespace-only".into());
        }
        if args.next().as_deref() != Some(OsStr::new("--")) {
            return Err("expected -- before the command".into());
        }
        let command: Vec<_> = args.collect();
        if command.first().is_none_or(|s| s.is_empty()) {
            return Err("missing command after --".into());
        }
        Ok(Self {
            mode,
            description,
            command,
        })
    }
}

// JSON-like quoting is display notation, never input to a shell. ASCII-only
// output also escapes bidi controls, zero-width characters, and invalid UTF-8
// without lossy replacement. \xNN denotes a raw non-UTF-8 byte.
#[must_use]
pub fn quote(value: &OsStr) -> String {
    let mut out = String::from("\"");
    push_escaped(&mut out, value);
    out.push('"');
    out
}

// Writing to a String cannot fail, so the fmt::Result is discarded.
fn push_escaped(out: &mut String, value: &OsStr) {
    for chunk in value.as_bytes().utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                ' '..='~' => out.push(c),
                _ => _ = write!(out, "\\u{{{:x}}}", c as u32),
            }
        }
        for b in chunk.invalid() {
            _ = write!(out, "\\x{b:02x}");
        }
    }
}

fn status_number(status: &str, key: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

#[derive(Debug)]
pub struct Origin {
    pub pid: u32,
    pub executable: OsString,
}

#[derive(Debug)]
pub struct Facts {
    pub cwd: PathBuf,
    pub uid: u32,
    pub username: Option<OsString>,
    pub origin: Vec<Origin>,
}

impl Facts {
    pub fn collect() -> Result<Self, String> {
        let cwd =
            std::env::current_dir().map_err(|e| format!("cannot read working directory: {e}"))?;
        Self::collect_from(cwd, Path::new("/proc"), Path::new("/etc/passwd"))
    }

    // Keep filesystem inputs explicit so snapshots can be tested without changing
    // process-wide environment or relying on the host's ancestry and accounts.
    fn collect_from(cwd: PathBuf, proc: &Path, passwd: &Path) -> Result<Self, String> {
        let status = fs::read_to_string(proc.join("self/status"))
            .map_err(|e| format!("cannot read process identity: {e}"))?;
        let uid = status_number(&status, "Uid:").ok_or("calling UID unavailable")?;
        let username = passwd_name(uid, passwd);
        let mut origin = Vec::new();
        let mut parent = status_number(&status, "PPid:");
        let mut seen = HashSet::new();
        // Observe the caller and at most two ancestors. Missing executables are
        // explicit; an unavailable parent ends this best-effort snapshot.
        for _ in 0..3 {
            let Some(pid) = parent.filter(|&pid| pid != 0) else {
                break;
            };
            if !seen.insert(pid) {
                break;
            }
            let executable = fs::read_link(proc.join(format!("{pid}/exe")))
                .map_or_else(|_| "executable unavailable".into(), PathBuf::into_os_string);
            origin.push(Origin { pid, executable });
            parent = fs::read_to_string(proc.join(format!("{pid}/status")))
                .ok()
                .and_then(|s| status_number(&s, "PPid:"));
        }
        Ok(Self {
            cwd,
            uid,
            username,
            origin,
        })
    }
}

// v1 reads local accounts. Never use USER/LOGNAME as evidence.
fn passwd_name(uid: u32, path: &Path) -> Option<OsString> {
    let passwd = fs::read(path).ok()?;
    passwd.split(|&b| b == b'\n').find_map(|line| {
        let mut fields = line.split(|&b| b == b':');
        let name = fields.next()?;
        fields.next()?;
        let entry_uid: u32 = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
        (entry_uid == uid).then(|| OsStr::from_bytes(name).to_owned())
    })
}

// Every value uses the same reversible ASCII notation, without outer quotes.
// askpass further escapes command arguments; it displays the cwd literally.
fn display_value(value: &OsStr) -> String {
    let mut out = String::new();
    push_escaped(&mut out, value);
    out
}

pub fn review_arguments(request: &Request, facts: &Facts) -> Result<Vec<String>, String> {
    let mut args = vec!["--review".into()];
    // askpass v0.2 defaults to sudo; naming only ssh keeps sudo requests
    // compatible with askpass v0.1.
    if request.mode == Mode::Ssh {
        args.extend(["--kind".into(), "ssh".into()]);
    }
    args.extend(["--reason".into(), display_value(&request.description)]);
    for argument in &request.command {
        args.extend(["--command-arg".into(), display_value(argument)]);
    }
    args.extend([
        "--working-directory".into(),
        display_value(facts.cwd.as_os_str()),
        "--requesting-user".into(),
        facts
            .username
            .as_deref()
            .map_or_else(|| "unavailable".into(), display_value),
        "--requesting-uid".into(),
        facts.uid.to_string(),
    ]);
    // An ssh-mode command keeps the caller's identity, so there is no target user.
    if request.mode == Mode::Sudo {
        args.extend(["--run-as-user".into(), "root".into()]);
    }
    for origin in &facts.origin {
        args.extend([
            "--origin".into(),
            format!("{}:{}", origin.pid, display_value(&origin.executable)),
        ]);
    }
    validate_review(&args)?;
    Ok(args)
}

// Length-prefixed UTF-8 fields preserve empty arguments and all delimiters.
// No shell, file, or password is involved in this transport.
pub fn encode_review(args: &[String]) -> Result<String, String> {
    validate_review(args)?;
    let mut encoded = String::new();
    for arg in args {
        _ = write!(encoded, "{}:{arg}", arg.len());
    }
    Ok(encoded)
}

pub fn decode_review(encoded: &str) -> Result<Vec<String>, String> {
    // At most one length prefix per option/value byte, plus the --review field.
    if encoded.len() > MAX_REVIEW_BYTES * 3 {
        return Err("review transport is too large".into());
    }
    let mut rest = encoded;
    let mut args = Vec::new();
    while !rest.is_empty() {
        let (length, tail) = rest.split_once(':').ok_or("invalid review transport")?;
        // parse() also accepts a leading '+'; an empty length fails parse() below.
        if !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid review field length".into());
        }
        let length: usize = length.parse().map_err(|_| "invalid review field length")?;
        let (value, tail) = tail
            .split_at_checked(length)
            .ok_or("invalid review field boundary")?;
        args.push(value.to_owned());
        rest = tail;
    }
    validate_review(&args)?;
    Ok(args)
}

fn valid_process(value: &str) -> bool {
    value.split_once(':').is_some_and(|(pid, executable)| {
        pid.bytes().all(|b| b.is_ascii_digit())
            && pid.parse::<u32>().is_ok_and(|n| n != 0)
            && !executable.is_empty()
    })
}

fn validate_review(args: &[String]) -> Result<(), String> {
    if args.iter().map(String::len).sum::<usize>() > MAX_REVIEW_BYTES {
        return Err("review exceeds askpass's 16 KiB budget; refusing to truncate".into());
    }
    let fields = match args.split_first() {
        Some((first, fields)) if first == "--review" && fields.len() % 2 == 0 => fields,
        _ => return Err("invalid review arguments".into()),
    };
    let mut seen = HashSet::new();
    let mut has_command = false;
    let mut kind = "sudo";
    let (pairs, _) = fields.as_chunks::<2>();
    for [option, value] in pairs {
        let option = option.as_str();
        match option {
            "--command-arg" => {
                if !has_command && value.is_empty() {
                    return Err("empty executable".into());
                }
                has_command = true;
            }
            "--origin" => {
                if !valid_process(value) {
                    return Err("invalid origin".into());
                }
            }
            "--reason"
            | "--working-directory"
            | "--requesting-user"
            | "--requesting-uid"
            | "--run-as-user"
            | "--kind"
            | "--prompt"
            | "--prompt-process" => {
                if !seen.insert(option)
                    || value.is_empty()
                    || (option == "--reason" && value.trim().is_empty())
                {
                    return Err(format!("missing or duplicate value for {option}"));
                }
                if option == "--requesting-uid"
                    && (!value.bytes().all(|b| b.is_ascii_digit()) || value.parse::<u32>().is_err())
                {
                    return Err("invalid requesting UID".into());
                }
                if option == "--run-as-user" && value != "root" {
                    return Err("run-as user must be root".into());
                }
                if option == "--kind" {
                    kind = match value.as_str() {
                        "sudo" => "sudo",
                        "ssh" => "ssh",
                        _ => return Err("kind must be sudo or ssh".into()),
                    };
                }
                if option == "--prompt-process" && !valid_process(value) {
                    return Err("invalid prompt process".into());
                }
            }
            _ => return Err(format!("unsupported review option: {option}")),
        }
    }
    let required = [
        "--reason",
        "--working-directory",
        "--requesting-user",
        "--requesting-uid",
    ];
    if !has_command || required.iter().any(|option| !seen.contains(option)) {
        return Err("incomplete review".into());
    }
    let prompt = seen.contains("--prompt");
    if prompt != seen.contains("--prompt-process") {
        return Err("prompt and prompt process must be supplied together".into());
    }
    match kind {
        "ssh" if seen.contains("--run-as-user") => {
            Err("run-as user does not apply to ssh requests".into())
        }
        "sudo" if prompt => Err("prompt fields require an ssh request".into()),
        "sudo" if !seen.contains("--run-as-user") => Err("incomplete review".into()),
        _ => Ok(()),
    }
}

#[must_use]
pub fn is_ssh_review(args: &[String]) -> bool {
    args.get(1..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .any(|pair| pair == &["--kind", "ssh"])
}

/// Add the per-call prompt facts to an ssh review. ssh may run the adapter
/// several times in one session, so each call builds its own copy.
pub fn ssh_prompt_review(
    mut args: Vec<String>,
    prompt: &OsStr,
    process: &Origin,
) -> Result<Vec<String>, String> {
    if !is_ssh_review(&args) {
        return Err("prompt fields require an ssh request".into());
    }
    if prompt.is_empty() {
        return Err("ssh supplied an empty prompt".into());
    }
    args.extend([
        "--prompt".into(),
        display_value(prompt),
        "--prompt-process".into(),
        format!("{}:{}", process.pid, display_value(&process.executable)),
    ]);
    validate_review(&args)?;
    Ok(args)
}

/// Interpret ssh's `SSH_ASKPASS_PROMPT` hint. askpass only collects a secret,
/// so confirmation and notification prompts are refused instead of answered.
pub fn check_ssh_prompt_hint(hint: Option<&OsStr>) -> Result<(), String> {
    let Some(hint) = hint else {
        return Ok(());
    };
    match hint.as_bytes() {
        b"" => Ok(()),
        b"confirm" => Err(
            "ssh requested a yes/no confirmation (SSH_ASKPASS_PROMPT=confirm); approve only answers passphrase prompts, so the request is refused".into(),
        ),
        b"none" => Err(
            "ssh requested a notification without input (SSH_ASKPASS_PROMPT=none); approve only answers passphrase prompts, so the request is refused".into(),
        ),
        _ => Err(format!(
            "unsupported SSH_ASKPASS_PROMPT value {}",
            quote(hint)
        )),
    }
}

/// Identify the process that will read the adapter's output.
///
/// In ssh mode the passphrase goes to this parent, so its executable is read
/// from `/proc` (not from the environment) and, when `expected` is fixed, must
/// match it exactly.
pub fn prompt_process(proc: &Path, expected: Option<&Path>) -> Result<Origin, String> {
    let status = fs::read_to_string(proc.join("self/status"))
        .map_err(|e| format!("cannot read process identity: {e}"))?;
    let pid = status_number(&status, "PPid:")
        .filter(|&pid| pid != 0)
        .ok_or("cannot identify the process requesting the passphrase")?;
    let executable = fs::read_link(proc.join(format!("{pid}/exe"))).map_err(|e| {
        format!("cannot read the executable of prompting process {pid}; refusing: {e}")
    })?;
    if let Some(expected) = expected {
        // Canonicalize the build-time path so a profile symlink names its target.
        let expected = fs::canonicalize(expected).unwrap_or_else(|_| expected.to_owned());
        if executable != expected {
            return Err(format!(
                "refusing passphrase prompt from {} (PID {pid}); expected {}",
                quote(executable.as_os_str()),
                quote(expected.as_os_str())
            ));
        }
    }
    Ok(Origin {
        pid,
        executable: executable.into_os_string(),
    })
}

pub fn find_askpass() -> Result<PathBuf, String> {
    let executable = |path: &PathBuf| {
        fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if let Some(path) = std::env::var_os("APPROVE_ASKPASS") {
        let path = PathBuf::from(path);
        if path.is_absolute() && executable(&path) {
            return Ok(path);
        }
        return Err(
            "APPROVE_ASKPASS must be an absolute path to an executable askpass binary".into(),
        );
    }
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("askpass"))
                .find(executable)
        })
        .and_then(|path| fs::canonicalize(path).ok())
        .ok_or_else(|| "askpass is not on PATH; install askpass v0.1 or set APPROVE_ASKPASS to its absolute path".into())
}

/// Build the command that replaces approve. Only this child receives the
/// askpass selection and the review transport.
#[must_use]
pub fn launch_command(request: &Request, helper: &Path, askpass: &Path, review: &str) -> Command {
    let mut command = match request.mode {
        Mode::Sudo => {
            let mut command = Command::new("sudo");
            command
                .args(["-k", "-A", "-p", "Password: ", "--"])
                .args(&request.command)
                .env("SUDO_ASKPASS", helper);
            command
        }
        Mode::Ssh => {
            // Request::parse rejects an empty command; if one is built by
            // hand anyway, executing "" fails instead of panicking.
            let (program, args) = request
                .command
                .split_first()
                .map_or_default(|(program, args)| (program.as_os_str(), args));
            let mut command = Command::new(program);
            command
                .args(args)
                .env("SSH_ASKPASS", helper)
                // Use the dialog with or without a terminal or display variable.
                .env("SSH_ASKPASS_REQUIRE", "force");
            command
        }
    };
    command
        .env("APPROVE_ASKPASS", askpass)
        .env(REVIEW_ENV, review);
    command
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests fail loudly on unexpected values"
)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Snapshot(PathBuf);

    impl Snapshot {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "approve-snapshot-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join("self")).unwrap();
            fs::write(path.join("self/status"), "Uid:\t1000\t0\t0\t0\nPPid:\t10\n").unwrap();
            fs::write(
                path.join("passwd"),
                b"malformed\nwrong:x:nope:\nother:x:2000:\nalice:x:1000:1000::/:/bin/sh\n",
            )
            .unwrap();
            Self(path)
        }

        fn process(&self, pid: u32, parent: &str, executable: Option<&str>) {
            let dir = self.0.join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("status"), format!("PPid:\t{parent}\n")).unwrap();
            if let Some(executable) = executable {
                symlink(executable, dir.join("exe")).unwrap();
            }
        }

        fn collect(&self) -> Result<Facts, String> {
            Facts::collect_from("/observed/cwd".into(), &self.0, &self.0.join("passwd"))
        }
    }

    impl Drop for Snapshot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn collects_real_uid_local_name_and_three_nearest_ancestors() {
        let snapshot = Snapshot::new();
        for (pid, parent, exe) in [
            (10, "20", "/caller"),
            (20, "30", "/parent"),
            (30, "40", "/grandparent"),
            (40, "0", "/excluded"),
        ] {
            snapshot.process(pid, parent, Some(exe));
        }
        let facts = snapshot.collect().unwrap();
        assert_eq!(facts.cwd, PathBuf::from("/observed/cwd"));
        assert_eq!(facts.uid, 1000); // The first UID, not the effective UID.
        assert_eq!(facts.username.as_deref(), Some(OsStr::new("alice")));
        let origins: Vec<_> = facts
            .origin
            .iter()
            .map(|o| (o.pid, o.executable.as_os_str()))
            .collect();
        assert_eq!(
            origins,
            vec![
                (10, OsStr::new("/caller")),
                (20, OsStr::new("/parent")),
                (30, OsStr::new("/grandparent"))
            ]
        );
    }

    #[test]
    fn ancestry_stops_at_namespace_boundaries_bad_parents_and_cycles() {
        for parent in ["0", "invalid", "", "10"] {
            let snapshot = Snapshot::new();
            snapshot.process(10, parent, None);
            let facts = snapshot.collect().unwrap();
            assert_eq!(facts.origin.len(), 1, "parent {parent:?}");
            assert_eq!(facts.origin[0].pid, 10);
            assert_eq!(facts.origin[0].executable, "executable unavailable");
        }
        let snapshot = Snapshot::new();
        // Missing parent status and exe still produce an explicit caller entry.
        let facts = snapshot.collect().unwrap();
        assert_eq!(facts.origin.len(), 1);
        assert_eq!(facts.origin[0].executable, "executable unavailable");
        fs::write(snapshot.0.join("self/status"), "Uid: 1000\nPPid: 0\n").unwrap();
        assert!(snapshot.collect().unwrap().origin.is_empty());
    }

    #[test]
    fn missing_accounts_and_unreadable_identity_are_handled() {
        let snapshot = Snapshot::new();
        fs::write(snapshot.0.join("passwd"), "other:x:2000:\n").unwrap();
        assert!(snapshot.collect().unwrap().username.is_none());
        fs::remove_file(snapshot.0.join("passwd")).unwrap();
        assert!(snapshot.collect().unwrap().username.is_none());
        for status in ["PPid: 10\n", "Uid: invalid\n", "Uid: 4294967296\n"] {
            fs::write(snapshot.0.join("self/status"), status).unwrap();
            assert_eq!(snapshot.collect().err().unwrap(), "calling UID unavailable");
        }
        fs::remove_file(snapshot.0.join("self/status")).unwrap();
        assert!(
            snapshot
                .collect()
                .err()
                .unwrap()
                .contains("cannot read process identity")
        );
    }

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_ssh_mode_only_as_the_leading_option() {
        let sudo = Request::parse(os(&["-d", "why", "--", "id"])).unwrap();
        assert_eq!(sudo.mode, Mode::Sudo);
        let ssh = Request::parse(os(&["--ssh", "-d", "why", "--", "git", "push"])).unwrap();
        assert_eq!(ssh.mode, Mode::Ssh);
        assert_eq!(ssh.description, "why");
        assert_eq!(ssh.command, os(&["git", "push"]));
        // After -- it is part of the command, not a mode switch.
        let literal = Request::parse(os(&["-d", "why", "--", "--ssh"])).unwrap();
        assert_eq!(
            (literal.mode, literal.command),
            (Mode::Sudo, os(&["--ssh"]))
        );
        for args in [
            os(&["--ssh"]),
            os(&["--ssh", "--ssh", "-d", "why", "--", "id"]),
            os(&["-d", "why", "--ssh", "--", "id"]),
            os(&["--ssh", "-d", "why", "--"]),
            os(&["--ssh", "-d", " ", "--", "id"]),
        ] {
            assert!(Request::parse(args.clone()).is_err(), "{args:?}");
        }
    }

    fn envs(command: &Command) -> Vec<(String, Option<String>)> {
        let mut envs: Vec<_> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        envs.sort();
        envs
    }

    #[test]
    fn launch_environment_is_scoped_to_the_selected_mode() {
        let helper = Path::new("/libexec/approve-askpass");
        let askpass = Path::new("/bin/askpass");
        let mut request = Request::parse(os(&["-d", "why", "--", "git", "", "-v"])).unwrap();
        let sudo = launch_command(&request, helper, askpass, "8:--review");
        assert_eq!(sudo.get_program(), "sudo");
        let args: Vec<_> = sudo.get_args().collect();
        assert_eq!(
            args,
            ["-k", "-A", "-p", "Password: ", "--", "git", "", "-v"]
        );
        let expected = |askpass_var: &str| {
            let mut expected = vec![
                ("APPROVE_ASKPASS".into(), Some("/bin/askpass".into())),
                (REVIEW_ENV.into(), Some("8:--review".into())),
                (askpass_var.into(), Some("/libexec/approve-askpass".into())),
            ];
            if askpass_var == "SSH_ASKPASS" {
                expected.push(("SSH_ASKPASS_REQUIRE".into(), Some("force".into())));
            }
            expected.sort();
            expected
        };
        assert_eq!(envs(&sudo), expected("SUDO_ASKPASS"));

        request.mode = Mode::Ssh;
        let ssh = launch_command(&request, helper, askpass, "8:--review");
        // The command runs directly as the caller; sudo is not involved.
        assert_eq!(ssh.get_program(), "git");
        let args: Vec<_> = ssh.get_args().collect();
        assert_eq!(args, ["", "-v"]);
        assert_eq!(envs(&ssh), expected("SSH_ASKPASS"));
    }

    fn sample_facts() -> Facts {
        Facts {
            cwd: "/repo".into(),
            uid: 1000,
            username: Some("alice".into()),
            origin: vec![Origin {
                pid: 12,
                executable: "/bin/sh".into(),
            }],
        }
    }

    #[test]
    fn ssh_review_names_its_kind_and_omits_the_target_user() {
        let request = Request::parse(os(&["--ssh", "-d", "Push", "--", "git", "push"])).unwrap();
        let review = review_arguments(&request, &sample_facts()).unwrap();
        assert_eq!(
            review,
            [
                "--review",
                "--kind",
                "ssh",
                "--reason",
                "Push",
                "--command-arg",
                "git",
                "--command-arg",
                "push",
                "--working-directory",
                "/repo",
                "--requesting-user",
                "alice",
                "--requesting-uid",
                "1000",
                "--origin",
                "12:/bin/sh",
            ]
        );
        assert!(is_ssh_review(&review));
        let sudo = Request::parse(os(&["-d", "Push", "--", "id"])).unwrap();
        let sudo = review_arguments(&sudo, &sample_facts()).unwrap();
        assert!(!is_ssh_review(&sudo));
        assert!(!sudo.contains(&"--kind".into()));
        assert_eq!(
            &sudo[sudo.len() - 4..sudo.len() - 2],
            ["--run-as-user", "root"]
        );
    }

    #[test]
    fn each_prompt_call_adds_its_own_escaped_prompt_and_process() {
        let request = Request::parse(os(&["--ssh", "-d", "Push", "--", "git", "push"])).unwrap();
        let review = review_arguments(&request, &sample_facts()).unwrap();
        let process = Origin {
            pid: 77,
            executable: "/nix/store/x-openssh/bin/ssh".into(),
        };
        let first = ssh_prompt_review(
            review.clone(),
            OsStr::new("Enter passphrase for key '/home/alice/.ssh/id_rsa': "),
            &process,
        )
        .unwrap();
        assert_eq!(
            &first[review.len()..],
            [
                "--prompt",
                "Enter passphrase for key '/home/alice/.ssh/id_rsa': ",
                "--prompt-process",
                "77:/nix/store/x-openssh/bin/ssh",
            ]
        );
        // A second call (another key, or a retry) starts from the same transport.
        let prompt = OsStr::from_bytes(b"Key '\xff\n\x1b[31m\"\\':");
        let second = ssh_prompt_review(review.clone(), prompt, &process).unwrap();
        assert_eq!(second[review.len() + 1], r#"Key '\xff\n\u{1b}[31m\"\\':"#);
        assert_eq!(
            decode_review(&encode_review(&second).unwrap()).unwrap(),
            second
        );
        // A transport cannot pre-seed prompt fields for the adapter to display.
        let seeded = ssh_prompt_review(first, OsStr::new("again"), &process);
        assert!(seeded.unwrap_err().contains("duplicate"));
        assert!(
            ssh_prompt_review(review.clone(), OsStr::new(""), &process)
                .unwrap_err()
                .contains("empty prompt")
        );
        let sudo = Request::parse(os(&["-d", "x", "--", "id"])).unwrap();
        let sudo = review_arguments(&sudo, &sample_facts()).unwrap();
        assert!(
            ssh_prompt_review(sudo, OsStr::new("Password: "), &process)
                .unwrap_err()
                .contains("require an ssh request")
        );
        let mut full = review;
        let room = MAX_REVIEW_BYTES - full.iter().map(String::len).sum::<usize>();
        full[4].push_str(&"x".repeat(room));
        assert!(
            ssh_prompt_review(full, OsStr::new("Passphrase: "), &process)
                .unwrap_err()
                .contains("refusing to truncate")
        );
    }

    #[test]
    fn review_kind_rules_are_validated() {
        let request = Request::parse(os(&["--ssh", "-d", "Push", "--", "git"])).unwrap();
        let ssh = review_arguments(&request, &sample_facts()).unwrap();
        let with = |base: &[String], extra: &[&str]| {
            let mut args = base.to_vec();
            args.extend(extra.iter().map(ToString::to_string));
            encode_review(&args)
        };
        assert!(
            with(&ssh, &["--run-as-user", "root"])
                .unwrap_err()
                .contains("does not apply")
        );
        assert!(
            with(&ssh, &["--kind", "ssh"])
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            with(&ssh, &["--prompt", "p"])
                .unwrap_err()
                .contains("together")
        );
        assert!(
            with(&ssh, &["--prompt-process", "1:/ssh"])
                .unwrap_err()
                .contains("together")
        );
        for process in ["0:/ssh", "1:", "x:/ssh", "+1:/ssh"] {
            let error = with(&ssh, &["--prompt", "p", "--prompt-process", process]).unwrap_err();
            assert_eq!(error, "invalid prompt process", "{process}");
        }
        let mut other = ssh.clone();
        other[2] = "gpg".into();
        assert_eq!(
            encode_review(&other).unwrap_err(),
            "kind must be sudo or ssh"
        );
        let sudo = Request::parse(os(&["-d", "x", "--", "id"])).unwrap();
        let sudo = review_arguments(&sudo, &sample_facts()).unwrap();
        assert!(with(&sudo, &["--kind", "sudo"]).is_ok());
        let prompted = with(&sudo, &["--prompt", "p", "--prompt-process", "1:/ssh"]);
        assert!(prompted.unwrap_err().contains("require an ssh request"));
        let mut explicit_sudo = ssh;
        explicit_sudo[2] = "sudo".into();
        assert_eq!(
            encode_review(&explicit_sudo).unwrap_err(),
            "incomplete review"
        );
    }

    #[test]
    fn prompt_hint_allows_only_passphrase_prompts() {
        assert!(check_ssh_prompt_hint(None).is_ok());
        assert!(check_ssh_prompt_hint(Some(OsStr::new(""))).is_ok());
        for (hint, message) in [
            ("confirm", "SSH_ASKPASS_PROMPT=confirm"),
            ("none", "SSH_ASKPASS_PROMPT=none"),
            (
                "other\n",
                "unsupported SSH_ASKPASS_PROMPT value \"other\\n\"",
            ),
        ] {
            let error = check_ssh_prompt_hint(Some(OsStr::new(hint))).unwrap_err();
            assert!(error.contains(message), "{error}");
        }
    }

    #[test]
    fn prompt_process_reads_the_parent_exe_and_enforces_the_build_path() {
        let snapshot = Snapshot::new();
        snapshot.process(10, "1", Some("/nix/store/x-openssh/bin/ssh"));
        let process = prompt_process(&snapshot.0, None).unwrap();
        assert_eq!(process.pid, 10);
        assert_eq!(process.executable, "/nix/store/x-openssh/bin/ssh");
        let expected = Path::new("/nix/store/x-openssh/bin/ssh");
        assert_eq!(prompt_process(&snapshot.0, Some(expected)).unwrap().pid, 10);
        // A build-time symlink is compared by its target.
        let link = snapshot.0.join("ssh-link");
        let target = snapshot.0.join("real-ssh");
        fs::write(&target, "").unwrap();
        symlink(&target, &link).unwrap();
        let other = Snapshot::new();
        other.process(10, "1", Some(target.to_str().unwrap()));
        assert_eq!(
            prompt_process(&other.0, Some(&link)).unwrap().executable,
            target
        );

        let error = prompt_process(&snapshot.0, Some(Path::new("/usr/bin/ssh"))).unwrap_err();
        assert!(error.contains("refusing passphrase prompt from"), "{error}");
        assert!(error.contains("PID 10"), "{error}");
        for fake in ["/tmp/bin/ssh", "/nix/store/x-openssh/bin/ssh (deleted)"] {
            let snapshot = Snapshot::new();
            snapshot.process(10, "1", Some(fake));
            assert!(
                prompt_process(&snapshot.0, Some(expected)).is_err(),
                "{fake}"
            );
            assert_eq!(prompt_process(&snapshot.0, None).unwrap().executable, fake);
        }
        // Without a readable parent executable, nothing is shown or sent.
        let snapshot = Snapshot::new();
        snapshot.process(10, "1", None);
        let error = prompt_process(&snapshot.0, None).unwrap_err();
        assert!(error.contains("cannot read the executable"), "{error}");
        for status in ["Uid: 1000\nPPid: 0\n", "Uid: 1000\n"] {
            fs::write(snapshot.0.join("self/status"), status).unwrap();
            let error = prompt_process(&snapshot.0, None).unwrap_err();
            assert!(error.contains("cannot identify"), "{error}");
        }
    }
}
