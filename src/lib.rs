use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const USAGE: &str = "Usage: approve -d <description> -- <command> [arguments...]";
// askpass v0.1 counts the UTF-8 bytes of all option names and values.
pub const MAX_REVIEW_BYTES: usize = 16 * 1024;
pub const REVIEW_ENV: &str = "APPROVE_REVIEW";

#[derive(Debug)]
pub struct Request {
    pub description: OsString,
    pub command: Vec<OsString>,
}

impl Request {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter();
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
            description,
            command,
        })
    }
}

// JSON-like quoting is display notation, never input to a shell. ASCII-only
// output also escapes bidi controls, zero-width characters, and invalid UTF-8
// without lossy replacement. \xNN denotes a raw non-UTF-8 byte.
pub fn quote(value: &OsStr) -> String {
    let mut out = String::from("\"");
    for chunk in value.as_bytes().utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                ' '..='~' => out.push(c),
                _ => write!(out, "\\u{{{:x}}}", c as u32).unwrap(),
            }
        }
        for b in chunk.invalid() {
            write!(out, "\\x{b:02x}").unwrap();
        }
    }
    out.push('"');
    out
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

pub struct Origin {
    pub pid: u32,
    pub executable: OsString,
}

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
                .map(|p| p.into_os_string())
                .unwrap_or_else(|_| "executable unavailable".into());
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
    let quoted = quote(value);
    quoted[1..quoted.len() - 1].to_owned()
}

pub fn review_arguments(request: &Request, facts: &Facts) -> Result<Vec<String>, String> {
    let mut args = vec![
        "--review".into(),
        "--reason".into(),
        display_value(&request.description),
    ];
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
            .map(display_value)
            .unwrap_or_else(|| "unavailable".into()),
        "--requesting-uid".into(),
        facts.uid.to_string(),
        "--run-as-user".into(),
        "root".into(),
    ]);
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
        write!(encoded, "{}:{arg}", arg.len()).unwrap();
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
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid review field length".into());
        }
        let length: usize = length.parse().map_err(|_| "invalid review field length")?;
        let value = tail.get(..length).ok_or("invalid review field boundary")?;
        args.push(value.to_owned());
        rest = &tail[length..];
    }
    validate_review(&args)?;
    Ok(args)
}

fn validate_review(args: &[String]) -> Result<(), String> {
    if args.iter().map(String::len).sum::<usize>() > MAX_REVIEW_BYTES {
        return Err("review exceeds askpass's 16 KiB budget; refusing to truncate".into());
    }
    if args.first().map(String::as_str) != Some("--review") || args.len() % 2 != 1 {
        return Err("invalid review arguments".into());
    }
    let mut seen = HashSet::new();
    let mut command_count = 0;
    for pair in args[1..].chunks_exact(2) {
        let option = pair[0].as_str();
        let value = &pair[1];
        match option {
            "--command-arg" => {
                if command_count == 0 && value.is_empty() {
                    return Err("empty executable".into());
                }
                command_count += 1;
            }
            "--origin" => {
                let (pid, executable) = value.split_once(':').ok_or("invalid origin")?;
                if pid.parse::<u32>().ok().filter(|&n| n != 0).is_none()
                    || !pid.bytes().all(|b| b.is_ascii_digit())
                    || executable.is_empty()
                {
                    return Err("invalid origin".into());
                }
            }
            "--reason"
            | "--working-directory"
            | "--requesting-user"
            | "--requesting-uid"
            | "--run-as-user" => {
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
            }
            _ => return Err(format!("unsupported review option: {option}")),
        }
    }
    if seen.len() != 5 || command_count == 0 {
        return Err("incomplete review".into());
    }
    Ok(())
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

pub fn sudo_command(request: &Request) -> Command {
    let mut command = Command::new("sudo");
    command
        .args(["-k", "-A", "-p", "Password: ", "--"])
        .args(&request.command);
    command
}

#[cfg(test)]
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
}
