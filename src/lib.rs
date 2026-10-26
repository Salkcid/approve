use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

pub const USAGE: &str = "Usage: approve -d <description> -- <command> [arguments...]";
// A conservative v1 budget, not a claim about arbitrary helpers or displays.
pub const MAX_PROMPT_BYTES: usize = 4096;
pub const MAX_PROMPT_LINES: usize = 40;
pub const PROMPT_COLUMNS: usize = 100;

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

pub struct Facts {
    pub cwd: PathBuf,
    pub uid: u32,
    pub username: Option<OsString>,
    pub origin: Vec<String>,
}

impl Facts {
    pub fn collect() -> Result<Self, String> {
        let cwd =
            std::env::current_dir().map_err(|e| format!("cannot read working directory: {e}"))?;
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|e| format!("cannot read process identity: {e}"))?;
        let uid = status_number(&status, "Uid:").ok_or("calling UID unavailable")?;
        let username = passwd_name(uid);
        let mut origin = vec![format!(
            "approve PID {}: {}",
            std::process::id(),
            fs::read_link("/proc/self/exe")
                .map(|p| quote(p.as_os_str()))
                .unwrap_or_else(|_| "executable unavailable".into())
        )];
        let mut parent = status_number(&status, "PPid:");
        let mut seen = HashSet::new();
        // Bound observation work; disclose omitted ancestry, never infer identity.
        for depth in 0..16 {
            let Some(pid) = parent else {
                origin.push("parent process information unavailable".into());
                break;
            };
            if pid == 0 {
                origin.push("parent beyond this PID namespace unavailable".into());
                break;
            }
            if !seen.insert(pid) {
                origin.push("remaining ancestry unavailable (process chain changed)".into());
                break;
            }
            let executable = fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| quote(p.as_os_str()))
                .unwrap_or_else(|_| "executable unavailable".into());
            let relation = if depth == 0 { "caller" } else { "ancestor" };
            origin.push(format!("{relation} PID {pid}: {executable}"));
            parent = fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|s| status_number(&s, "PPid:"));
            if depth == 15 {
                origin.push("remaining ancestry unavailable (16-process observation limit)".into());
            }
        }
        Ok(Self {
            cwd,
            uid,
            username,
            origin,
        })
    }
}

// v1 targets this laptop's local accounts. Never use USER/LOGNAME as evidence.
fn passwd_name(uid: u32) -> Option<OsString> {
    let passwd = fs::read("/etc/passwd").ok()?;
    passwd.split(|&b| b == b'\n').find_map(|line| {
        let mut fields = line.split(|&b| b == b':');
        let name = fields.next()?;
        fields.next()?;
        let entry_uid: u32 = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
        (entry_uid == uid).then(|| OsStr::from_bytes(name).to_owned())
    })
}

pub fn render_prompt(request: &Request, facts: &Facts) -> Result<String, String> {
    let command = request
        .command
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(" ");
    let username = facts
        .username
        .as_deref()
        .map(quote)
        .unwrap_or_else(|| "unavailable".into());
    let prompt = format!(
        "Administrator access requested\n\nReason supplied by caller:\n  {}\n\nObserved execution facts:\n\nRequested command (quoted arguments):\n  {}\n\nWorking directory:\n  {}\n\nCalling user: {} (UID {})\nRun as: root\n\nOrigin (process snapshot):\n  {}\n\nDisplay lines wrap. Quoted values use backslash escapes; no shell expansion.\n\nPassword: ",
        quote(&request.description),
        command,
        quote(facts.cwd.as_os_str()),
        username,
        facts.uid,
        facts.origin.join("\n  "),
    );
    if prompt.len() > MAX_PROMPT_BYTES {
        return Err(format!(
            "request needs {} prompt bytes; v1 permits at most {MAX_PROMPT_BYTES}; refusing to truncate",
            prompt.len()
        ));
    }
    let wrapped = prompt
        .lines()
        .flat_map(|line| {
            if line.is_empty() {
                vec![String::new()]
            } else {
                line.as_bytes()
                    .chunks(PROMPT_COLUMNS)
                    .map(|part| String::from_utf8(part.to_vec()).expect("prompt is ASCII"))
                    .collect()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if wrapped.lines().count() > MAX_PROMPT_LINES {
        return Err(format!(
            "request exceeds the {MAX_PROMPT_LINES}-line display budget; refusing to truncate"
        ));
    }
    Ok(wrapped)
}

pub fn find_zenity() -> Result<PathBuf, String> {
    let executable = |path: &PathBuf| {
        fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if let Some(path) = std::env::var_os("APPROVE_ZENITY") {
        let path = PathBuf::from(path);
        if path.is_absolute() && executable(&path) {
            return Ok(path);
        }
        return Err(
            "APPROVE_ZENITY must be an absolute path to an executable Zenity binary".into(),
        );
    }
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("zenity"))
                .find(executable)
        })
        .and_then(|path| fs::canonicalize(path).ok())
        .ok_or_else(|| {
            "zenity is not on PATH; enter nix develop or set APPROVE_ZENITY to its absolute path"
                .into()
        })
}

// Zenity 4.2.2 entry labels apply g_strcompress and GTK mnemonic handling.
// Protect backslashes first and double underscores; markup is plain label text.
pub fn zenity_text(prompt: &str) -> String {
    prompt.replace('\\', "\\\\").replace('_', "__")
}

pub fn sudo_command(request: &Request, prompt: &str) -> Command {
    let mut command = Command::new("sudo");
    command
        .args(["-k", "-A", "-p"])
        .arg(prompt.replace('%', "%%"));
    command.arg("--").args(&request.command);
    command
}
