use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "approve-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        fixture.script(
            "zenity",
            "printf '%s\\0' \"$@\" > \"$ZENITY_ARGS\"\nexit 1\n",
        );
        fixture.script(
            "sudo",
            concat!(
                "printf '%s\\0' \"$@\" > \"$SUDO_ARGS\"\n",
                "printf '%s' \"$SUDO_ASKPASS\" > \"$HELPER_PATH\"\n",
                "if [ \"${DENY:-0}\" = 1 ]; then exit 1; fi\n",
                "shift 5\nexec \"$@\"\n"
            ),
        );
        fixture
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.0)
            .env("PATH", &self.0)
            .env("APPROVE_ZENITY", self.0.join("zenity"))
            .env("SUDO_ARGS", self.0.join("sudo-args"))
            .env("ZENITY_ARGS", self.0.join("zenity-args"))
            .env("HELPER_PATH", self.0.join("helper"))
            .env("TARGET_ARGS", self.0.join("target-args"))
            .env("PWD", "/caller-supplied-fake-directory")
            .env("USER", "caller-supplied-fake-user");
        command
    }

    fn args(&self, filename: &str) -> Vec<OsString> {
        let data = fs::read(self.0.join(filename)).unwrap();
        data.strip_suffix(&[0])
            .unwrap()
            .split(|&b| b == 0)
            .map(|s| OsString::from_vec(s.to_vec()))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn preserves_execution_arguments_cwd_streams_and_status() {
    let fixture = Fixture::new();
    let values = vec![
        OsString::from(""),
        OsString::from("two words"),
        OsString::from("'\"\\"),
        OsString::from("line\nbreak"),
        OsString::from("%p%u%%"),
        OsString::from("<b>_literal_ & text</b>"),
        OsString::from_vec(vec![0xff]),
        OsString::from("--help"),
    ];
    let mut command = fixture.command(env!("CARGO_BIN_EXE_approve"));
    command.args(["-d", "test %u <b>_reason_</b>", "--", "/bin/sh", "-c",
        "printf '%s\\0' \"$@\" > \"$TARGET_ARGS\"; IFS= read -r line; printf 'out:%s' \"$line\"; printf 'err' >&2; exit 37", "test"])
        .args(&values).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"input\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"out:input");
    assert_eq!(output.stderr, b"err");
    assert_eq!(fixture.args("target-args"), values);
    let sudo = fixture.args("sudo-args");
    assert_eq!(&sudo[..3], &["-k", "-A", "-p"]);
    let prompt = sudo[3].to_str().unwrap();
    assert!(prompt.contains("%%u"));
    assert!(prompt.contains(&approve::quote(fixture.0.as_os_str())));
    assert!(!prompt.contains("caller-supplied-fake"));
    assert!(prompt.contains("caller PID"));
    assert!(prompt.contains("Run as: root"));
    assert_eq!(sudo[4], "--");
    assert_eq!(sudo[5], "/bin/sh");
    assert_eq!(&sudo[sudo.len() - values.len()..], &values);
    let helper = fs::read_to_string(fixture.0.join("helper")).unwrap();
    assert_eq!(
        Path::new(&helper),
        Path::new(env!("CARGO_BIN_EXE_approve-askpass"))
    );
}

#[test]
fn sudo_failure_is_returned_without_running_the_target() {
    let fixture = Fixture::new();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .env("DENY", "1")
        .args([
            "-d",
            "denied",
            "--",
            "/bin/sh",
            "-c",
            "printf created > marker",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.0.join("marker").exists());
}

#[test]
fn invalid_and_oversized_requests_never_invoke_sudo() {
    let fixture = Fixture::new();
    for args in [
        vec!["-d", "", "--", "id"],
        vec!["-d", "why", "id"],
        vec!["-d", "why", "--"],
    ] {
        let output = fixture
            .command(env!("CARGO_BIN_EXE_approve"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!fixture.0.join("sudo-args").exists());
    }
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .args(["-d", "large", "--", "id", &"x".repeat(5000)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to truncate"));
    assert!(!fixture.0.join("sudo-args").exists());
}

#[test]
fn adapter_escapes_zenity_processing_and_propagates_cancellation() {
    let fixture = Fixture::new();
    let prompt = "Command:\n  \"<b>_text_ & \\n %u</b>\"\nPassword: ";
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .arg(prompt)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let args = fixture.args("zenity-args");
    assert!(args.contains(&OsString::from("--hide-text")));
    assert!(args.contains(&OsString::from("--entry")));
    assert_eq!(
        args.last().unwrap(),
        "--text=Command:\n  \"<b>__text__ & \\\\n %u</b>\"\nPassword: "
    );
}

#[test]
fn complete_adapter_path_cancels_or_executes_without_cli_reading_its_output() {
    let fixture = Fixture::new();
    // This is a protocol stand-in, not a test of real sudo authentication.
    fixture.script(
        "sudo",
        concat!(
            "reply=$(\"$SUDO_ASKPASS\" \"$4\") || exit 1\n",
            "[ \"$reply\" = fixture-authorization ] || exit 1\n",
            "shift 5\nexec \"$@\"\n"
        ),
    );
    let run = || {
        fixture
            .command(env!("CARGO_BIN_EXE_approve"))
            .args([
                "-d",
                "test adapter path",
                "--",
                "/bin/sh",
                "-c",
                "printf created > marker; printf result; exit 18",
            ])
            .output()
            .unwrap()
    };
    let cancelled = run();
    assert_eq!(cancelled.status.code(), Some(1));
    assert!(cancelled.stdout.is_empty());
    assert!(!fixture.0.join("marker").exists());
    fixture.script("zenity", "printf fixture-authorization\n");
    let allowed = run();
    assert_eq!(allowed.status.code(), Some(18));
    assert_eq!(allowed.stdout, b"result");
    assert_eq!(fs::read(fixture.0.join("marker")).unwrap(), b"created");
}

#[test]
fn adapter_rejects_prompts_it_cannot_display() {
    let fixture = Fixture::new();
    for prompt in [
        "bad\u{1b}control".to_string(),
        "é".to_string(),
        "x".repeat(approve::PROMPT_COLUMNS + 1),
        "line\n".repeat(approve::MAX_PROMPT_LINES + 1),
    ] {
        let output = fixture
            .command(env!("CARGO_BIN_EXE_approve-askpass"))
            .arg(prompt)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!fixture.0.join("zenity-args").exists());
    }
}

#[test]
fn quote_distinguishes_raw_bytes_controls_and_literal_escapes() {
    assert_eq!(approve::quote(OsStr::new("")), "\"\"");
    assert_eq!(
        approve::quote(OsStr::new("\n\\n\t\r\"")),
        "\"\\n\\\\n\\t\\r\\\"\""
    );
    assert_eq!(
        approve::quote(OsStr::from_bytes(&[0xff, b'\\', b'x', b'f', b'f'])),
        "\"\\xff\\\\xff\""
    );
    assert_eq!(
        approve::quote(OsStr::new("\u{202e}\u{1b}é")),
        "\"\\u{202e}\\u{1b}\\u{e9}\""
    );
}

#[test]
fn prompt_wraps_without_losing_any_content() {
    let request =
        approve::Request::parse(["-d", "wrap", "--", "echo", &"x".repeat(250)].map(OsString::from))
            .unwrap();
    let facts = approve::Facts {
        cwd: "/test".into(),
        uid: 1000,
        username: None,
        origin: vec!["unavailable".into()],
    };
    let prompt = approve::render_prompt(&request, &facts).unwrap();
    assert!(
        prompt
            .lines()
            .all(|line| line.len() <= approve::PROMPT_COLUMNS)
    );
    assert!(prompt.replace('\n', "").contains(&"x".repeat(250)));
    assert!(prompt.contains("Calling user: unavailable (UID 1000)"));
}
