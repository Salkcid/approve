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
            "askpass",
            concat!(
                "[ \"${APPROVE_REVIEW+x}\" != x ] || exit 99\n",
                "printf '%s\\0' \"$@\" > \"$ASKPASS_ARGS\"\nexit 1\n"
            ),
        );
        fixture.script(
            "sudo",
            concat!(
                "printf '%s\\0' \"$@\" > \"$SUDO_ARGS\"\n",
                "printf '%s' \"$SUDO_ASKPASS\" > \"$HELPER_PATH\"\n",
                "if [ \"${DENY:-0}\" = 1 ]; then exit 1; fi\n",
                "printf '%s' \"$APPROVE_REVIEW\" > review\n",
                "shift 5\nexec \"$@\"\n"
            ),
        );
        // `prompt <text>` asks $SSH_ASKPASS for one passphrase from a process
        // this build accepts as ssh and prints the reply, as ssh would read it.
        match approve::EXPECTED_SSH {
            None => fixture.script("prompt", "exec \"$SSH_ASKPASS\" \"$1\"\n"),
            Some(ssh) => {
                let out = sh_quote(&fixture.0.join("prompt-out").to_string_lossy());
                let config = fixture.ssh_launcher(
                    "prompt-launch",
                    &format!("exec \"$SSH_ASKPASS\" \"$PROMPT_TEXT\" > {out}\n"),
                );
                fixture.script(
                    "prompt",
                    &format!(
                        concat!(
                            "case $(PROMPT_TEXT=$1 {} -G -F {} approve-test 2>/dev/null) in\n",
                            "  *'hostname accepted'*) ;;\n  *) exit 1 ;;\nesac\n",
                            "IFS= read -r reply < {out}\nprintf '%s\\n' \"$reply\"\n"
                        ),
                        sh_quote(ssh),
                        sh_quote(&config.to_string_lossy()),
                        out = out,
                    ),
                );
            }
        }
        fixture
    }

    /// Write the script `name` and an ssh config whose `Match exec` runs it.
    /// `ssh -G` evaluates that while resolving configuration, without
    /// connecting, and the script replaces the shell, so the process it
    /// becomes is a direct child of ssh. Success shows as `hostname accepted`.
    fn ssh_launcher(&self, name: &str, body: &str) -> PathBuf {
        self.script(name, body);
        let config = self.0.join(format!("{name}.ssh-config"));
        let launcher = self.0.join(name);
        fs::write(
            &config,
            format!(
                "Match exec \"exec {}\"\n  Hostname accepted\n",
                launcher.display()
            ),
        )
        .unwrap();
        config
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
            .env("APPROVE_ASKPASS", self.0.join("askpass"))
            .env("SUDO_ARGS", self.0.join("sudo-args"))
            .env("ASKPASS_ARGS", self.0.join("askpass-args"))
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

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct AdapterRun {
    /// The adapter's exit code, when it is observable.
    code: Option<i32>,
    success: bool,
    stdout: Vec<u8>,
    stderr: String,
    /// The `--prompt-process` value the adapter should report.
    parent: String,
}

/// Run the adapter as the child of a parent this build accepts. Without
/// APPROVE_SSH any parent is accepted, so this test process runs it. With it,
/// only the build-time ssh is, so that ssh launches the adapter (see
/// `Fixture::ssh_launcher`); ssh then reveals only success or failure.
fn run_adapter(fixture: &Fixture, transport: &str, prompts: &[&str]) -> AdapterRun {
    let adapter = env!("CARGO_BIN_EXE_approve-askpass");
    let Some(ssh) = approve::EXPECTED_SSH else {
        let output = fixture
            .command(adapter)
            .env(approve::REVIEW_ENV, transport)
            .args(prompts)
            .output()
            .unwrap();
        return AdapterRun {
            code: output.status.code(),
            success: output.status.success(),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            parent: format!(
                "{}:{}",
                std::process::id(),
                std::env::current_exe().unwrap().display()
            ),
        };
    };
    let (out, err) = (fixture.0.join("adapter-out"), fixture.0.join("adapter-err"));
    let words: Vec<_> = [adapter]
        .iter()
        .chain(prompts)
        .map(|w| sh_quote(w))
        .collect();
    let config = fixture.ssh_launcher(
        "adapter-launch",
        &format!(
            "exec {} > {} 2> {}\n",
            words.join(" "),
            sh_quote(&out.to_string_lossy()),
            sh_quote(&err.to_string_lossy())
        ),
    );
    let child = fixture
        .command(ssh)
        .arg("-G")
        .arg("-F")
        .arg(&config)
        .arg("approve-test")
        .env(approve::REVIEW_ENV, transport)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    AdapterRun {
        code: None,
        success: String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "hostname accepted"),
        stdout: fs::read(&out).unwrap(),
        stderr: fs::read_to_string(&err).unwrap(),
        parent: format!("{pid}:{}", fs::canonicalize(ssh).unwrap().display()),
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
    assert_eq!(sudo[3], "Password: ");
    let review =
        approve::decode_review(&fs::read_to_string(fixture.0.join("review")).unwrap()).unwrap();
    assert!(review.contains(&"test %u <b>_reason_</b>".into()));
    assert!(review.contains(&fixture.0.to_str().unwrap().to_owned()));
    assert!(
        !review
            .iter()
            .any(|value| value.contains("caller-supplied-fake"))
    );
    assert!(review.contains(&"--origin".into()));
    assert!(review.contains(&"root".into()));
    assert_eq!(sudo[4], "--");
    assert_eq!(sudo[5], "/bin/sh");
    let displayed_command: Vec<_> = review[1..]
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|[option, _]| option == "--command-arg")
        .map(|[_, value]| value.clone())
        .collect();
    let expected_command: Vec<_> = sudo[5..]
        .iter()
        .map(|arg| {
            let quoted = approve::quote(arg);
            quoted[1..quoted.len() - 1].to_owned()
        })
        .collect();
    assert_eq!(displayed_command, expected_command);
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
        vec![],
        vec!["--unknown"],
        vec!["-d"],
        vec!["-d", "", "--", "id"],
        vec!["-d", " \t\n", "--", "id"],
        vec!["-d", "why", "--", ""],
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
        .args(["-d", "large", "--", "id", &"x".repeat(17000)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to truncate"));
    assert!(!fixture.0.join("sudo-args").exists());
}

#[test]
fn adapter_passes_structured_values_and_propagates_cancellation() {
    let fixture = Fixture::new();
    let review = sample_review();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .env(
            approve::REVIEW_ENV,
            approve::encode_review(&review).unwrap(),
        )
        .arg("ignored sudo prompt %u")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fixture.args("askpass-args"),
        review.iter().map(OsString::from).collect::<Vec<_>>()
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
    fixture.script(
        "askpass",
        concat!(
            "[ \"${APPROVE_REVIEW+x}\" != x ] || exit 99\n",
            "printf 'fixture-authorization\\n'\n"
        ),
    );
    let allowed = run();
    assert_eq!(allowed.status.code(), Some(18));
    assert_eq!(allowed.stdout, b"result");
    assert_eq!(fs::read(fixture.0.join("marker")).unwrap(), b"created");
}

#[test]
fn adapter_rejects_missing_malformed_and_oversized_transport() {
    let fixture = Fixture::new();
    for encoded in [
        None,
        Some("".into()),
        Some("99:short".into()),
        Some("1:é".into()),
        Some("0:".repeat(25000)),
        Some("8:--review".into()),
    ] {
        let mut command = fixture.command(env!("CARGO_BIN_EXE_approve-askpass"));
        command.env_remove(approve::REVIEW_ENV).arg("Password: ");
        if let Some(encoded) = encoded {
            command.env(approve::REVIEW_ENV, encoded);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!fixture.0.join("askpass-args").exists());
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

fn sample_review() -> Vec<String> {
    [
        "--review",
        "--reason",
        "Review <b>_literal_</b> %u",
        "--command-arg",
        "echo",
        "--command-arg",
        "",
        "--command-arg",
        "--help",
        "--command-arg",
        "line\nbreak:é",
        "--working-directory",
        "/test",
        "--requesting-user",
        "local-user",
        "--requesting-uid",
        "1000",
        "--run-as-user",
        "root",
        "--origin",
        "12:/bin/sh",
    ]
    .map(String::from)
    .to_vec()
}

#[test]
fn transport_preserves_empty_values_delimiters_and_unicode() {
    let args = sample_review();
    assert_eq!(
        approve::decode_review(&approve::encode_review(&args).unwrap()).unwrap(),
        args
    );
    for pair in [
        ["--unknown", "x"],
        ["--reason", "duplicate"],
        ["--origin", "0:/bad"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(pair.map(String::from));
        assert!(approve::encode_review(&invalid).is_err());
    }
}

#[test]
fn review_preserves_request_details_and_structured_origins_without_wrapping() {
    let request = approve::Request::parse([
        OsString::from("-d"),
        OsString::from("Review this request"),
        OsString::from("--"),
        OsString::from("echo"),
        OsString::from(""),
        OsString::from("x".repeat(5000)),
        OsString::from_vec(vec![0xff]),
        OsString::from("\\xff"),
    ])
    .unwrap();
    let facts = approve::Facts {
        cwd: "/test".into(),
        uid: 1000,
        username: None,
        origin: vec![approve::Origin {
            pid: 12,
            executable: "/bin/sh:with:colons".into(),
        }],
    };
    let args = approve::review_arguments(&request, &facts).unwrap();
    assert!(args.contains(&"x".repeat(5000)));
    assert!(args.contains(&"12:/bin/sh:with:colons".into()));
    assert!(args.contains(&"unavailable".into()));
    assert!(args.contains(&r"\xff".into()));
    assert!(args.contains(&r"\\xff".into()));
    assert_eq!(
        approve::decode_review(&approve::encode_review(&args).unwrap()).unwrap(),
        args
    );
}

#[test]
fn budget_matches_askpass_option_and_value_bytes() {
    let mut args = sample_review();
    let size = args.iter().map(String::len).sum::<usize>();
    args[2].push_str(&"x".repeat(approve::MAX_REVIEW_BYTES - size));
    assert!(approve::encode_review(&args).is_ok());
    args[2].push('x');
    assert!(
        approve::encode_review(&args)
            .unwrap_err()
            .contains("refusing to truncate")
    );
}

#[test]
fn executable_lookup_supports_path_and_rejects_invalid_override() {
    let fixture = Fixture::new();
    let run = |override_path: Option<&Path>| {
        let mut command = fixture.command(env!("CARGO_BIN_EXE_approve"));
        command
            .env_remove("APPROVE_ASKPASS")
            .args(["-d", "test", "--", "/bin/sh", "-c", "exit 0"]);
        if let Some(path) = override_path {
            command.env("APPROVE_ASKPASS", path);
        }
        command.output().unwrap()
    };
    assert!(run(None).status.success());
    for path in [Path::new("relative"), Path::new("/missing/askpass")] {
        let output = run(Some(path));
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("APPROVE_ASKPASS"));
    }
}

// Deliberately bypass the production encoder to exercise adapter-side validation.
fn unchecked_transport(args: &[String]) -> String {
    args.iter()
        .map(|value| format!("{}:{value}", value.len()))
        .collect()
}

fn assert_adapter_rejects(fixture: &Fixture, transport: &OsStr, prompts: &[&str], message: &str) {
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .env(approve::REVIEW_ENV, transport)
        .args(prompts)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{output:?}"
    );
    assert!(!fixture.0.join("askpass-args").exists());
}

#[test]
fn adapter_validates_all_required_fields_before_launching_askpass() {
    let fixture = Fixture::new();
    let valid = sample_review();
    for option in [
        "--reason",
        "--working-directory",
        "--requesting-user",
        "--requesting-uid",
        "--run-as-user",
    ] {
        let index = valid.iter().position(|s| s == option).unwrap();
        let mut missing = valid.clone();
        missing.drain(index..index + 2);
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&unchecked_transport(&missing)),
            &["Password: "],
            "incomplete review",
        );
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid[index..index + 2]);
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&unchecked_transport(&duplicate)),
            &["Password: "],
            "duplicate value",
        );
        let mut empty = valid.clone();
        empty[index + 1].clear();
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&unchecked_transport(&empty)),
            &["Password: "],
            "missing or duplicate",
        );
    }
    for (option, value, error) in [
        ("--reason", " \t\n", "missing or duplicate"),
        ("--command-arg", "", "empty executable"),
        ("--requesting-uid", "-1", "invalid requesting UID"),
        ("--requesting-uid", "+1", "invalid requesting UID"),
        ("--requesting-uid", "4294967296", "invalid requesting UID"),
        ("--requesting-uid", "abc", "invalid requesting UID"),
        ("--run-as-user", "alice", "run-as user must be root"),
        ("--origin", "12", "invalid origin"),
        ("--origin", "0:/bin/sh", "invalid origin"),
        ("--origin", "-1:/bin/sh", "invalid origin"),
        ("--origin", "+1:/bin/sh", "invalid origin"),
        ("--origin", "4294967296:/bin/sh", "invalid origin"),
        ("--origin", "12:", "invalid origin"),
    ] {
        let mut args = valid.clone();
        let index = args.iter().position(|s| s == option).unwrap();
        args[index + 1] = value.into();
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&unchecked_transport(&args)),
            &["Password: "],
            error,
        );
    }
    let mut no_command = valid.clone();
    let mut index = 1;
    while index < no_command.len() {
        if no_command[index] == "--command-arg" {
            no_command.drain(index..index + 2);
        } else {
            index += 2;
        }
    }
    assert_adapter_rejects(
        &fixture,
        OsStr::new(&unchecked_transport(&no_command)),
        &["Password: "],
        "incomplete review",
    );
    let mut unknown = valid.clone();
    unknown.extend(["--unknown".into(), "value".into()]);
    assert_adapter_rejects(
        &fixture,
        OsStr::new(&unchecked_transport(&unknown)),
        &["Password: "],
        "unsupported review option",
    );
    let mut oversized = valid;
    oversized[2] = "x".repeat(approve::MAX_REVIEW_BYTES);
    assert_adapter_rejects(
        &fixture,
        OsStr::new(&unchecked_transport(&oversized)),
        &["Password: "],
        "refusing to truncate",
    );
}

#[test]
fn adapter_rejects_invalid_framing_non_utf8_and_wrong_prompt_count() {
    let fixture = Fixture::new();
    for encoded in [
        "missing-colon",
        ":x",
        "-1:x",
        "+1:x",
        "x:y",
        "999999999999999999999999999999:x",
        "8:--review1:x",
    ] {
        assert_adapter_rejects(
            &fixture,
            OsStr::new(encoded),
            &["Password: "],
            "invalid review",
        );
    }
    assert_adapter_rejects(
        &fixture,
        OsStr::from_bytes(&[0xff]),
        &["Password: "],
        "non-UTF-8",
    );
    assert_adapter_rejects(
        &fixture,
        OsStr::new("8:--review0:0:"),
        &["Password: "],
        "unsupported review option",
    );
    let valid = unchecked_transport(&sample_review());
    for prompts in [vec![], vec!["one", "two"]] {
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&valid),
            &prompts,
            "expected one prompt argument",
        );
    }
}

#[test]
fn review_has_exact_ordered_fields_and_reversible_display_values() {
    let request = approve::Request {
        mode: approve::Mode::Sudo,
        description: "reason\n\"é".into(),
        command: vec![
            "echo".into(),
            "".into(),
            "two words".into(),
            "--help".into(),
            "\n\r\t\"\\".into(),
            OsString::from_vec(vec![0xff]),
            "\\xff".into(),
        ],
    };
    let facts = approve::Facts {
        cwd: "/test\n\\é".into(),
        uid: 1000,
        username: Some("al\tice".into()),
        origin: vec![
            approve::Origin {
                pid: 12,
                executable: "/bin/sh:with:colons".into(),
            },
            approve::Origin {
                pid: 13,
                executable: "executable unavailable".into(),
            },
        ],
    };
    let expected: Vec<String> = [
        "--review",
        "--reason",
        r#"reason\n\"\u{e9}"#,
        "--command-arg",
        "echo",
        "--command-arg",
        "",
        "--command-arg",
        "two words",
        "--command-arg",
        "--help",
        "--command-arg",
        r#"\n\r\t\"\\"#,
        "--command-arg",
        r"\xff",
        "--command-arg",
        r"\\xff",
        "--working-directory",
        r"/test\n\\\u{e9}",
        "--requesting-user",
        r"al\tice",
        "--requesting-uid",
        "1000",
        "--run-as-user",
        "root",
        "--origin",
        "12:/bin/sh:with:colons",
        "--origin",
        "13:executable unavailable",
    ]
    .map(String::from)
    .to_vec();
    let actual = approve::review_arguments(&request, &facts).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        approve::decode_review(&approve::encode_review(&actual).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn escaping_can_exceed_budget_before_sudo_runs() {
    let fixture = Fixture::new();
    for (description, argument) in [
        ("reason".to_owned(), "\n".repeat(9000)),
        ("é".repeat(3000), "small".to_owned()),
    ] {
        assert!(description.len() + argument.len() < approve::MAX_REVIEW_BYTES);
        let output = fixture
            .command(env!("CARGO_BIN_EXE_approve"))
            .args(["-d", &description, "--", "echo", &argument])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to truncate"));
        assert!(!fixture.0.join("sudo-args").exists());
    }
}

#[test]
fn all_origins_are_preserved_and_count_toward_the_exact_budget() {
    let mut request = approve::Request {
        mode: approve::Mode::Sudo,
        description: "reason".into(),
        command: vec!["echo".into()],
    };
    let mut facts = approve::Facts {
        cwd: "/test".into(),
        uid: 1000,
        username: None,
        origin: vec![],
    };
    let base = approve::review_arguments(&request, &facts).unwrap();
    request.description.push("x".repeat(
        approve::MAX_REVIEW_BYTES
            - base.iter().map(String::len).sum::<usize>()
            - 3 * ("--origin".len() + "12:/bin/sh".len()),
    ));
    for pid in [12, 13, 14] {
        facts.origin.push(approve::Origin {
            pid,
            executable: "/bin/sh".into(),
        });
    }
    let args = approve::review_arguments(&request, &facts).unwrap();
    assert_eq!(
        args.iter().map(String::len).sum::<usize>(),
        approve::MAX_REVIEW_BYTES
    );
    assert_eq!(
        &args[args.len() - 6..],
        [
            "--origin",
            "12:/bin/sh",
            "--origin",
            "13:/bin/sh",
            "--origin",
            "14:/bin/sh"
        ]
    );
    assert_eq!(
        approve::decode_review(&approve::encode_review(&args).unwrap()).unwrap(),
        args
    );
    facts.origin[2].executable.push("x");
    assert!(
        approve::review_arguments(&request, &facts)
            .unwrap_err()
            .contains("refusing to truncate")
    );
    assert_eq!(facts.origin.len(), 3);
}

#[test]
fn target_signal_is_preserved() {
    use std::os::unix::process::ExitStatusExt;
    let fixture = Fixture::new();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .args(["-d", "signal test", "--", "/bin/sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15));
}

#[test]
fn startup_failures_report_errors_without_running_the_target() {
    let run = |fixture: &Fixture, binary: &str| {
        fixture
            .command(binary)
            .args([
                "-d",
                "startup test",
                "--",
                "/bin/sh",
                "-c",
                "printf created > marker",
            ])
            .output()
            .unwrap()
    };
    let fixture = Fixture::new();
    let isolated = fixture.0.join("approve");
    fs::copy(env!("CARGO_BIN_EXE_approve"), &isolated).unwrap();
    let output = run(&fixture, isolated.to_str().unwrap());
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("approve-askpass must be installed beside approve")
    );
    assert!(!fixture.0.join("sudo-args").exists());

    for mode in ["missing", "non-executable", "directory"] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.0.join("askpass")).unwrap();
        match mode {
            "non-executable" => fs::write(fixture.0.join("askpass"), "data").unwrap(),
            "directory" => fs::create_dir(fixture.0.join("askpass")).unwrap(),
            _ => {}
        }
        for use_override in [false, true] {
            let mut command = fixture.command(env!("CARGO_BIN_EXE_approve"));
            if !use_override {
                command.env_remove("APPROVE_ASKPASS");
            }
            let output = command
                .args(["-d", "startup", "--", "id"])
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(if use_override {
                    "APPROVE_ASKPASS must be"
                } else {
                    "askpass is not on PATH"
                }),
                "{stderr}"
            );
            assert!(!fixture.0.join("sudo-args").exists());
        }
        assert!(!fixture.0.join("marker").exists());
    }
    let fixture = Fixture::new();
    fs::remove_file(fixture.0.join("sudo")).unwrap();
    let output = run(&fixture, env!("CARGO_BIN_EXE_approve"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not execute sudo"));
    assert!(!fixture.0.join("marker").exists());

    let fixture = Fixture::new();
    // Executable metadata passes lookup, but the interpreter cannot be executed.
    fixture.script("askpass", "exit 0\n");
    fs::write(
        fixture.0.join("askpass"),
        "#!/missing/approve-test-interpreter\n",
    )
    .unwrap();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .env(approve::REVIEW_ENV, unchecked_transport(&sample_review()))
        .arg("Password: ")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not execute askpass"));
    assert!(!fixture.0.join("askpass-args").exists());
}

#[test]
fn ssh_mode_runs_directly_and_reviews_each_prompt_separately() {
    let fixture = Fixture::new();
    fixture.script(
        "askpass",
        concat!(
            "[ \"${APPROVE_REVIEW+x}\" != x ] || exit 99\n",
            "printf '%s\\0' \"$@\" > \"$ASKPASS_ARGS\"\n",
            "printf 'fixture-passphrase\\n'\n"
        ),
    );
    // A protocol stand-in for ssh: two keys, each prompting through SSH_ASKPASS.
    fixture.script(
        "ssh",
        concat!(
            "printf '%s|%s|%s' \"$SSH_ASKPASS_REQUIRE\" \"${SUDO_ASKPASS-unset}\" ",
            "\"$SSH_ASKPASS\" > ssh-env\n",
            "printf '%s' $$ > ssh-pid\n",
            "for key in one two; do\n",
            "  reply=$(ASKPASS_ARGS=\"$PWD/askpass-$key\" prompt ",
            "\"Enter passphrase for key '/keys/$key': \") || exit 41\n",
            "  [ \"$reply\" = fixture-passphrase ] || exit 42\n",
            "done\n",
            "printf '%s\\0' \"$@\" > \"$TARGET_ARGS\"\nexit 23\n"
        ),
    );
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        // ssh mode must not introduce a sudo askpass of its own.
        .env_remove("SUDO_ASKPASS")
        .args([
            "--ssh",
            "-d",
            "Test GitHub auth",
            "--",
            "ssh",
            "-T",
            "git@example.com",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23), "{output:?}");
    assert_eq!(fixture.args("target-args"), ["-T", "git@example.com"]);
    assert!(!fixture.0.join("sudo-args").exists());
    assert_eq!(
        fs::read_to_string(fixture.0.join("ssh-env")).unwrap(),
        format!("force|unset|{}", env!("CARGO_BIN_EXE_approve-askpass"))
    );
    let ssh_pid = fs::read_to_string(fixture.0.join("ssh-pid")).unwrap();
    for key in ["one", "two"] {
        let review: Vec<String> = fixture
            .args(&format!("askpass-{key}"))
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect();
        assert_eq!(&review[..3], ["--review", "--kind", "ssh"]);
        assert!(review.contains(&"Test GitHub auth".into()));
        assert!(!review.contains(&"--run-as-user".into()));
        let tail = &review[review.len() - 4..];
        assert_eq!(tail[0], "--prompt");
        assert_eq!(tail[1], format!("Enter passphrase for key '/keys/{key}': "));
        assert_eq!(tail[2], "--prompt-process");
        let (pid, exe) = tail[3].split_once(':').unwrap();
        match approve::EXPECTED_SSH {
            // The stand-in ssh is the parent.
            None => assert_eq!(pid, ssh_pid),
            // `prompt` used the build-time ssh, as the build requires.
            Some(ssh) => assert_eq!(Path::new(exe), fs::canonicalize(ssh).unwrap()),
        }
        assert!(Path::new(exe).is_absolute(), "{exe}");
        // Each call contributes exactly one prompt.
        assert_eq!(review.iter().filter(|arg| *arg == "--prompt").count(), 1);
    }
}

#[test]
fn ssh_cancellation_reaches_ssh_and_the_failure_status_is_returned() {
    let fixture = Fixture::new();
    fixture.script(
        "ssh",
        "prompt 'Enter passphrase: ' > /dev/null || exit 255\nexit 0\n",
    );
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .args(["--ssh", "-d", "cancel", "--", "ssh", "host"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(255));
    assert!(fixture.0.join("askpass-args").exists());
}

fn ssh_transport() -> String {
    let mut review = sample_review();
    review.truncate(review.len() - 4);
    review.splice(1..1, ["--kind".into(), "ssh".into()]);
    review.extend(["--origin".into(), "12:/bin/sh".into()]);
    approve::encode_review(&review).unwrap()
}

#[test]
fn ssh_adapter_shows_the_prompt_and_the_parent_executable() {
    let fixture = Fixture::new();
    let run = run_adapter(
        &fixture,
        &ssh_transport(),
        &["Enter passphrase for key '/k\x1b[0m':"],
    );
    // The stand-in askpass cancels; the adapter propagates its status.
    assert!(!run.success, "{}", run.stderr);
    assert!(run.code.is_none_or(|code| code == 1), "{}", run.stderr);
    let args = fixture.args("askpass-args");
    let tail = &args[args.len() - 4..];
    assert_eq!(
        tail,
        [
            "--prompt",
            "Enter passphrase for key '/k\\u{1b}[0m':",
            "--prompt-process",
            run.parent.as_str()
        ]
    );
}

#[test]
fn ssh_adapter_refuses_prompts_not_from_the_build_time_ssh() {
    // Without APPROVE_SSH, every parent is accepted.
    let Some(ssh) = approve::EXPECTED_SSH else {
        return;
    };
    let expected = fs::canonicalize(ssh).unwrap();
    let fixture = Fixture::new();
    // Run directly, the adapter's parent is this test binary.
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .env(approve::REVIEW_ENV, ssh_transport())
        .arg("Enter passphrase: ")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing passphrase prompt from"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("PID {}", std::process::id())),
        "{stderr}"
    );
    assert!(stderr.contains(&*expected.to_string_lossy()), "{stderr}");
    assert!(!fixture.0.join("askpass-args").exists());

    // Through approve, a stand-in ssh is refused and sees the failure.
    fixture.script(
        "ssh",
        "\"$SSH_ASKPASS\" 'Enter passphrase: ' > /dev/null || exit 41\nexit 0\n",
    );
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .args(["--ssh", "-d", "refuse", "--", "ssh", "host"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(41), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing passphrase prompt from"));
    assert!(!fixture.0.join("askpass-args").exists());
}

#[test]
fn ssh_adapter_refuses_confirmation_notification_and_bad_prompt_counts() {
    let fixture = Fixture::new();
    for (hint, message) in [
        ("confirm", "SSH_ASKPASS_PROMPT=confirm"),
        ("none", "SSH_ASKPASS_PROMPT=none"),
        ("other", "unsupported SSH_ASKPASS_PROMPT"),
    ] {
        let output = fixture
            .command(env!("CARGO_BIN_EXE_approve-askpass"))
            .env(approve::REVIEW_ENV, ssh_transport())
            .env("SSH_ASKPASS_PROMPT", hint)
            .arg("Allow use of key? ")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
        assert!(!fixture.0.join("askpass-args").exists());
    }
    for prompts in [vec![], vec!["one", "two"]] {
        assert_adapter_rejects(
            &fixture,
            OsStr::new(&ssh_transport()),
            &prompts,
            "expected one prompt argument",
        );
    }
    let run = run_adapter(&fixture, &ssh_transport(), &[""]);
    assert!(!run.success);
    assert!(run.code.is_none_or(|code| code == 1));
    assert!(run.stdout.is_empty());
    assert!(run.stderr.contains("empty prompt"), "{}", run.stderr);
    assert!(!fixture.0.join("askpass-args").exists());
    // A sudo prompt is ignored, and sudo reviews never gain prompt fields.
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve-askpass"))
        .env(approve::REVIEW_ENV, unchecked_transport(&sample_review()))
        .env("SSH_ASKPASS_PROMPT", "confirm")
        .arg("Password: ")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fixture.args("askpass-args"),
        sample_review()
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
    );
}

#[test]
fn ssh_mode_reports_a_missing_command_without_sudo() {
    let fixture = Fixture::new();
    let output = fixture
        .command(env!("CARGO_BIN_EXE_approve"))
        .args(["--ssh", "-d", "missing", "--", "no-such-ssh"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not execute \"no-such-ssh\""),
        "{output:?}"
    );
    assert!(!fixture.0.join("sudo-args").exists());
}
