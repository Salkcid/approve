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
        .chunks_exact(2)
        .filter(|pair| pair[0] == "--command-arg")
        .map(|pair| pair[1].clone())
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
            "expected one sudo prompt",
        );
    }
}

#[test]
fn review_has_exact_ordered_fields_and_reversible_display_values() {
    let request = approve::Request {
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
