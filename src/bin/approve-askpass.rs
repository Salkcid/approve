use approve::{
    EXPECTED_SSH, REVIEW_ENV, check_ssh_prompt_hint, decode_review, find_askpass, is_ssh_review,
    prompt_process, ssh_prompt_review,
};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn run() -> Result<(), String> {
    // sudo and ssh each supply one prompt. Review data comes only from our
    // transport; ssh's prompt is added as a displayed field, never parsed.
    let mut args = std::env::args_os().skip(1);
    let (Some(prompt), None) = (args.next(), args.next()) else {
        return Err("expected one prompt argument".into());
    };
    let encoded = std::env::var(REVIEW_ENV).map_err(|_| "missing or non-UTF-8 review transport")?;
    let mut review = decode_review(&encoded)?;
    if is_ssh_review(&review) {
        check_ssh_prompt_hint(std::env::var_os("SSH_ASKPASS_PROMPT").as_deref())?;
        let process = prompt_process(Path::new("/proc"), EXPECTED_SSH.map(Path::new))?;
        review = ssh_prompt_review(review, &prompt, &process)?;
    }
    let error = Command::new(find_askpass()?)
        .args(review)
        .env_remove(REVIEW_ENV)
        .exec();
    Err(format!("could not execute askpass: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("approve-askpass: {error}");
        std::process::exit(1);
    }
}
