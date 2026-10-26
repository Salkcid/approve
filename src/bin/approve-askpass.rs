use approve::{MAX_PROMPT_LINES, PROMPT_COLUMNS, find_zenity, zenity_text};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let prompt = args.next().ok_or("expected one sudo prompt argument")?;
    if args.next().is_some()
        || prompt.is_empty()
        || !prompt.is_ascii()
        || prompt.lines().count() > MAX_PROMPT_LINES
        || prompt.lines().any(|line| line.len() > PROMPT_COLUMNS)
        || prompt.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err("invalid or oversized prompt".into());
    }
    let error = Command::new(find_zenity()?)
        .args([
            "--entry",
            "--hide-text",
            "--title=Administrator access requested",
            "--ok-label=Authorize",
            "--cancel-label=Cancel",
            "--width=820",
        ])
        .arg(format!("--text={}", zenity_text(&prompt)))
        .exec();
    Err(format!("could not execute Zenity: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("approve-askpass: {error}");
        std::process::exit(1);
    }
}
