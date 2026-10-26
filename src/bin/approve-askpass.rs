use approve::{REVIEW_ENV, decode_review, find_askpass};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn run() -> Result<(), String> {
    // sudo supplies one prompt. Review data comes only from our transport.
    let mut args = std::env::args_os().skip(1);
    if args.next().is_none() || args.next().is_some() {
        return Err("expected one sudo prompt argument".into());
    }
    let encoded = std::env::var(REVIEW_ENV).map_err(|_| "missing or non-UTF-8 review transport")?;
    let review = decode_review(&encoded)?;
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
