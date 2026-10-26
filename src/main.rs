use approve::{
    Facts, REVIEW_ENV, Request, USAGE, encode_review, find_askpass, review_arguments, sudo_command,
};
use std::os::unix::process::CommandExt;

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let request = Request::parse(args).map_err(|e| format!("{e}\n{USAGE}"))?;
    let facts = Facts::collect()?;
    let review = encode_review(&review_arguments(&request, &facts)?)?;
    let helper = std::env::current_exe()
        .map_err(|e| format!("cannot locate approve: {e}"))?
        .with_file_name("approve-askpass");
    if !helper.is_file() {
        return Err("approve-askpass must be installed beside approve; run cargo build --bins or cargo install --path .".into());
    }
    let askpass = find_askpass()?;
    // Replacing the process preserves stdio, cwd, exit status, and signals.
    let error = sudo_command(&request)
        .env("SUDO_ASKPASS", helper)
        .env("APPROVE_ASKPASS", askpass)
        .env(REVIEW_ENV, review)
        .exec();
    Err(format!("could not execute sudo: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("approve: {error}");
        std::process::exit(2);
    }
}
