use approve::{
    Facts, Mode, Request, USAGE, encode_review, find_askpass, launch_command, quote,
    review_arguments,
};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let [arg] = args.as_slice()
        && (arg == "--help" || arg == "-h")
    {
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
    let error = launch_command(&request, &helper, &askpass, &review).exec();
    Err(match request.mode {
        Mode::Sudo => format!("could not execute sudo: {error}"),
        Mode::Ssh => format!(
            "could not execute {}: {error}",
            quote(request.command.first().map_or_default(OsString::as_os_str))
        ),
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("approve: {error}");
        std::process::exit(2);
    }
}
