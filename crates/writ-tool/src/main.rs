//! The `writ` command-line tool. See `writ --help`, writ(1), and DESIGN.md §14.

mod args;
mod cmd_identity;
mod cmd_issue;
mod cmd_query;
mod completions;
mod display;
mod error;
mod fs;
mod help;
mod ident;
#[cfg(test)]
mod man;
mod specs;
mod state;
mod style;
mod subject;

use args::{Parsed, Spec};
use error::{Error, Result};
use std::ffi::OsString;
use std::process::ExitCode;
use style::{BAD, BOLD, Stream, WARN};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The function that runs each command.
fn runner(name: &str) -> Option<fn(&Parsed) -> Result<()>> {
    Some(match name {
        "init" => cmd_identity::init,
        "id" => cmd_identity::id,
        "rotate" => cmd_identity::rotate,
        "export" => cmd_identity::export,
        "keygen" => cmd_identity::keygen,
        "pubkey" => cmd_identity::pubkey,
        "name" => cmd_issue::name,
        "grant" => cmd_issue::grant,
        "revoke" => cmd_issue::revoke,
        "leaf" => cmd_issue::leaf,
        "sign" => cmd_issue::sign,
        "verify" => cmd_query::verify,
        "check" => cmd_query::check,
        "resolve" => cmd_query::resolve,
        "prove" => cmd_query::prove,
        "show" => cmd_query::show,
        "completions" => completions_cmd,
        _ => return None,
    })
}

fn find(name: &str) -> Option<&'static Spec> {
    specs::all().find(|s| s.name == name)
}

fn completions_cmd(parsed: &Parsed) -> Result<()> {
    let [shell] = parsed.exact(&specs::COMPLETIONS, ["SHELL"])?;
    match completions::script(shell) {
        Some(script) => fs::print(&script),
        None => Err(specs::COMPLETIONS.usage_error(format!(
            "unknown shell '{shell}'; writ knows bash, zsh, and fish"
        ))),
    }
}

/// Takes `--color WHEN` / `--color=WHEN` from anywhere before `--`.
fn take_color(argv: &mut Vec<OsString>) -> Result<()> {
    let mut i = 0;
    while let Some(arg) = argv.get(i).and_then(|a| a.to_str()).map(str::to_owned) {
        if arg == "--" {
            break;
        }
        let value = if arg == "--color" {
            argv.remove(i);
            if i < argv.len() {
                Some(argv.remove(i))
            } else {
                None
            }
        } else if let Some(v) = arg.strip_prefix("--color=") {
            let v = OsString::from(v);
            argv.remove(i);
            Some(v)
        } else {
            i += 1;
            continue;
        };
        let when = value
            .as_ref()
            .and_then(|v| v.to_str())
            .and_then(style::When::parse)
            .ok_or_else(|| Error::Msg("--color: expected auto, always, or never".into()))?;
        style::set(when);
    }
    Ok(())
}

fn run(mut argv: Vec<OsString>) -> Result<()> {
    take_color(&mut argv)?;
    let Some(first) = argv.first().and_then(|a| a.to_str()) else {
        eprint!("{}", help::overview(false));
        return Err(Error::Msg(String::new()));
    };
    match first {
        "-h" => return fs::print(&help::overview(false)),
        "--help" => return fs::print(&help::overview(true)),
        "-V" | "--version" => return fs::print(&format!("writ {VERSION}\n")),
        "help" => {
            return match argv.get(1).and_then(|a| a.to_str()) {
                None => fs::print(&help::overview(true)),
                Some(name) => match find(name) {
                    Some(spec) => fs::print(&help::command(spec, true)),
                    None => error::err(format!("no such command: {name}")),
                },
            };
        }
        _ => {}
    }
    let (Some(spec), Some(run)) = (find(first), runner(first)) else {
        let suggestion = specs::all()
            .find(|s| s.name.starts_with(first.get(..2).unwrap_or(first)))
            .map(|s| format!(" (did you mean '{}'?)", s.name))
            .unwrap_or_default();
        return error::err(format!(
            "unknown command '{first}'{suggestion}; run 'writ --help' for a list"
        ));
    };
    let parsed = spec.parse(argv.get(1..).unwrap_or_default())?;
    run(&parsed)
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            match &e {
                Error::Help { spec, long } => {
                    let _ = fs::print(&help::command(spec, *long));
                }
                Error::Usage { spec, message } => {
                    eprintln!(
                        "{} {message}\n{} {}\nRun 'writ {} --help' for more.",
                        style::paint(Stream::Err, BAD, &format!("writ {}:", spec.name)),
                        style::paint(Stream::Err, BOLD, "Usage:"),
                        help::usage_line(spec),
                        spec.name
                    );
                }
                Error::Msg(m) if m.is_empty() => {}
                Error::Msg(m) => {
                    eprintln!("{} {m}", style::paint(Stream::Err, BAD, "writ:"));
                }
                Error::Denied => {}
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Prints a warning to stderr.
pub fn warn(message: impl std::fmt::Display) {
    eprintln!(
        "{} {message}",
        style::paint(Stream::Err, WARN, "writ: warning:")
    );
}

/// Prints a note to stderr.
pub fn note(message: impl std::fmt::Display) {
    eprintln!("{} {message}", style::paint(Stream::Err, BOLD, "writ:"));
}

/// The OS random number generator.
pub struct OsRng;

impl libwrit::Rng for OsRng {
    fn fill(&mut self, out: &mut [u8]) {
        if let Err(e) = getrandom::fill(out) {
            // Continuing without randomness is never acceptable.
            eprintln!("writ: the operating system's random number generator failed: {e}");
            std::process::abort();
        }
    }
}

/// The wall clock, in seconds since the epoch.
pub fn wall_clock() -> libwrit::Time {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Prints a progress or summary line to stderr unless `--quiet`.
pub fn say(parsed: &args::Parsed, line: impl std::fmt::Display) {
    if !parsed.flag("quiet") {
        eprintln!("{line}");
    }
}
