//! The `writ` command-line tool. See DESIGN.md §14 and `writ help`.

mod args;
mod cmd_identity;
mod cmd_issue;
mod cmd_query;
mod display;
mod error;
mod fs;
mod ident;
mod state;
mod subject;

use args::Spec;
use error::{Error, Result};
use std::ffi::OsString;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Command {
    spec: &'static Spec,
    run: fn(&args::Parsed) -> Result<()>,
}

const COMMANDS: &[(&str, &[Command])] = &[
    (
        "Identities",
        &[
            Command {
                spec: &cmd_identity::INIT,
                run: cmd_identity::init,
            },
            Command {
                spec: &cmd_identity::ID,
                run: cmd_identity::id,
            },
            Command {
                spec: &cmd_identity::ROTATE,
                run: cmd_identity::rotate,
            },
            Command {
                spec: &cmd_identity::EXPORT,
                run: cmd_identity::export,
            },
        ],
    ),
    (
        "Statements",
        &[
            Command {
                spec: &cmd_issue::NAME,
                run: cmd_issue::name,
            },
            Command {
                spec: &cmd_issue::GRANT,
                run: cmd_issue::grant,
            },
            Command {
                spec: &cmd_issue::REVOKE,
                run: cmd_issue::revoke,
            },
            Command {
                spec: &cmd_issue::LEAF,
                run: cmd_issue::leaf,
            },
        ],
    ),
    (
        "Signatures",
        &[
            Command {
                spec: &cmd_issue::SIGN,
                run: cmd_issue::sign,
            },
            Command {
                spec: &cmd_query::VERIFY,
                run: cmd_query::verify,
            },
        ],
    ),
    (
        "Questions (read bundles from stdin or --in)",
        &[
            Command {
                spec: &cmd_query::CHECK,
                run: cmd_query::check,
            },
            Command {
                spec: &cmd_query::RESOLVE,
                run: cmd_query::resolve,
            },
            Command {
                spec: &cmd_query::PROVE,
                run: cmd_query::prove,
            },
            Command {
                spec: &cmd_query::SHOW,
                run: cmd_query::show,
            },
        ],
    ),
    (
        "Keys",
        &[
            Command {
                spec: &cmd_identity::KEYGEN,
                run: cmd_identity::keygen,
            },
            Command {
                spec: &cmd_identity::PUBKEY,
                run: cmd_identity::pubkey,
            },
        ],
    ),
];

fn overview() -> String {
    let mut s = format!(
        "writ {VERSION} — signed statements about keys: who is who, and who may do what.\n\n\
         Usage: writ <command> [options]\n"
    );
    for (group, commands) in COMMANDS {
        s.push_str(&format!("\n{group}:\n"));
        for c in *commands {
            s.push_str(&format!("  {:<9} {}\n", c.spec.name, c.spec.about));
        }
    }
    s.push_str(
        "\nRun `writ <command> --help` for details. Exit status: 0 yes, 1 no (denied), 2 error.\n\n\
         Example:\n  \
         writ init me --next-out - | age -p > me-next.key.age\n  \
         writ name  -i me alice writ1…\n  \
         writ grant -i me 'me alice' '(ssh nas)' >> bundle.writ\n  \
         writ check --as me alice '(ssh nas)' < bundle.writ\n",
    );
    s
}

fn find(name: &str) -> Option<&'static Command> {
    COMMANDS
        .iter()
        .flat_map(|(_, cs)| cs.iter())
        .find(|c| c.spec.name == name)
}

fn run(argv: &[OsString]) -> Result<()> {
    let Some(first) = argv.first().and_then(|a| a.to_str()) else {
        eprint!("{}", overview());
        return Err(Error::Msg(String::new()));
    };
    match first {
        "-h" | "--help" => {
            fs::print(&overview())?;
            return Ok(());
        }
        "-V" | "--version" | "version" => {
            fs::print(&format!("writ {VERSION}\n"))?;
            return Ok(());
        }
        "help" => {
            match argv.get(1).and_then(|a| a.to_str()) {
                None => fs::print(&overview())?,
                Some(name) => match find(name) {
                    Some(c) => fs::print(&c.spec.help())?,
                    None => return error::err(format!("no such command: {name}")),
                },
            }
            return Ok(());
        }
        _ => {}
    }
    let Some(command) = find(first) else {
        let suggestion = COMMANDS
            .iter()
            .flat_map(|(_, cs)| cs.iter())
            .find(|c| c.spec.name.starts_with(first.get(..2).unwrap_or(first)))
            .map(|c| format!(" (did you mean `{}`?)", c.spec.name))
            .unwrap_or_default();
        return error::err(format!(
            "unknown command '{first}'{suggestion}; see `writ --help`"
        ));
    };
    let parsed = command.spec.parse(argv.get(1..).unwrap_or_default())?;
    (command.run)(&parsed)
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            match &e {
                Error::Help(spec) => {
                    let _ = fs::print(&spec.help());
                }
                Error::Usage { spec, message } => {
                    eprintln!(
                        "writ {}: {message}\nUsage: writ {}\nRun `writ {} --help` for more.",
                        spec.name, spec.usage, spec.name
                    );
                }
                Error::Msg(m) if m.is_empty() => {}
                Error::Msg(m) => eprintln!("writ: {m}"),
                Error::Denied => {}
            }
            ExitCode::from(e.exit_code())
        }
    }
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
