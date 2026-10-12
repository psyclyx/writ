//! Color, used sparingly: verdicts, errors and warnings, headings, and dim
//! hashes.
//!
//! `--color always|never` decides. Otherwise (`auto`): no color if
//! `NO_COLOR` is set and not empty; color if `CLICOLOR_FORCE` is set and not
//! `0`; no color if `TERM` is `dumb`; else color only on a terminal. Each of
//! stdout and stderr is judged on its own.

use std::cell::Cell;
use std::io::IsTerminal;

/// Where text will be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Out,
    Err,
}

/// The `--color` setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    Auto,
    Always,
    Never,
}

impl When {
    pub fn parse(text: &str) -> Option<When> {
        match text {
            "auto" => Some(When::Auto),
            "always" => Some(When::Always),
            "never" => Some(When::Never),
            _ => None,
        }
    }
}

thread_local! {
    static WHEN: Cell<When> = const { Cell::new(When::Auto) };
    static DECIDED: Cell<[Option<bool>; 2]> = const { Cell::new([None, None]) };
}

pub fn set(when: When) {
    WHEN.set(when);
    DECIDED.set([None, None]);
}

fn env_set(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Whether to color text for `stream`.
pub fn enabled(stream: Stream) -> bool {
    let i = usize::from(stream == Stream::Err);
    if let Some(Some(on)) = DECIDED.get().get(i).copied() {
        return on;
    }
    let on = match WHEN.get() {
        When::Always => true,
        When::Never => false,
        When::Auto => {
            if env_set("NO_COLOR").is_some() {
                false
            } else if env_set("CLICOLOR_FORCE").is_some_and(|v| v != "0") {
                true
            } else if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
                false
            } else {
                match stream {
                    Stream::Out => std::io::stdout().is_terminal(),
                    Stream::Err => std::io::stderr().is_terminal(),
                }
            }
        }
    };
    let mut decided = DECIDED.get();
    if let Some(slot) = decided.get_mut(i) {
        *slot = Some(on);
    }
    DECIDED.set(decided);
    on
}

/// ANSI SGR parameters.
pub const BOLD: &str = "1";
pub const DIM: &str = "2";
pub const OK: &str = "1;32";
pub const BAD: &str = "1;31";
pub const WARN: &str = "1;33";
pub const ACCENT: &str = "36";

/// `text` in `style`, if color is on for `stream`.
pub fn paint(stream: Stream, style: &str, text: &str) -> String {
    if enabled(stream) && !text.is_empty() {
        format!("\x1b[{style}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}
