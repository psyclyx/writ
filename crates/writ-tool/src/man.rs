//! Man pages in roff, generated from the command specs: writ(1) and one
//! writ-COMMAND(1) per command. They are committed under `doc/man/`;
//! `cargo xtask man` writes them, and a test in `xtask` checks they are
//! current.

use crate::args::{Opt, Spec, Word};
use crate::specs::{self, GROUPS};
use std::fmt::Write as _;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Escapes text for roff, rendering `` `code` `` in bold.
fn text(s: &str) -> String {
    let mut out = String::new();
    for (i, piece) in s.split('`').enumerate() {
        let esc = piece.replace('\\', "\\e").replace('-', "\\-");
        if i % 2 == 1 {
            let _ = write!(out, "\\fB{esc}\\fR");
        } else {
            out.push_str(&esc);
        }
    }
    // A line must not start with a control character.
    out.lines()
        .map(|l| {
            if l.starts_with('.') || l.starts_with('\'') {
                format!("\\&{l}")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn block(out: &mut String, b: &str) {
    if b.starts_with("    ") {
        out.push_str(".PP\n.RS 4\n.nf\n");
        for line in b.lines() {
            out.push_str(&text(line.strip_prefix("    ").unwrap_or(line)));
            out.push('\n');
        }
        out.push_str(".fi\n.RE\n");
    } else {
        let _ = writeln!(out, ".PP\n{}", text(b));
    }
}

fn opt_term(o: &Opt) -> String {
    let mut s = match o.short {
        Some(c) => format!("\\fB\\-{c}\\fR, "),
        None => String::new(),
    };
    let _ = write!(s, "\\fB\\-\\-{}\\fR", o.long.replace('-', "\\-"));
    if let Some((meta, _)) = o.value {
        let _ = write!(s, " \\fI{meta}\\fR");
    }
    s
}

fn word(w: &Word) -> String {
    match w {
        Word::Opt(o) => {
            let name = match o.short {
                Some(c) => format!("\\fB\\-{c}\\fR"),
                None => format!("\\fB\\-\\-{}\\fR", o.long.replace('-', "\\-")),
            };
            let body = match o.value {
                Some((meta, _)) => format!("{name}\\ \\fI{meta}\\fR"),
                None => name,
            };
            let body = if o.required {
                body
            } else {
                format!("[{body}]")
            };
            if o.many { format!("{body}...") } else { body }
        }
        Word::Arg(a) => {
            let body = format!("\\fI{}\\fR", a.name);
            let body = if a.optional {
                format!("[{body}]")
            } else {
                body
            };
            if a.many { format!("{body}...") } else { body }
        }
        Word::Literal(l) => text(l),
    }
}

fn header(out: &mut String, name: &str, about: &str) {
    let _ = writeln!(
        out,
        ".\\\" Generated from crates/writ-tool/src/specs.rs; do not edit.\n\
         .TH {} 1 {} \"writ {VERSION}\" \"writ manual\"\n\
         .SH NAME\n{} \\- {}",
        name.to_uppercase().replace('-', "\\-"),
        specs::MAN_DATE,
        name.replace('-', "\\-"),
        text(about)
    );
}

fn list(out: &mut String, heading: &str, items: &[(&str, &str)], bold: bool) {
    let _ = writeln!(out, ".SH {heading}");
    for (term, desc) in items {
        let term = if bold {
            format!("\\fB{}\\fR", text(term))
        } else {
            text(term)
        };
        let _ = writeln!(out, ".TP\n{term}\n{}", text(desc));
    }
}

fn examples(out: &mut String, items: &[(&str, &str)]) {
    if items.is_empty() {
        return;
    }
    out.push_str(".SH EXAMPLES\n");
    for (what, cmd) in items {
        let _ = writeln!(out, ".PP\n{}\n.PP\n.RS 4\n.nf", text(what));
        for line in cmd.lines() {
            let _ = writeln!(out, "{}", text(line));
        }
        out.push_str(".fi\n.RE\n");
    }
}

/// writ-NAME(1).
pub fn command(spec: &'static Spec) -> String {
    let mut out = String::new();
    header(&mut out, &format!("writ-{}", spec.name), spec.about);
    out.push_str(".SH SYNOPSIS\n.nh\n.ad l\n");
    let words: Vec<String> = spec.synopsis_words().iter().map(word).collect();
    let _ = writeln!(
        out,
        "\\fBwrit {}\\fR {}\n.ad\n.hy",
        spec.name,
        words.join(" ")
    );
    out.push_str(".SH DESCRIPTION\n");
    for b in spec.description {
        block(&mut out, b);
    }
    if !spec.args.is_empty() {
        out.push_str(".SH ARGUMENTS\n");
        for a in spec.args {
            let _ = writeln!(out, ".TP\n\\fI{}\\fR\n{}", a.name, text(a.help));
        }
    }
    out.push_str(".SH OPTIONS\n");
    for o in spec.opts {
        let _ = writeln!(out, ".TP\n{}\n{}", opt_term(o), text(o.help));
    }
    out.push_str(".TP\n\\fB\\-h\\fR, \\fB\\-\\-help\\fR\nprint help; \\fB\\-h\\fR is short, \\fB\\-\\-help\\fR is long\n");
    list(&mut out, "EXIT STATUS", specs::EXIT_STATUS, false);
    examples(&mut out, spec.examples);
    out.push_str(".SH SEE ALSO\n");
    let mut refs: Vec<String> = vec!["\\fBwrit\\fR(1)".to_owned()];
    refs.extend(
        spec.see_also
            .iter()
            .map(|n| format!("\\fBwrit\\-{n}\\fR(1)")),
    );
    let _ = writeln!(out, "{}", refs.join(", "));
    out
}

/// writ(1).
pub fn overview() -> String {
    let mut out = String::new();
    header(&mut out, "writ", "signed statements about keys");
    out.push_str(
        ".SH SYNOPSIS\n\\fBwrit\\fR [\\fB\\-\\-color\\fR \\fIWHEN\\fR] \\fICOMMAND\\fR [\\fIARGS\\fR]...\n.br\n\\fBwrit\\fR \\fB\\-\\-help\\fR | \\fB\\-\\-version\\fR\n",
    );
    out.push_str(".SH DESCRIPTION\n");
    for b in specs::OVERVIEW {
        block(&mut out, b);
    }
    out.push_str(".SH COMMANDS\n");
    for (group, specs) in GROUPS {
        let _ = writeln!(out, ".SS {group}");
        for spec in specs.iter() {
            let _ = writeln!(
                out,
                ".TP\n\\fBwrit\\-{}\\fR(1)\n{}",
                spec.name.replace('-', "\\-"),
                text(spec.about)
            );
        }
    }
    out.push_str(".SH OPTIONS\n");
    for o in specs::GLOBAL_OPTS {
        let _ = writeln!(out, ".TP\n{}\n{}", opt_term(o), text(o.help));
    }
    out.push_str(".TP\n\\fB\\-h\\fR, \\fB\\-\\-help\\fR\nprint help\n.TP\n\\fB\\-V\\fR, \\fB\\-\\-version\\fR\nprint the version\n");
    for (heading, blocks) in specs::MANUAL {
        let _ = writeln!(out, ".SH {heading}");
        for b in blocks.iter() {
            block(&mut out, b);
        }
    }
    list(&mut out, "EXIT STATUS", specs::EXIT_STATUS, false);
    list(&mut out, "ENVIRONMENT", specs::ENVIRONMENT, true);
    list(&mut out, "FILES", specs::FILES, true);
    examples(&mut out, specs::TOUR);
    let _ = writeln!(out, ".SH STANDARDS\n{}", text(specs::STANDARDS));
    out.push_str(".SH SEE ALSO\n");
    let mut refs: Vec<String> = specs::all()
        .map(|s| format!("\\fBwrit\\-{}\\fR(1)", s.name))
        .collect();
    refs.push("\\fBage\\fR(1)".to_owned());
    refs.push("\\fBssh\\-keygen\\fR(1)".to_owned());
    let _ = writeln!(out, "{}", refs.join(", "));
    out
}

/// Drops `.PP` right after a section heading, where it does nothing.
fn tidy(page: &str) -> String {
    let mut out = String::with_capacity(page.len());
    let mut after_heading = false;
    for line in page.lines() {
        if after_heading && line == ".PP" {
            after_heading = false;
            continue;
        }
        after_heading = line.starts_with(".SH ") || line.starts_with(".SS ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Every page: (file name, contents).
pub fn pages() -> Vec<(String, String)> {
    let mut pages = vec![("writ.1".to_owned(), tidy(&overview()))];
    for spec in specs::all() {
        pages.push((format!("writ-{}.1", spec.name), tidy(&command(spec))));
    }
    pages
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../doc/man")
    }

    #[test]
    fn man_pages_are_ascii_and_lint_clean() {
        for (name, page) in pages() {
            assert!(page.is_ascii(), "{name}");
        }
        let Ok(out) = std::process::Command::new("mandoc")
            .args(["-T", "lint", "-W", "warning"])
            .args(pages().iter().map(|(n, _)| dir().join(n)))
            .output()
        else {
            eprintln!("mandoc not installed; skipping the lint");
            return;
        };
        let report = String::from_utf8_lossy(&out.stdout);
        assert!(report.trim().is_empty(), "{report}");
    }
}
