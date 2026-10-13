//! `-h` (short) and `--help` (long) text, generated from [`crate::specs`].

use crate::args::{Arg, Opt, Spec, Word};
use crate::specs::{GLOBAL_OPTS, GROUPS, OVERVIEW};
use crate::style::{self, ACCENT, BOLD, Stream};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Text width: `$COLUMNS` if set, else 80; between 40 and 100.
fn width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(80usize)
        .clamp(40, 100)
        - 1
}

/// Display width of text with `` ` `` marks.
fn display_len(word: &str) -> usize {
    word.chars().filter(|c| *c != '`').count()
}

/// Wraps `text` into lines of at most `width` columns.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut len = 0;
    for word in text.split_whitespace() {
        let w = display_len(word);
        if len > 0 && len + 1 + w > width {
            lines.push(std::mem::take(&mut line));
            len = 0;
        }
        if len > 0 {
            line.push(' ');
            len += 1;
        }
        line.push_str(word);
        len += w;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Applies `` `code` `` styling across lines (a span may continue onto the
/// next line).
fn styled(lines: &[String], indent: &str) -> String {
    let mut out = String::new();
    let mut open = false;
    for line in lines {
        out.push_str(indent);
        let pieces = line.split('`');
        let mut first = true;
        for piece in pieces {
            if !first {
                open = !open;
            }
            first = false;
            if open {
                out.push_str(&style::paint(Stream::Out, BOLD, piece));
            } else {
                out.push_str(piece);
            }
        }
        out.push('\n');
    }
    out
}

/// A description block: a paragraph (wrapped) or a verbatim block.
fn block(text: &str, indent: &str, width: usize) -> String {
    if text.starts_with("    ") {
        text.lines()
            .map(|l| format!("{indent}{}\n", l.strip_prefix("  ").unwrap_or(l)))
            .collect()
    } else {
        styled(&wrap(text, width.saturating_sub(indent.len())), indent)
    }
}

fn heading(text: &str) -> String {
    format!("{}\n", style::paint(Stream::Out, BOLD, text))
}

fn opt_left(o: &Opt) -> String {
    let short = match o.short {
        Some(c) => format!("-{c}, "),
        None => "    ".to_owned(),
    };
    let value = match o.value {
        Some((meta, _)) => format!(" {meta}"),
        None => String::new(),
    };
    format!("{short}--{}{value}", o.long)
}

/// Two-column rows: left terms, wrapped right-hand help.
fn rows(rows: &[(String, String)], width: usize) -> String {
    let left = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0)
        .min(28);
    let mut out = String::new();
    for (l, help) in rows {
        let text_width = width.saturating_sub(left + 4).max(20);
        let text = styled(&wrap(help, text_width), "");
        let l_len = l.chars().count();
        let term = style::paint(Stream::Out, BOLD, l);
        let hang = " ".repeat(left + 4);
        let mut lines = text.lines();
        if l_len > left {
            out.push_str(&format!("  {term}\n"));
        } else {
            let pad = " ".repeat(left - l_len);
            let first = lines.next().unwrap_or("");
            out.push_str(&format!("  {term}{pad}  {first}\n"));
        }
        for line in lines {
            out.push_str(&format!("{hang}{line}\n"));
        }
    }
    out
}

/// `writ NAME` plus the synopsis, wrapped with a hanging indent.
pub fn synopsis(spec: &'static Spec, width: usize) -> String {
    let lead = format!("writ {}", spec.name);
    let mut out = format!("  {}", style::paint(Stream::Out, BOLD, &lead));
    let hang = " ".repeat(lead.len() + 3);
    let mut col = lead.len() + 2;
    for word in spec.synopsis_words() {
        let w = word.plain();
        if col + 1 + w.len() > width {
            out.push('\n');
            out.push_str(&hang);
            col = hang.len();
        } else {
            out.push(' ');
            col += 1;
        }
        out.push_str(&w);
        col += w.len();
    }
    out.push('\n');
    out
}

fn arg_rows(args: &[Arg]) -> Vec<(String, String)> {
    args.iter()
        .map(|a| (a.name.to_owned(), a.help.to_owned()))
        .collect()
}

fn opt_rows(opts: &[Opt], long: bool) -> Vec<(String, String)> {
    opts.iter()
        .map(|o| (opt_left(o), o.help.to_owned()))
        .chain([(
            "-h, --help".to_owned(),
            if long {
                "print help".to_owned()
            } else {
                "print help (--help for more)".to_owned()
            },
        )])
        .collect()
}

/// Help for one command. `long` adds arguments, description and examples.
pub fn command(spec: &'static Spec, long: bool) -> String {
    let width = width();
    let mut s = format!(
        "{} - {}\n\n",
        style::paint(Stream::Out, BOLD, &format!("writ {}", spec.name)),
        spec.about
    );
    s.push_str(&heading("Usage:"));
    s.push_str(&synopsis(spec, width));
    if long && !spec.args.is_empty() {
        s.push('\n');
        s.push_str(&heading("Arguments:"));
        s.push_str(&rows(&arg_rows(spec.args), width));
    }
    s.push('\n');
    s.push_str(&heading("Options:"));
    s.push_str(&rows(&opt_rows(spec.opts, long), width));
    if long {
        for b in spec.description {
            s.push('\n');
            s.push_str(&block(b, "", width));
        }
        if !spec.examples.is_empty() {
            s.push('\n');
            s.push_str(&heading("Examples:"));
            for (i, (what, cmd)) in spec.examples.iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&block(what, "  ", width));
                for line in cmd.lines() {
                    s.push_str(&format!("    {line}\n"));
                }
            }
        }
        if !spec.see_also.is_empty() {
            let names: Vec<String> = spec.see_also.iter().map(|n| format!("writ {n}")).collect();
            s.push_str(&format!(
                "\nSee also: {}, and man writ-{}.\n",
                names.join(", "),
                spec.name
            ));
        }
    } else {
        s.push_str(&format!(
            "\nRun '{}' for details and examples.\n",
            style::paint(Stream::Out, BOLD, &format!("writ {} --help", spec.name))
        ));
    }
    s
}

/// `writ --help` and `writ -h`.
pub fn overview(long: bool) -> String {
    let width = width();
    let mut s = format!(
        "{} {VERSION} - signed statements about keys\n\n",
        style::paint(Stream::Out, BOLD, "writ")
    );
    s.push_str(&heading("Usage:"));
    s.push_str(&format!(
        "  {} [--color WHEN] COMMAND [ARGS]...\n",
        style::paint(Stream::Out, BOLD, "writ")
    ));
    if long {
        for b in OVERVIEW {
            s.push('\n');
            s.push_str(&block(b, "", width));
        }
    }
    s.push('\n');
    s.push_str(&heading("Commands:"));
    let all: Vec<(String, String)> = GROUPS
        .iter()
        .flat_map(|(_, specs)| specs.iter())
        .map(|spec| (spec.name.to_owned(), spec.about.to_owned()))
        .collect();
    let col = all.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (group, specs) in GROUPS {
        s.push_str(&format!("  {}\n", style::paint(Stream::Out, ACCENT, group)));
        for spec in specs.iter() {
            s.push_str(&format!(
                "    {}{}  {}\n",
                style::paint(Stream::Out, BOLD, spec.name),
                " ".repeat(col - spec.name.len()),
                spec.about
            ));
        }
    }
    s.push('\n');
    s.push_str(&heading("Options:"));
    let mut opts = opt_rows(GLOBAL_OPTS, long);
    opts.push(("-V, --version".to_owned(), "print the version".to_owned()));
    s.push_str(&rows(&opts, width));
    s.push_str(&format!(
        "\nRun 'writ COMMAND --help' for help with a command{}.\n\
         Exit status: 0 for success or yes, 1 for no (denied), 2 for errors.\n",
        if long {
            ", and 'man writ' for the manual"
        } else {
            ", and 'writ --help' for more"
        }
    ));
    s
}

/// The synopsis line for usage errors.
pub fn usage_line(spec: &'static Spec) -> String {
    let words: Vec<String> = spec.synopsis_words().iter().map(Word::plain).collect();
    format!("writ {} {}", spec.name, words.join(" "))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wraps() {
        assert_eq!(wrap("a bb ccc dddd", 6), ["a bb", "ccc", "dddd"]);
        assert_eq!(wrap("`writ show` x", 9), ["`writ show`", "x"]);
    }

    #[test]
    fn every_command_has_help() {
        for spec in crate::specs::all() {
            let long = command(spec, true);
            assert!(long.contains("Usage:"), "{}", spec.name);
            assert!(!spec.about.ends_with('.'), "{}", spec.name);
            assert!(
                long.lines().all(|l| l.chars().count() <= 100),
                "{}",
                spec.name
            );
            for o in spec.opts {
                assert!(!o.help.ends_with('.'), "--{}", o.long);
            }
        }
    }
}
