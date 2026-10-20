//! The command-line interface as data, and a small parser for it.
//!
//! Every command is described once, by a [`Spec`]. The parser, `--help`,
//! the man pages and the shell completions are all generated from these
//! descriptions, so they can't disagree.
//!
//! Syntax: `--long VALUE`, `--long=VALUE`, `-s VALUE`, `-sVALUE`, flags,
//! repeated options, positional arguments, and `--` to end options.

use crate::error::Error;
use std::collections::BTreeMap;
use std::ffi::OsString;

/// What kind of value an argument takes, for completion and documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// A directory that may not exist yet.
    NewDir,
    /// An existing identity directory.
    Identity,
    /// An id or an identity directory.
    Id,
    /// A file to read.
    File,
    /// A file to write.
    OutFile,
    /// A subject: an id, identity directory, name path, key file, or SSH key.
    Subject,
    /// Free text: tags, names, durations, times, labels, numbers.
    Text,
    /// One of a fixed set of words.
    Choice(&'static [&'static str]),
}

/// One option.
#[derive(Debug)]
pub struct Opt {
    pub long: &'static str,
    pub short: Option<char>,
    /// The placeholder (e.g. `DIR`) and kind of the option's value, if any.
    pub value: Option<(&'static str, Value)>,
    pub help: &'static str,
    /// Shown without brackets in the synopsis.
    pub required: bool,
    /// May be given more than once.
    pub many: bool,
}

/// A flag: an option without a value.
pub const fn flag(long: &'static str, help: &'static str) -> Opt {
    Opt {
        long,
        short: None,
        value: None,
        help,
        required: false,
        many: false,
    }
}

/// An option with a value.
pub const fn opt(long: &'static str, meta: &'static str, kind: Value, help: &'static str) -> Opt {
    Opt {
        long,
        short: None,
        value: Some((meta, kind)),
        help,
        required: false,
        many: false,
    }
}

impl Opt {
    pub const fn short(mut self, c: char) -> Opt {
        self.short = Some(c);
        self
    }

    pub const fn required(mut self) -> Opt {
        self.required = true;
        self
    }

    pub const fn many(mut self) -> Opt {
        self.many = true;
        self
    }
}

/// One positional argument.
#[derive(Debug)]
pub struct Arg {
    pub name: &'static str,
    pub value: Value,
    pub help: &'static str,
    pub optional: bool,
    pub many: bool,
}

/// A required positional argument.
pub const fn arg(name: &'static str, value: Value, help: &'static str) -> Arg {
    Arg {
        name,
        value,
        help,
        optional: false,
        many: false,
    }
}

impl Arg {
    pub const fn optional(mut self) -> Arg {
        self.optional = true;
        self
    }

    pub const fn many(mut self) -> Arg {
        self.many = true;
        self
    }
}

/// A command.
#[derive(Debug)]
pub struct Spec {
    pub name: &'static str,
    /// A short phrase, lower case, no period: "grant TAG to SUBJECT".
    pub about: &'static str,
    /// Overrides the generated synopsis (the words after `writ NAME`).
    pub synopsis: Option<&'static str>,
    pub args: &'static [Arg],
    pub opts: &'static [Opt],
    /// Description blocks. A block whose lines start with four spaces is
    /// shown verbatim; `` `code` `` is shown in bold.
    pub description: &'static [&'static str],
    /// (what it does, the command line).
    pub examples: &'static [(&'static str, &'static str)],
    /// Related commands.
    pub see_also: &'static [&'static str],
}

/// Parsed arguments.
#[derive(Debug, Default)]
pub struct Parsed {
    values: BTreeMap<&'static str, Vec<String>>,
    pub positional: Vec<String>,
}

impl Spec {
    pub fn parse(&'static self, args: &[OsString]) -> Result<Parsed, Error> {
        let mut out = Parsed::default();
        let mut iter = args.iter();
        let mut only_positional = false;
        while let Some(raw) = iter.next() {
            let arg = raw
                .to_str()
                .ok_or_else(|| self.usage_error(format!("argument is not UTF-8: {raw:?}")))?;
            if only_positional || arg == "-" || !arg.starts_with('-') {
                out.positional.push(arg.to_owned());
                continue;
            }
            if arg == "--" {
                only_positional = true;
                continue;
            }
            if arg == "-h" || arg == "--help" {
                return Err(Error::Help {
                    spec: self,
                    long: arg == "--help",
                });
            }
            let (opt, inline) = if let Some(long) = arg.strip_prefix("--") {
                let (name, inline) = match long.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (long, None),
                };
                let opt = self
                    .opts
                    .iter()
                    .find(|o| o.long == name)
                    .ok_or_else(|| self.usage_error(format!("unknown option --{name}")))?;
                (opt, inline)
            } else {
                let mut chars = arg.chars().skip(1);
                let c = chars.next().unwrap_or('-');
                let rest: String = chars.collect();
                let opt = self
                    .opts
                    .iter()
                    .find(|o| o.short == Some(c))
                    .ok_or_else(|| self.usage_error(format!("unknown option -{c}")))?;
                (opt, (!rest.is_empty()).then_some(rest))
            };
            let value = match (opt.value, inline) {
                (None, None) => String::new(),
                (None, Some(_)) => {
                    return Err(self.usage_error(format!("--{} takes no value", opt.long)));
                }
                (Some(_), Some(v)) => v,
                (Some((meta, _)), None) => iter
                    .next()
                    .and_then(|v| v.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        self.usage_error(format!("--{} needs a value ({meta})", opt.long))
                    })?,
            };
            let values = out.values.entry(opt.long).or_default();
            if opt.value.is_some() && !opt.many && !values.is_empty() {
                return Err(self.usage_error(format!("--{} can be given only once", opt.long)));
            }
            values.push(value);
        }
        Ok(out)
    }

    /// Whether `arg`, in option position, is an option whose value is the
    /// next argument (`--key PATH`, `-i DIR`), not inline (`--key=PATH`).
    pub fn takes_next(&self, arg: &str) -> bool {
        let opt = if let Some(long) = arg.strip_prefix("--") {
            self.opts.iter().find(|o| o.long == long)
        } else if let Some(short) = arg.strip_prefix('-') {
            let mut chars = short.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => self.opts.iter().find(|o| o.short == Some(c)),
                _ => None,
            }
        } else {
            None
        };
        opt.is_some_and(|o| o.value.is_some())
    }

    pub fn usage_error(&'static self, message: String) -> Error {
        Error::Usage {
            spec: self,
            message,
        }
    }

    /// The synopsis as words, after `writ NAME`: required options first, then
    /// optional ones, then positional arguments.
    pub fn synopsis_words(&'static self) -> Vec<Word> {
        if let Some(s) = self.synopsis {
            return s.split(' ').map(|w| Word::Literal(w.to_owned())).collect();
        }
        let ordered = self
            .opts
            .iter()
            .filter(|o| o.required)
            .chain(self.opts.iter().filter(|o| !o.required));
        ordered
            .map(Word::Opt)
            .chain(self.args.iter().map(Word::Arg))
            .collect()
    }
}

/// One element of a synopsis.
pub enum Word {
    Opt(&'static Opt),
    Arg(&'static Arg),
    Literal(String),
}

impl Word {
    /// Plain text, e.g. `[--key PATH]...`.
    pub fn plain(&self) -> String {
        match self {
            Word::Opt(o) => {
                let name = match o.short {
                    Some(c) => format!("-{c}"),
                    None => format!("--{}", o.long),
                };
                let body = match o.value {
                    Some((meta, _)) => format!("{name} {meta}"),
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
                let body = if a.optional {
                    format!("[{}]", a.name)
                } else {
                    a.name.to_owned()
                };
                if a.many { format!("{body}...") } else { body }
            }
            Word::Literal(s) => s.clone(),
        }
    }
}

impl Parsed {
    pub fn flag(&self, long: &str) -> bool {
        self.values.contains_key(long)
    }

    pub fn value(&self, long: &str) -> Option<&str> {
        self.values
            .get(long)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    pub fn values(&self, long: &str) -> &[String] {
        self.values.get(long).map(Vec::as_slice).unwrap_or_default()
    }

    /// Positional arguments, exactly `names.len()` of them.
    pub fn exact<const N: usize>(
        &self,
        spec: &'static Spec,
        names: [&str; N],
    ) -> Result<[&str; N], Error> {
        if self.positional.len() != N {
            let what = if self.positional.len() < N {
                let missing: Vec<&str> =
                    names.iter().skip(self.positional.len()).copied().collect();
                format!("missing {}", missing.join(" "))
            } else {
                format!(
                    "unexpected argument '{}'",
                    self.positional.get(N).map(String::as_str).unwrap_or("")
                )
            };
            return Err(spec.usage_error(what));
        }
        let mut out = [""; N];
        for (slot, value) in out.iter_mut().zip(&self.positional) {
            *slot = value;
        }
        Ok(out)
    }

    /// Positional arguments: exactly `names.len()` of them, then one or
    /// more called `many`.
    pub fn exact_then_many<const N: usize>(
        &self,
        spec: &'static Spec,
        names: [&str; N],
        many: &str,
    ) -> Result<([&str; N], &[String]), Error> {
        let (first, rest) = self.positional.split_at(self.positional.len().min(N));
        if rest.is_empty() {
            let mut missing: Vec<&str> = names.iter().skip(first.len()).copied().collect();
            missing.push(many);
            return Err(spec.usage_error(format!("missing {}", missing.join(" "))));
        }
        let mut out = [""; N];
        for (slot, value) in out.iter_mut().zip(first) {
            *slot = value;
        }
        Ok((out, rest))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    static SPEC: Spec = Spec {
        name: "t",
        about: "test",
        synopsis: None,
        args: &[
            arg("A", Value::Text, "a"),
            arg("B", Value::File, "b").optional().many(),
        ],
        opts: &[
            flag("delegate", "delegate"),
            opt("identity", "DIR", Value::Identity, "identity")
                .short('i')
                .required(),
            opt("key", "PATH", Value::File, "key").many(),
        ],
        description: &[],
        examples: &[],
        see_also: &[],
    };

    fn parse(args: &[&str]) -> Result<Parsed, Error> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        SPEC.parse(&args)
    }

    #[test]
    fn parses() {
        let p = parse(&[
            "-i",
            "me",
            "a",
            "--delegate",
            "--key=x",
            "--key",
            "y",
            "-",
            "--",
            "-z",
        ])
        .unwrap();
        assert_eq!(p.value("identity"), Some("me"));
        assert!(p.flag("delegate"));
        assert_eq!(p.values("key"), ["x", "y"]);
        assert_eq!(p.positional, ["a", "-", "-z"]);
        assert_eq!(parse(&["-ime"]).unwrap().value("identity"), Some("me"));
    }

    #[test]
    fn rejects() {
        for bad in [
            &["--nope"][..],
            &["-x"],
            &["--key"],
            &["--delegate=yes"],
            &["-i", "a", "-i", "b"],
            &["-ia", "--identity=b"],
        ] {
            assert!(matches!(parse(bad), Err(Error::Usage { .. })), "{bad:?}");
        }
        assert!(matches!(
            parse(&["--help"]),
            Err(Error::Help { long: true, .. })
        ));
        assert!(matches!(
            parse(&["-h"]),
            Err(Error::Help { long: false, .. })
        ));
    }

    #[test]
    fn synopsis() {
        let words: Vec<String> = SPEC.synopsis_words().iter().map(Word::plain).collect();
        assert_eq!(
            words.join(" "),
            "-i DIR [--delegate] [--key PATH]... A [B]..."
        );
    }
}
