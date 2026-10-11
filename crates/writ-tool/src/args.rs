//! A small hand-written argument parser: `--long VALUE`, `--long=VALUE`,
//! `-s VALUE`, boolean flags, repeated options, positionals, and `--`.

use crate::error::Error;
use std::collections::BTreeMap;
use std::ffi::OsString;

/// One option a command accepts.
#[derive(Debug)]
pub struct Opt {
    pub long: &'static str,
    pub short: Option<char>,
    pub value: Option<&'static str>,
    pub help: &'static str,
}

/// Shorthand constructors.
pub const fn flag(long: &'static str, help: &'static str) -> Opt {
    Opt {
        long,
        short: None,
        value: None,
        help,
    }
}

pub const fn opt(long: &'static str, value: &'static str, help: &'static str) -> Opt {
    Opt {
        long,
        short: None,
        value: Some(value),
        help,
    }
}

pub const fn short(mut o: Opt, c: char) -> Opt {
    o.short = Some(c);
    o
}

/// A command's interface: for parsing and for `--help`.
#[derive(Debug)]
pub struct Spec {
    pub name: &'static str,
    pub usage: &'static str,
    pub about: &'static str,
    pub details: &'static str,
    pub opts: &'static [Opt],
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
                return Err(Error::Help(self));
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
                (Some(meta), None) => iter
                    .next()
                    .and_then(|v| v.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        self.usage_error(format!("--{} needs a value ({meta})", opt.long))
                    })?,
            };
            out.values.entry(opt.long).or_default().push(value);
        }
        Ok(out)
    }

    pub fn usage_error(&'static self, message: String) -> Error {
        Error::Usage {
            spec: self,
            message,
        }
    }

    /// The full `--help` text.
    pub fn help(&self) -> String {
        let mut s = format!("{}\n\nUsage: writ {}\n", self.about, self.usage);
        if !self.opts.is_empty() {
            s.push_str("\nOptions:\n");
            let rows: Vec<(String, &str)> = self
                .opts
                .iter()
                .map(|o| {
                    let mut left = match o.short {
                        Some(c) => format!("-{c}, --{}", o.long),
                        None => format!("    --{}", o.long),
                    };
                    if let Some(v) = o.value {
                        left.push(' ');
                        left.push_str(v);
                    }
                    (left, o.help)
                })
                .chain([("-h, --help".to_owned(), "show this help")])
                .collect();
            let width = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
            for (left, help) in rows {
                let mut lines = help.lines();
                s.push_str(&format!(
                    "  {left:width$}  {}\n",
                    lines.next().unwrap_or_default()
                ));
                for line in lines {
                    s.push_str(&format!("  {:width$}  {line}\n", ""));
                }
            }
        }
        if !self.details.is_empty() {
            s.push('\n');
            s.push_str(self.details.trim_end());
            s.push('\n');
        }
        s
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    static SPEC: Spec = Spec {
        name: "t",
        usage: "t",
        about: "test",
        details: "",
        opts: &[
            short(opt("identity", "DIR", "identity"), 'i'),
            flag("delegate", "delegate"),
            opt("key", "PATH", "key"),
        ],
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
        for bad in [&["--nope"][..], &["-x"], &["--key"], &["--delegate=yes"]] {
            assert!(matches!(parse(bad), Err(Error::Usage { .. })), "{bad:?}");
        }
        assert!(matches!(parse(&["--help"]), Err(Error::Help(_))));
    }
}
