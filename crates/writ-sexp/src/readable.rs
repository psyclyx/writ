//! The readable form: what humans type and read.
//!
//! ```text
//! sexp    = atom / "(" *( ws / sexp ) ")"
//! atom    = token / quoted / hex / base64
//! token   = 1*tokenchar          ; ASCII graphic except ( ) " # | ' ; \ [ ] { }
//! quoted  = DQUOTE *( char / escape ) DQUOTE
//!           ; UTF-8; escapes \" \\ \n \t \r \xHH; raw control characters rejected
//! hex     = "#" *( 2HEXDIG ) "#"
//! base64  = "|" padded-base64 "|"
//! ```
//!
//! Whitespace is space, tab, CR and LF. The printer chooses, per atom, a
//! token if possible, else a quoted string for printable UTF-8, else hex for
//! short binary and base64 for long binary.

use crate::{Sexp, base64};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

/// Maximum nesting depth accepted by the parser.
pub const MAX_DEPTH: usize = 32;

/// Binary atoms up to this length print as hex; longer ones as base64.
const HEX_MAX: usize = 32;

/// Why readable text was rejected. Offsets are byte positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadableError {
    /// Input ended in the middle of an expression.
    Truncated,
    /// No expression at all.
    Empty,
    /// A character that is not allowed here.
    Unexpected {
        /// Offset of the character.
        at: usize,
    },
    /// A malformed `\` escape in a quoted string.
    BadEscape {
        /// Offset of the backslash.
        at: usize,
    },
    /// Malformed `#hex#` or `|base64|`.
    BadEncoding {
        /// Offset of the opening delimiter.
        at: usize,
    },
    /// More than one expression, or junk after it.
    TrailingData {
        /// Offset of the extra input.
        at: usize,
    },
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl fmt::Display for ReadableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadableError::Truncated => write!(f, "unexpected end of input"),
            ReadableError::Empty => write!(f, "empty input"),
            ReadableError::Unexpected { at } => write!(f, "unexpected character at offset {at}"),
            ReadableError::BadEscape { at } => write!(f, "bad escape at offset {at}"),
            ReadableError::BadEncoding { at } => {
                write!(f, "malformed hex or base64 atom at offset {at}")
            }
            ReadableError::TrailingData { at } => write!(f, "unexpected input at offset {at}"),
            ReadableError::TooDeep => write!(f, "nested too deeply"),
        }
    }
}

impl core::error::Error for ReadableError {}

/// Parses exactly one expression, with optional surrounding whitespace.
pub fn parse(text: &str) -> Result<Sexp, ReadableError> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    if p.pos == p.s.len() {
        return Err(ReadableError::Empty);
    }
    let sexp = p.sexp(0)?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(ReadableError::TrailingData { at: p.pos });
    }
    Ok(sexp)
}

/// Parses zero or more whitespace-separated expressions.
pub fn parse_many(text: &str) -> Result<Vec<Sexp>, ReadableError> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    let mut out = Vec::new();
    loop {
        p.skip_ws();
        if p.pos == p.s.len() {
            return Ok(out);
        }
        out.push(p.sexp(0)?);
    }
}

/// Whether `b` may appear in a bare token.
pub fn is_token_byte(b: u8) -> bool {
    b.is_ascii_graphic()
        && !matches!(
            b,
            b'(' | b')' | b'"' | b'#' | b'|' | b'\'' | b';' | b'\\' | b'[' | b']' | b'{' | b'}'
        )
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn sexp(&mut self, depth: usize) -> Result<Sexp, ReadableError> {
        let start = self.pos;
        match self.peek().ok_or(ReadableError::Truncated)? {
            b'(' => {
                if depth >= MAX_DEPTH {
                    return Err(ReadableError::TooDeep);
                }
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek().ok_or(ReadableError::Truncated)? {
                        b')' => {
                            self.pos += 1;
                            return Ok(Sexp::List(items));
                        }
                        _ => items.push(self.sexp(depth + 1)?),
                    }
                }
            }
            b'"' => self.quoted().map(Sexp::Atom),
            b'#' => {
                let body = self.delimited(b'#')?;
                decode_hex(body)
                    .map(Sexp::Atom)
                    .ok_or(ReadableError::BadEncoding { at: start })
            }
            b'|' => {
                let body = self.delimited(b'|')?;
                base64::decode(body)
                    .map(Sexp::Atom)
                    .ok_or(ReadableError::BadEncoding { at: start })
            }
            b if is_token_byte(b) => {
                while self.peek().is_some_and(is_token_byte) {
                    self.pos += 1;
                }
                let token = self.s.get(start..self.pos).unwrap_or_default();
                // A token must be followed by a delimiter.
                match self.peek() {
                    None | Some(b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')') => {
                        Ok(Sexp::atom(token))
                    }
                    Some(_) => Err(ReadableError::Unexpected { at: self.pos }),
                }
            }
            _ => Err(ReadableError::Unexpected { at: start }),
        }
    }

    fn delimited(&mut self, close: u8) -> Result<&[u8], ReadableError> {
        let start = self.pos + 1;
        let len = self
            .s
            .get(start..)
            .and_then(|rest| rest.iter().position(|&b| b == close))
            .ok_or(ReadableError::Truncated)?;
        self.pos = start + len + 1;
        Ok(self.s.get(start..start + len).unwrap_or_default())
    }

    fn quoted(&mut self) -> Result<Vec<u8>, ReadableError> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let at = self.pos;
            let b = self.peek().ok_or(ReadableError::Truncated)?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or(ReadableError::Truncated)?;
                    self.pos += 1;
                    match e {
                        b'"' | b'\\' => out.push(e),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'x' => {
                            let hex = self
                                .s
                                .get(self.pos..self.pos + 2)
                                .ok_or(ReadableError::BadEscape { at })?;
                            let v = decode_hex(hex)
                                .and_then(|v| v.first().copied())
                                .ok_or(ReadableError::BadEscape { at })?;
                            self.pos += 2;
                            out.push(v);
                        }
                        _ => return Err(ReadableError::BadEscape { at }),
                    }
                }
                _ if b.is_ascii_control() => return Err(ReadableError::Unexpected { at }),
                _ => out.push(b),
            }
        }
    }
}

fn decode_hex(text: &[u8]) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[hi, lo]| {
            let hi = char::from(*hi).to_digit(16)?;
            let lo = char::from(*lo).to_digit(16)?;
            Some((hi << 4 | lo) as u8)
        })
        .collect()
}

/// Prints `sexp` in readable form on one line.
pub fn print(sexp: &Sexp) -> String {
    let mut out = String::new();
    write_sexp(&mut out, sexp);
    out
}

/// Prints one atom in readable form.
pub fn print_atom(atom: &[u8]) -> String {
    let mut out = String::new();
    write_atom(&mut out, atom);
    out
}

fn write_sexp(out: &mut String, sexp: &Sexp) {
    match sexp {
        Sexp::Atom(a) => write_atom(out, a),
        Sexp::List(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                write_sexp(out, item);
            }
            out.push(')');
        }
    }
}

/// Characters that print as nothing, or that change how the text around
/// them is laid out (direction overrides, line separators): a quoted atom
/// holding one could display as something else, so it prints as hex.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

fn write_atom(out: &mut String, atom: &[u8]) {
    if !atom.is_empty() && atom.iter().all(|&b| is_token_byte(b)) {
        out.extend(atom.iter().map(|&b| char::from(b)));
    } else if let Ok(s) = core::str::from_utf8(atom)
        && s.chars()
            .all(|c| (!c.is_control() || matches!(c, '\n' | '\t' | '\r')) && !is_invisible(c))
    {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                c => out.push(c),
            }
        }
        out.push('"');
    } else if atom.len() <= HEX_MAX {
        out.push('#');
        for b in atom {
            let _ = write!(out, "{b:02x}");
        }
        out.push('#');
    } else {
        out.push('|');
        out.push_str(&base64::encode(atom));
        out.push('|');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn a(s: &str) -> Sexp {
        Sexp::atom(s)
    }

    #[test]
    fn parses() {
        assert_eq!(parse("()"), Ok(Sexp::list(vec![])));
        assert_eq!(
            parse("  (zuko home\n relay)  "),
            Ok(Sexp::list(vec![a("zuko"), a("home"), a("relay")]))
        );
        assert_eq!(
            parse(r#"(a "b c\"\\\n\x00" #00ff# |AAEC| ("") (x(y)))"#),
            Ok(Sexp::list(vec![
                a("a"),
                Sexp::atom(b"b c\"\\\n\0"),
                Sexp::atom([0, 255]),
                Sexp::atom([0, 1, 2]),
                Sexp::list(vec![a("")]),
                Sexp::list(vec![a("x"), Sexp::list(vec![a("y")])]),
            ]))
        );
        assert_eq!(parse("writ1abc"), Ok(a("writ1abc")));
        assert_eq!(parse("##"), Ok(a("")));
    }

    #[test]
    fn rejects() {
        assert_eq!(parse(""), Err(ReadableError::Empty));
        assert_eq!(parse("(a"), Err(ReadableError::Truncated));
        assert_eq!(parse("a)"), Err(ReadableError::TrailingData { at: 1 }));
        assert_eq!(parse("a b"), Err(ReadableError::TrailingData { at: 2 }));
        assert_eq!(parse("ab\"c\""), Err(ReadableError::Unexpected { at: 2 }));
        assert_eq!(parse("#0#"), Err(ReadableError::BadEncoding { at: 0 }));
        assert_eq!(parse("#zz#"), Err(ReadableError::BadEncoding { at: 0 }));
        assert_eq!(parse("|AA|"), Err(ReadableError::BadEncoding { at: 0 }));
        assert_eq!(parse("\"\\q\""), Err(ReadableError::BadEscape { at: 1 }));
        assert_eq!(parse("\"\\x4\""), Err(ReadableError::BadEscape { at: 1 }));
        assert_eq!(parse("\"a\nb\""), Err(ReadableError::Unexpected { at: 2 }));
        assert_eq!(parse("'a'"), Err(ReadableError::Unexpected { at: 0 }));
        assert_eq!(parse(&"(".repeat(40)), Err(ReadableError::TooDeep));
    }

    #[test]
    fn prints() {
        let s = Sexp::list(vec![
            a("zuko"),
            a("a b"),
            a(""),
            Sexp::atom([0xff, 0]),
            Sexp::atom([0xffu8; 40]),
            a("tab\there \"q\""),
        ]);
        let text = print(&s);
        assert_eq!(
            text,
            "(zuko \"a b\" \"\" #ff00# |/////////////////////////////////////////////////////w==| \"tab\\there \\\"q\\\"\")"
        );
        assert_eq!(parse(&text), Ok(s));
    }

    /// Direction overrides and invisible characters would let an atom look
    /// like something else, or rearrange what follows it: they print as hex.
    #[test]
    fn invisible_characters_print_as_hex() {
        for s in ["alice\u{202e}gnp", "a\u{200b}b", "x\u{2066}", "\u{feff}y"] {
            let text = print_atom(s.as_bytes());
            assert!(text.starts_with('#'), "{text}");
            assert_eq!(parse(&text), Ok(a(s)));
        }
        assert_eq!(print_atom("café".as_bytes()), "\"café\"");
    }

    #[test]
    fn many() {
        assert_eq!(
            parse_many(" a (b) "),
            Ok(vec![a("a"), Sexp::list(vec![a("b")])])
        );
    }
}
