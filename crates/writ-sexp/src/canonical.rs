//! Canonical csexp decoding.
//!
//! Grammar (no display hints, no whitespace, no other bytes):
//!
//! ```text
//! sexp  = atom / list
//! atom  = length ":" bytes          ; length is decimal, no leading zeros
//! list  = "(" *sexp ")"
//! ```

use crate::Sexp;
use alloc::vec::Vec;
use core::fmt;

/// Resource limits for decoding untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum total input length in bytes.
    pub max_len: usize,
    /// Maximum list nesting depth (the outermost list is depth 1).
    pub max_depth: usize,
    /// Maximum number of nodes (atoms + lists).
    pub max_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_len: 4 << 20,
            max_depth: 32,
            max_nodes: 1 << 18,
        }
    }
}

/// Why a canonical encoding was rejected. Offsets are byte positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended in the middle of an expression.
    Truncated,
    /// A byte that cannot start or continue an expression here.
    Unexpected {
        /// Offset of the byte.
        at: usize,
    },
    /// A length prefix with a leading zero, or too large.
    BadLength {
        /// Offset of the length.
        at: usize,
    },
    /// Bytes remain after a complete expression.
    TrailingData {
        /// Offset of the first extra byte.
        at: usize,
    },
    /// A [`Limits`] bound was exceeded.
    TooLarge,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated s-expression"),
            DecodeError::Unexpected { at } => write!(f, "unexpected byte at offset {at}"),
            DecodeError::BadLength { at } => write!(f, "non-canonical length at offset {at}"),
            DecodeError::TrailingData { at } => write!(f, "trailing data at offset {at}"),
            DecodeError::TooLarge => write!(f, "s-expression exceeds size limits"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Decodes exactly one canonical expression occupying all of `input`.
pub fn decode(input: &[u8], limits: &Limits) -> Result<Sexp, DecodeError> {
    let mut parser = Parser::new(input, limits)?;
    let sexp = parser.sexp(0)?;
    if parser.pos != input.len() {
        return Err(DecodeError::TrailingData { at: parser.pos });
    }
    Ok(sexp)
}

/// Decodes the canonical expression at the start of `input`, returning it
/// and the number of bytes it occupies. The limits apply to that expression
/// alone, so a concatenation (a binary bundle) can be decoded one expression
/// at a time, each turned into something smaller before the next is read.
pub fn decode_prefix(input: &[u8], limits: &Limits) -> Result<(Sexp, usize), DecodeError> {
    let window = input.get(..limits.max_len).unwrap_or(input);
    let mut parser = Parser {
        input: window,
        pos: 0,
        nodes: 0,
        limits,
    };
    match parser.sexp(0) {
        Ok(sexp) => Ok((sexp, parser.pos)),
        // It ran past `max_len` bytes.
        Err(DecodeError::Truncated) if window.len() < input.len() => Err(DecodeError::TooLarge),
        Err(e) => Err(e),
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    nodes: usize,
    limits: &'a Limits,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8], limits: &'a Limits) -> Result<Self, DecodeError> {
        if input.len() > limits.max_len {
            return Err(DecodeError::TooLarge);
        }
        Ok(Parser {
            input,
            pos: 0,
            nodes: 0,
            limits,
        })
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        self.input
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::Truncated)
    }

    fn sexp(&mut self, depth: usize) -> Result<Sexp, DecodeError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(DecodeError::TooLarge);
        }
        match self.peek()? {
            b'(' => {
                if depth >= self.limits.max_depth {
                    return Err(DecodeError::TooLarge);
                }
                self.pos += 1;
                let mut items = Vec::new();
                while self.peek()? != b')' {
                    items.push(self.sexp(depth + 1)?);
                }
                self.pos += 1;
                Ok(Sexp::List(items))
            }
            b'0'..=b'9' => self.atom().map(Sexp::Atom),
            _ => Err(DecodeError::Unexpected { at: self.pos }),
        }
    }

    fn atom(&mut self) -> Result<Vec<u8>, DecodeError> {
        let start = self.pos;
        let mut len: usize = 0;
        loop {
            let b = self.peek()?;
            match b {
                b'0'..=b'9' => {
                    if self.pos > start && len == 0 {
                        // "0" followed by more digits: leading zero.
                        return Err(DecodeError::BadLength { at: start });
                    }
                    len = len
                        .checked_mul(10)
                        .and_then(|l| l.checked_add(usize::from(b - b'0')))
                        .ok_or(DecodeError::BadLength { at: start })?;
                    self.pos += 1;
                }
                b':' => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(DecodeError::Unexpected { at: self.pos }),
            }
        }
        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeError::BadLength { at: start })?;
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn d(s: &[u8]) -> Result<Sexp, DecodeError> {
        decode(s, &Limits::default())
    }

    #[test]
    fn accepts_canonical() {
        assert_eq!(d(b"0:"), Ok(Sexp::atom("")));
        assert_eq!(d(b"()"), Ok(Sexp::list(vec![])));
        assert_eq!(
            d(b"(3:abc(1:x)10:0123456789)"),
            Ok(Sexp::list(vec![
                Sexp::atom("abc"),
                Sexp::list(vec![Sexp::atom("x")]),
                Sexp::atom("0123456789"),
            ]))
        );
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(d(b"03:abc"), Err(DecodeError::BadLength { at: 0 }));
        assert_eq!(d(b"00:"), Err(DecodeError::BadLength { at: 0 }));
        assert_eq!(d(b"( 1:a)"), Err(DecodeError::Unexpected { at: 1 }));
        assert_eq!(d(b"[1:a]1:b"), Err(DecodeError::Unexpected { at: 0 }));
        assert_eq!(d(b"1:ab"), Err(DecodeError::TrailingData { at: 3 }));
        assert_eq!(d(b"(1:a"), Err(DecodeError::Truncated));
        assert_eq!(d(b"5:abc"), Err(DecodeError::Truncated));
        assert_eq!(d(b""), Err(DecodeError::Truncated));
        assert_eq!(d(b"3abc"), Err(DecodeError::Unexpected { at: 1 }));
        assert_eq!(d(b")"), Err(DecodeError::Unexpected { at: 0 }));
        assert_eq!(
            d(b"99999999999999999999999:"),
            Err(DecodeError::BadLength { at: 0 })
        );
    }

    #[test]
    fn enforces_limits() {
        let deep = [b"(".repeat(33), b")".repeat(33)].concat();
        assert_eq!(d(&deep), Err(DecodeError::TooLarge));
        let ok = [b"(".repeat(32), b")".repeat(32)].concat();
        assert!(d(&ok).is_ok());
        let limits = Limits {
            max_nodes: 3,
            ..Limits::default()
        };
        assert!(decode(b"(0:0:)", &limits).is_ok());
        assert_eq!(decode(b"(0:0:0:)", &limits), Err(DecodeError::TooLarge));
        let limits = Limits {
            max_len: 3,
            ..Limits::default()
        };
        assert_eq!(decode(b"2:ab", &limits), Err(DecodeError::TooLarge));
    }

    #[test]
    fn prefix() {
        let l = Limits::default();
        assert_eq!(
            decode_prefix(b"(1:a)1:b", &l),
            Ok((Sexp::list(vec![Sexp::atom("a")]), 5))
        );
        assert_eq!(decode_prefix(b"1:b", &l), Ok((Sexp::atom("b"), 3)));
        assert_eq!(decode_prefix(b"", &l), Err(DecodeError::Truncated));
        assert_eq!(decode_prefix(b"(1:a", &l), Err(DecodeError::Truncated));
        // Limits apply per expression, not to what follows it.
        let small = Limits {
            max_len: 5,
            max_nodes: 2,
            ..l
        };
        assert_eq!(
            decode_prefix(b"(1:a)(1:a)(1:a)", &small),
            Ok((Sexp::list(vec![Sexp::atom("a")]), 5))
        );
        assert_eq!(decode_prefix(b"(1:ab)", &small), Err(DecodeError::TooLarge));
        assert_eq!(decode_prefix(b"9:a", &small), Err(DecodeError::Truncated));
        assert_eq!(
            decode_prefix(b"9:abcdefghi", &small),
            Err(DecodeError::TooLarge)
        );
        assert_eq!(decode_prefix(b"(0:0:)", &small), Err(DecodeError::TooLarge));
    }
}
