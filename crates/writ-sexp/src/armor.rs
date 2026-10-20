//! Strict PEM-subset armor, one block per item (DESIGN.md §12).
//!
//! ```text
//! -----BEGIN WRIT-----
//! <standard padded base64, exactly 64 columns per line, last line 1–64>
//! -----END WRIT-----
//! ```
//!
//! No headers. Lines end in LF or CRLF. Whitespace (space, tab, CR, LF) is
//! allowed between and around blocks; anything else is rejected. A bundle is
//! any number of blocks, so concatenating armored files composes.

use crate::base64;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// The first line of a block.
pub const BEGIN: &str = "-----BEGIN WRIT-----";
/// The last line of a block.
pub const END: &str = "-----END WRIT-----";
const COLUMNS: usize = 64;

/// Armors one item.
pub fn encode(data: &[u8]) -> String {
    let b64 = base64::encode(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / COLUMNS + 48);
    out.push_str(BEGIN);
    out.push('\n');
    for line in b64.as_bytes().chunks(COLUMNS) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.extend(line.iter().map(|&b| char::from(b)));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Why armored text was rejected. Lines are 1-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmorError {
    /// Something other than whitespace or a BEGIN line outside a block.
    ExpectedBegin {
        /// Line number.
        line: usize,
    },
    /// A block was not terminated by an END line.
    MissingEnd {
        /// Line number of the BEGIN line.
        line: usize,
    },
    /// A body line is not exactly 64 columns (or 1–64 for the last).
    BadLineLength {
        /// Line number.
        line: usize,
    },
    /// The body is not canonical padded base64, or is empty.
    BadBase64 {
        /// Line number of the BEGIN line.
        line: usize,
    },
    /// The block encodes more than the caller's limit for one item.
    TooLarge {
        /// Line number of the BEGIN line.
        line: usize,
    },
}

impl fmt::Display for ArmorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArmorError::ExpectedBegin { line } => {
                write!(f, "line {line}: expected `{BEGIN}`")
            }
            ArmorError::MissingEnd { line } => {
                write!(f, "line {line}: block has no `{END}` line")
            }
            ArmorError::BadLineLength { line } => {
                write!(f, "line {line}: armor lines must be {COLUMNS} columns")
            }
            ArmorError::BadBase64 { line } => {
                write!(f, "line {line}: block is not canonical base64")
            }
            ArmorError::TooLarge { line } => {
                write!(f, "line {line}: block is larger than one item may be")
            }
        }
    }
}

impl core::error::Error for ArmorError {}

/// Whether `text` looks like armor (its first non-whitespace line is BEGIN).
pub fn is_armored(text: &[u8]) -> bool {
    let start = text
        .iter()
        .position(|b| !is_space(*b))
        .unwrap_or(text.len());
    text.get(start..)
        .is_some_and(|t| t.starts_with(BEGIN.as_bytes()))
}

/// Decodes every block in `text`, with no limit on a block's size.
pub fn decode(text: &[u8]) -> Result<Vec<Vec<u8>>, ArmorError> {
    decode_bounded(text, usize::MAX)
}

/// Decodes every block in `text`, refusing a block that would decode to
/// more than `max_item` bytes before decoding it, so an oversized block
/// costs no more than reading its lines.
pub fn decode_bounded(text: &[u8], max_item: usize) -> Result<Vec<Vec<u8>>, ArmorError> {
    // Base64 of n bytes is 4·⌈n/3⌉ characters.
    let max_body = max_item.div_ceil(3).saturating_mul(4);
    let mut items = Vec::new();
    let mut lines = text.split(|&b| b == b'\n').enumerate().peekable();
    while let Some((i, raw)) = lines.next() {
        let line = strip_cr(raw);
        if line.iter().all(|b| is_space(*b)) {
            continue;
        }
        if line != BEGIN.as_bytes() {
            return Err(ArmorError::ExpectedBegin { line: i + 1 });
        }
        let begin = i + 1;
        let mut body = Vec::new();
        let mut short_line = false;
        loop {
            let Some((j, raw)) = lines.next() else {
                return Err(ArmorError::MissingEnd { line: begin });
            };
            let line = strip_cr(raw);
            if line == END.as_bytes() {
                break;
            }
            if line.is_empty() && lines.peek().is_none() {
                return Err(ArmorError::MissingEnd { line: begin });
            }
            if short_line || line.is_empty() || line.len() > COLUMNS {
                return Err(ArmorError::BadLineLength { line: j + 1 });
            }
            short_line = line.len() < COLUMNS;
            if body.len() + line.len() > max_body {
                return Err(ArmorError::TooLarge { line: begin });
            }
            body.extend_from_slice(line);
        }
        match base64::decode(&body) {
            Some(data) if !data.is_empty() => items.push(data),
            _ => return Err(ArmorError::BadBase64 { line: begin }),
        }
    }
    Ok(items)
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip() {
        for len in [1, 2, 3, 47, 48, 49, 96, 1000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let text = encode(&data);
            assert!(is_armored(text.as_bytes()));
            assert_eq!(decode(text.as_bytes()), Ok(vec![data]));
        }
    }

    #[test]
    fn concatenation_composes() {
        let a = encode(b"first");
        let b = encode(b"second");
        let text = alloc::format!("\n \t\n{a}\r\n{b}\n\n");
        assert_eq!(
            decode(text.as_bytes()),
            Ok(vec![b"first".to_vec(), b"second".to_vec()])
        );
        assert_eq!(decode(b"  \n"), Ok(vec![]));
    }

    #[test]
    fn bounded() {
        let text = encode(&[7u8; 100]);
        assert_eq!(decode_bounded(text.as_bytes(), 100).map(|v| v.len()), Ok(1));
        assert_eq!(
            decode_bounded(text.as_bytes(), 99),
            Err(ArmorError::TooLarge { line: 1 })
        );
        // The limit is on what a block decodes to, not on the text, at the
        // granularity of base64's three-byte groups.
        for len in [1, 2, 3, 4, 5, 6, 63, 64, 65, 66] {
            let text = encode(&vec![1u8; len]);
            assert!(decode_bounded(text.as_bytes(), len).is_ok(), "{len}");
            if len > 3 {
                assert!(decode_bounded(text.as_bytes(), len - 3).is_err(), "{len}");
            }
        }
    }

    #[test]
    fn crlf() {
        let text = encode(b"hello").replace('\n', "\r\n");
        assert_eq!(decode(text.as_bytes()), Ok(vec![b"hello".to_vec()]));
    }

    #[test]
    fn rejects() {
        let good = encode(&[7u8; 100]);
        let cases: &[(String, ArmorError)] = &[
            (
                good.replace("BEGIN WRIT", "BEGIN AGE"),
                ArmorError::ExpectedBegin { line: 1 },
            ),
            (
                alloc::format!("junk\n{good}"),
                ArmorError::ExpectedBegin { line: 1 },
            ),
            (
                alloc::format!("{good}junk"),
                ArmorError::ExpectedBegin { line: 6 },
            ),
            (good.replace(END, ""), ArmorError::BadLineLength { line: 5 }),
            (
                good.replace(&alloc::format!("\n{END}\n"), "\n"),
                ArmorError::MissingEnd { line: 1 },
            ),
            // A header line.
            (
                good.replace(BEGIN, &alloc::format!("{BEGIN}\nKey: v\n")),
                ArmorError::BadLineLength { line: 3 },
            ),
            // Rewrapped at 76 columns.
            (
                alloc::format!(
                    "{BEGIN}\n{}\n{}\n{END}\n",
                    &base64::encode(&[7u8; 100])[..76],
                    &base64::encode(&[7u8; 100])[76..]
                ),
                ArmorError::BadLineLength { line: 2 },
            ),
            // Short line followed by more data.
            (
                alloc::format!("{BEGIN}\nAAAA\nAAAA\n{END}\n"),
                ArmorError::BadLineLength { line: 3 },
            ),
            (
                alloc::format!("{BEGIN}\nAAB=\n{END}\n"),
                ArmorError::BadBase64 { line: 1 },
            ),
            (
                alloc::format!("{BEGIN}\n{END}\n"),
                ArmorError::BadBase64 { line: 1 },
            ),
            (
                alloc::format!("{BEGIN}\nAAAA"),
                ArmorError::MissingEnd { line: 1 },
            ),
            (
                alloc::format!("{BEGIN}\n AAAA\n{END}\n"),
                ArmorError::BadBase64 { line: 1 },
            ),
        ];
        for (text, err) in cases {
            assert_eq!(decode(text.as_bytes()), Err(*err), "{text}");
        }
    }
}
