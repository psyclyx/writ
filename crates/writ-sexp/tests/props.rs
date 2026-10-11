//! Property tests: round-trips, uniqueness of the canonical encoding, and
//! that rejected input really is invalid.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use proptest::prelude::*;
use writ_sexp::{Limits, Sexp, armor, base64, decode, decode_many, readable};

fn arb_sexp() -> impl Strategy<Value = Sexp> {
    let atom = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..40),
        "[a-z0-9/._-]{0,12}".prop_map(String::into_bytes),
        "\\PC{0,8}".prop_map(String::into_bytes),
    ]
    .prop_map(Sexp::Atom);
    atom.prop_recursive(6, 64, 8, |inner| {
        proptest::collection::vec(inner, 0..8).prop_map(Sexp::List)
    })
}

/// A reference check of canonical form, written independently of the
/// decoder: the input is a sequence of well-formed tokens with no leading
/// zeros and balanced parentheses.
fn is_canonical(input: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut i = 0;
    let mut seen = false;
    while i < input.len() {
        if seen && depth == 0 {
            return false;
        }
        match input[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                i += 1;
                seen = true;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < input.len() && input[i].is_ascii_digit() {
                    i += 1;
                }
                if i >= input.len() || input[i] != b':' {
                    return false;
                }
                let digits = &input[start..i];
                if digits.len() > 1 && digits[0] == b'0' {
                    return false;
                }
                let Ok(len) = std::str::from_utf8(digits).unwrap().parse::<usize>() else {
                    return false;
                };
                i += 1;
                if input.len() - i < len {
                    return false;
                }
                i += len;
                if depth == 0 {
                    seen = true;
                }
            }
            _ => return false,
        }
    }
    depth == 0 && seen
}

proptest! {
    #[test]
    fn canonical_round_trip(s in arb_sexp()) {
        let bytes = s.encode();
        prop_assert_eq!(bytes.len(), s.encoded_len());
        prop_assert_eq!(decode(&bytes, &Limits::default()), Ok(s));
    }

    #[test]
    fn readable_round_trip(s in arb_sexp()) {
        prop_assert_eq!(readable::parse(&s.to_readable()), Ok(s));
    }

    #[test]
    fn armor_round_trip(items in proptest::collection::vec(arb_sexp(), 0..4)) {
        let text: String = items.iter().map(|s| armor::encode(&s.encode())).collect();
        let blocks = armor::decode(text.as_bytes()).unwrap();
        let decoded: Vec<Sexp> = blocks
            .iter()
            .map(|b| decode(b, &Limits::default()).unwrap())
            .collect();
        prop_assert_eq!(decoded, items);
    }

    /// Decoding accepts exactly the canonical inputs, and an accepted input
    /// is the unique encoding of its tree.
    #[test]
    fn decode_is_exact(input in proptest::collection::vec(
        prop_oneof![Just(b'('), Just(b')'), Just(b':'), Just(b'0'), Just(b'1'), Just(b'2'), Just(b'a')],
        0..24,
    )) {
        let result = decode(&input, &Limits::default());
        prop_assert_eq!(result.is_ok(), is_canonical(&input));
        if let Ok(s) = result {
            prop_assert_eq!(s.encode(), input);
        }
    }

    /// Mutating one byte of a valid encoding either yields another canonical
    /// encoding (that re-encodes identically) or is rejected.
    #[test]
    fn mutations(s in arb_sexp(), idx in any::<prop::sample::Index>(), b in any::<u8>()) {
        let mut bytes = s.encode();
        let i = idx.index(bytes.len());
        bytes[i] = b;
        match decode(&bytes, &Limits::default()) {
            Ok(t) => prop_assert_eq!(t.encode(), bytes),
            Err(_) => prop_assert!(!is_canonical(&bytes)),
        }
    }

    #[test]
    fn many_round_trip(items in proptest::collection::vec(arb_sexp(), 0..4)) {
        let bytes: Vec<u8> = items.iter().flat_map(Sexp::encode).collect();
        prop_assert_eq!(decode_many(&bytes, &Limits::default()), Ok(items));
    }

    #[test]
    fn base64_round_trip(data in proptest::collection::vec(any::<u8>(), 0..100)) {
        let enc = base64::encode(&data);
        prop_assert_eq!(base64::decode(enc.as_bytes()), Some(data));
    }

    /// Strict base64: anything accepted re-encodes to itself.
    #[test]
    fn base64_unique(text in "[A-Za-z0-9+/=]{0,12}") {
        if let Some(data) = base64::decode(text.as_bytes()) {
            prop_assert_eq!(base64::encode(&data), text);
        }
    }

    #[test]
    fn readable_never_panics(text in "\\PC{0,40}") {
        let _ = readable::parse(&text);
    }

    #[test]
    fn armor_never_panics(text in "[-A-Za-z0-9+/= \n\r]{0,200}") {
        let _ = armor::decode(text.as_bytes());
    }
}
