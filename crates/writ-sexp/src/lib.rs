//! Canonical S-expressions (Rivest csexp) and writ's strict PEM-subset armor.
//!
//! See DESIGN.md §12 and SPEC.md. No dependencies.
//!
//! Three representations of the same tree:
//!
//! - **canonical** ([`Sexp::encode`], [`decode`]): `3:abc`, `(…)`. What is
//!   signed and hashed. Exactly one encoding per tree; anything else is
//!   rejected.
//! - **readable** ([`readable::parse`], [`Sexp::to_readable`]): what humans
//!   type and read, e.g. `(zuko home "a b" #00ff# |AAEC|)`.
//! - **armor** ([`armor`]): canonical bytes wrapped in strict PEM blocks.
#![no_std]

extern crate alloc;

pub mod armor;
pub mod base64;
mod canonical;
pub mod readable;

pub use canonical::{DecodeError, Limits, decode, decode_many};

use alloc::vec::Vec;

/// An S-expression: a byte-string atom or a list.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Sexp {
    /// A byte string. May be empty.
    Atom(Vec<u8>),
    /// A list of expressions. May be empty.
    List(Vec<Sexp>),
}

impl Sexp {
    /// An atom from anything byte-like.
    pub fn atom(bytes: impl AsRef<[u8]>) -> Self {
        Sexp::Atom(bytes.as_ref().to_vec())
    }

    /// A list.
    pub fn list(items: impl Into<Vec<Sexp>>) -> Self {
        Sexp::List(items.into())
    }

    /// The bytes of an atom, or `None` for a list.
    pub fn as_atom(&self) -> Option<&[u8]> {
        match self {
            Sexp::Atom(a) => Some(a),
            Sexp::List(_) => None,
        }
    }

    /// The items of a list, or `None` for an atom.
    pub fn as_list(&self) -> Option<&[Sexp]> {
        match self {
            Sexp::Atom(_) => None,
            Sexp::List(l) => Some(l),
        }
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Appends the canonical encoding to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Sexp::Atom(a) => {
                push_decimal(out, a.len());
                out.push(b':');
                out.extend_from_slice(a);
            }
            Sexp::List(items) => {
                out.push(b'(');
                for item in items {
                    item.encode_into(out);
                }
                out.push(b')');
            }
        }
    }

    /// Length of the canonical encoding in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Sexp::Atom(a) => decimal_len(a.len()) + 1 + a.len(),
            Sexp::List(items) => 2 + items.iter().map(Sexp::encoded_len).sum::<usize>(),
        }
    }

    /// The readable form on one line. See [`readable`].
    pub fn to_readable(&self) -> alloc::string::String {
        readable::print(self)
    }
}

fn decimal_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 10 {
        n /= 10;
        len += 1;
    }
    len
}

fn push_decimal(out: &mut Vec<u8>, n: usize) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut n = n;
    loop {
        i -= 1;
        if let Some(d) = digits.get_mut(i) {
            *d = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(i..).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encodes() {
        let s = Sexp::list(vec![
            Sexp::atom("grant"),
            Sexp::atom(""),
            Sexp::list(vec![]),
            Sexp::atom([0u8; 10]),
        ]);
        let mut want = b"(5:grant0:()10:".to_vec();
        want.extend_from_slice(&[0; 10]);
        want.push(b')');
        assert_eq!(s.encode(), want);
        assert_eq!(s.encoded_len(), want.len());
    }
}
