//! Tags: flat paths of atoms (DESIGN.md §6).
//!
//! `a ⊆ b` iff `b` is a prefix of `a`; `∩(a, b)` is the longer of the two if
//! one is a prefix of the other, else nothing. `()` is everything.

use crate::model::{DecodeError, MAX_ATOM};
use writ_sexp::Sexp;

/// Most atoms in a tag.
pub const MAX_TAG_LEN: usize = 32;

/// A tag, e.g. `(zuko home relay)`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(Vec<Vec<u8>>);

impl Tag {
    /// `()`: everything.
    pub fn everything() -> Tag {
        Tag(Vec::new())
    }

    /// A tag from atoms. `None` if too long or an atom is empty or too long.
    pub fn new(atoms: Vec<Vec<u8>>) -> Option<Tag> {
        let ok = atoms.len() <= MAX_TAG_LEN
            && atoms.iter().all(|a| !a.is_empty() && a.len() <= MAX_ATOM);
        ok.then_some(Tag(atoms))
    }

    /// The atoms, general to specific.
    pub fn atoms(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// `self ⊆ other`: `other` is a prefix of `self`.
    pub fn is_within(&self, other: &Tag) -> bool {
        self.0.starts_with(&other.0)
    }

    /// `∩(self, other)`.
    pub fn intersect(&self, other: &Tag) -> Option<Tag> {
        if self.is_within(other) {
            Some(self.clone())
        } else if other.is_within(self) {
            Some(other.clone())
        } else {
            None
        }
    }

    /// `(tag ATOM…)`.
    pub fn to_sexp(&self) -> Sexp {
        let mut v = vec![Sexp::atom("tag")];
        v.extend(self.0.iter().map(Sexp::atom));
        Sexp::List(v)
    }

    pub(crate) fn from_sexp(s: &Sexp) -> Result<Tag, DecodeError> {
        match s.as_list() {
            Some([Sexp::Atom(h), rest @ ..]) if h == b"tag" => {
                let atoms = rest
                    .iter()
                    .map(|a| a.as_atom().map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(DecodeError::Malformed("tag atoms"))?;
                Tag::new(atoms).ok_or(DecodeError::Malformed("tag"))
            }
            _ => Err(DecodeError::Malformed("tag")),
        }
    }

    /// Readable form: `(zuko home)`.
    pub fn to_readable(&self) -> String {
        Sexp::List(self.0.iter().map(Sexp::atom).collect()).to_readable()
    }

    /// Parses what a human types: `(zuko home)`, `zuko home`, or `()`.
    pub fn parse(text: &str) -> Option<Tag> {
        let trimmed = text.trim();
        let sexp = if trimmed.starts_with('(') {
            writ_sexp::readable::parse(trimmed).ok()?
        } else {
            Sexp::List(writ_sexp::readable::parse_many(trimmed).ok()?)
        };
        let atoms = sexp
            .as_list()?
            .iter()
            .map(|a| a.as_atom().map(<[u8]>::to_vec))
            .collect::<Option<Vec<_>>>()?;
        Tag::new(atoms)
    }
}

impl core::fmt::Display for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_readable())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn t(s: &str) -> Tag {
        Tag::parse(s).unwrap_or_default()
    }

    #[test]
    fn examples() {
        assert!(t("(zuko home relay)").is_within(&t("(zuko home)")));
        assert!(t("(zuko home)").is_within(&t("(zuko)")));
        assert!(t("(zuko)").is_within(&t("()")));
        assert!(!t("(zuko homework)").is_within(&t("(zuko home)")));
        assert!(!t("(zuko)").is_within(&t("(zuko home)")));
        assert_eq!(
            t("(zuko)").intersect(&t("(zuko home)")),
            Some(t("(zuko home)"))
        );
        assert_eq!(t("(zuko a)").intersect(&t("(zuko b)")), None);
        assert_eq!(t("zuko home"), t("(zuko home)"));
        assert_eq!(Tag::parse("()"), Some(Tag::everything()));
        assert_eq!(Tag::parse(""), Some(Tag::everything()));
        assert_eq!(Tag::parse("(a (b))"), None);
        assert_eq!(Tag::parse("(\"\")"), None);
        assert_eq!(t("(ssh \"my host\")").to_string(), "(ssh \"my host\")");
    }

    fn arb_tag() -> impl Strategy<Value = Tag> {
        proptest::collection::vec(
            prop_oneof![
                Just(b"a".to_vec()),
                Just(b"b".to_vec()),
                Just(b"ab".to_vec())
            ],
            0..4,
        )
        .prop_map(Tag)
    }

    proptest! {
        #[test]
        fn intersect_commutative(a in arb_tag(), b in arb_tag()) {
            prop_assert_eq!(a.intersect(&b), b.intersect(&a));
        }

        #[test]
        fn intersect_associative(a in arb_tag(), b in arb_tag(), c in arb_tag()) {
            let left = a.intersect(&b).and_then(|ab| ab.intersect(&c));
            let right = b.intersect(&c).and_then(|bc| a.intersect(&bc));
            prop_assert_eq!(left, right);
        }

        #[test]
        fn intersect_idempotent(a in arb_tag()) {
            prop_assert_eq!(a.intersect(&a), Some(a));
        }

        #[test]
        fn everything_is_identity(a in arb_tag()) {
            prop_assert_eq!(a.intersect(&Tag::everything()), Some(a));
        }

        /// ∩ is the greatest lower bound under ⊆.
        #[test]
        fn intersect_is_meet(a in arb_tag(), b in arb_tag(), c in arb_tag()) {
            match a.intersect(&b) {
                Some(m) => {
                    prop_assert!(m.is_within(&a) && m.is_within(&b));
                    if c.is_within(&a) && c.is_within(&b) {
                        prop_assert!(c.is_within(&m));
                    }
                }
                None => prop_assert!(!(c.is_within(&a) && c.is_within(&b))),
            }
        }

        #[test]
        fn within_is_partial_order(a in arb_tag(), b in arb_tag(), c in arb_tag()) {
            prop_assert!(a.is_within(&a));
            if a.is_within(&b) && b.is_within(&a) { prop_assert_eq!(&a, &b); }
            if a.is_within(&b) && b.is_within(&c) { prop_assert!(a.is_within(&c)); }
        }

        #[test]
        fn readable_round_trip(a in arb_tag()) {
            prop_assert_eq!(Tag::parse(&a.to_readable()), Some(a));
        }
    }
}
