//! writ: signed statements about keys — names, grants, revocation, identity logs.
//!
//! Pure: no IO, no clock, no ambient randomness. See DESIGN.md and SPEC.md.
//!
//! - Build [`Material`] from items ([`Item::decode_bundle`]).
//! - Ask a [`Verifier`] for your roots: [`Verifier::check`],
//!   [`Verifier::resolve`], [`Verifier::verify`]. Answers come with a
//!   [`Proof`]; denials with a [`Denial`] that says why.
//! - Issue with [`incept`], [`rotate`], [`issue`], [`sign_data`].

pub mod bech32;
mod hash;
pub mod issue;
pub mod keys;
mod log;
mod material;
pub mod model;
mod tag;
pub mod time;
mod verify;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod reference;
#[cfg(test)]
mod scenarios;
#[cfg(test)]
mod testing;

pub use hash::{DataHasher, Hash, ID_HRP, Id, LeafId, label, labelled_message};
pub use issue::{
    IssueError, RotationPlan, incept, issue, issue_leaf, rotate, sign_data, sign_data_leaf,
    sign_record, sign_with_authority,
};
pub use keys::{LeafKey, PublicKey, Rng, RootKey, Seed, Signer, Suite};
pub use log::{Evidence, Log, LogError, equivocation};
pub use material::{Material, Principal};
pub use model::{
    Authority, Body, Claim, DataSig, DecodeError, Event, Inception, Issuer, Item, NamePath,
    OpaqueKey, Publish, Record, Rotation, Sig, Signed, Statement, Subject,
};
pub use tag::{MAX_GRANT_TAGS, Tag, Tags, TagsError};
pub use time::{Floor, Time};
pub use verify::{Denial, Holder, Policy, Proof, Reason, Rejection, Step, Verifier};
/// Re-exported so callers can hold secrets without depending on `zeroize`.
pub use zeroize::Zeroizing;

/// `∩(a, b)` (DESIGN.md §6).
pub fn tag_intersect(a: &Tag, b: &Tag) -> Option<Tag> {
    a.intersect(b)
}
