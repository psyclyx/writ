//! Channel binding (DESIGN.md §18.3): tying a secure channel made by TLS
//! 1.3, DTLS, QUIC or Noise to a key writ vouches for. writ does no key
//! exchange; this is the step applications get wrong when they do it
//! themselves: checking the key the handshake authenticated, not one the
//! peer merely claims.
//!
//! After the handshake, each side takes the channel's exporter value `E`
//! (TLS: the exporter of RFC 8446 §7.5 with label `EXPORTER-writ-channel`;
//! Noise: the handshake hash), signs it with its leaf key ([`bind`]), and
//! sends the signature. The other side checks it ([`check`]): the signature
//! is over this channel's `E`, by the peer's role, and its key holds the
//! tag the application requires.

use crate::hash::{DataHasher, Hash};
use crate::issue::{IssueError, sign_data_leaf_any};
use crate::keys::{Rng, Signer};
use crate::model::{DataSig, MAX_ATOM, Signed};
use crate::tag::Tag;
use crate::time::Time;
use crate::verify::{Denial, Proof, Verifier};

/// Which side of the handshake a binding is for. Part of what is signed,
/// so a binding cannot be reflected back to its signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The side that started the handshake.
    Initiator,
    /// The other side.
    Responder,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Initiator => 1,
            Role::Responder => 2,
        }
    }
}

/// Shortest exporter value accepted, in bytes.
pub const MIN_EXPORTER: usize = 32;

/// `writ/v1/channel/<app>`: the context of a binding for `app`.
fn context(app: &str) -> Option<Vec<u8>> {
    let mut c = b"writ/v1/channel/".to_vec();
    c.extend_from_slice(app.as_bytes());
    (!app.is_empty() && c.len() <= MAX_ATOM).then_some(c)
}

/// `D(role ‖ E)`: what a binding signs.
fn data(exporter: &[u8], role: Role) -> Hash {
    let mut h = DataHasher::new();
    h.update(&[role.byte()]);
    h.update(exporter);
    h.finish()
}

/// Binds the channel with exporter value `exporter` to `signer`, a leaf
/// key, for the side `role` and the application `app`.
pub fn bind(
    exporter: &[u8],
    role: Role,
    app: &str,
    issued: Time,
    signer: &dyn Signer,
    rng: &mut dyn Rng,
) -> Result<Signed<DataSig>, IssueError> {
    if exporter.len() < MIN_EXPORTER {
        return Err(IssueError::Rule(
            "the exporter value must be at least 32 bytes",
        ));
    }
    let context = context(app).ok_or(IssueError::Rule(
        "the application name must be 1 to 239 bytes",
    ))?;
    sign_data_leaf_any(data(exporter, role), &context, issued, signer, rng)
}

/// Checks the peer's binding `sig`: it binds this channel (`exporter`) for
/// the peer's `role` and `app`, and its signer holds `tag` from the
/// verifier's roots at `now`. Returns the proof, as [`Verifier::verify`]
/// does.
pub fn check(
    verifier: &Verifier<'_>,
    sig: &Signed<DataSig>,
    exporter: &[u8],
    role: Role,
    app: &str,
    tag: &Tag,
    now: Time,
) -> Result<Proof, Denial> {
    if exporter.len() < MIN_EXPORTER {
        return Err(Denial::Data);
    }
    let context = context(app).ok_or(Denial::Context)?;
    verifier.verify(sig, &data(exporter, role), &context, tag, now)
}
