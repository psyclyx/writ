//! Issuing: inception, rotation, statements, data signatures (DESIGN.md §13).
//!
//! Issuing applies the same rules the verifier does, so writ never produces
//! an item it would itself reject.

use crate::hash::{Hash, Id};
use crate::keys::{PublicKey, Rng, SignError, Signer};
use crate::log::Log;
use crate::model::{
    Authority, Body, Claim, DataSig, Event, Inception, Issuer, Publish, Record, Rotation, Sig,
    Signed, Statement,
};
use core::fmt;

/// Why something can't be issued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// The statement breaks a rule (see [`Statement::check_wellformed`]).
    Rule(&'static str),
    /// A signer's key is not in the authority.
    NotInAuthority,
    /// Fewer than `k` distinct signers.
    BelowThreshold {
        /// Needed.
        k: usize,
        /// Given.
        have: usize,
    },
    /// The revealed authority is not the one the log committed to.
    WrongNext,
    /// The statement's issuer is not the log's identity at its head event.
    WrongIssuer,
    /// `max-validity` requires an expiry no further than this many seconds.
    MaxValidity(u64),
    /// A leaf statement needs exactly one leaf signer.
    LeafSigner,
    /// The signer failed.
    Sign(SignError),
    /// The item would not decode (SPEC §3.1, §5): writ never signs what it
    /// can't read back.
    Encoding(crate::DecodeError),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueError::Rule(r) => f.write_str(r),
            IssueError::NotInAuthority => write!(f, "key is not in the current authority"),
            IssueError::BelowThreshold { k, have } => {
                write!(f, "need {k} signing keys, have {have}")
            }
            IssueError::WrongNext => {
                write!(
                    f,
                    "these keys are not the next authority the log committed to"
                )
            }
            IssueError::WrongIssuer => {
                write!(f, "issuer must be this identity at its latest event")
            }
            IssueError::MaxValidity(mv) => write!(
                f,
                "this identity requires every statement to expire within {}",
                crate::time::Duration(*mv)
            ),
            IssueError::LeafSigner => write!(f, "a leaf statement needs exactly one leaf key"),
            IssueError::Sign(e) => write!(f, "{e}"),
            IssueError::Encoding(e) => write!(f, "can't be encoded: {e}"),
        }
    }
}

impl std::error::Error for IssueError {}

impl From<SignError> for IssueError {
    fn from(e: SignError) -> Self {
        IssueError::Sign(e)
    }
}

/// Checks, before anything is signed, that the item will decode: its body
/// parses back to itself, and with up to 16 signatures attached it stays
/// within the per-item limits (SPEC §3.1). The CLI otherwise could sign a
/// subject or a `keep` list that every reader, itself included, rejects.
fn check_decodable<T: Body + PartialEq>(body: &T) -> Result<(), IssueError> {
    // "(" "7:writ/v1" body *("(" "3:sig" index bytes ")") ")"
    const SIGS: usize = 16 * (crate::keys::ROOT_SIGNATURE_SIZE + 16) + 16;
    let limits = writ_sexp::Limits::default();
    let bytes = body.encode();
    let within = writ_sexp::Limits {
        max_len: limits.max_len - SIGS,
        max_nodes: limits.max_nodes - 2 - 4 * 16,
        max_depth: limits.max_depth - 1,
    };
    let sexp = writ_sexp::decode(&bytes, &within)
        .map_err(|e| IssueError::Encoding(crate::DecodeError::Sexp(e)))?;
    match T::from_sexp(&sexp) {
        Ok(back) if back == *body => Ok(()),
        Ok(_) => Err(IssueError::Encoding(crate::DecodeError::NonCanonical)),
        Err(e) => Err(IssueError::Encoding(e)),
    }
}

/// Checks, after signing, that the whole item decodes: the body checks of
/// [`check_decodable`] cannot see that the signatures fit the issuer (a leaf
/// issuer with root-sized signatures, say).
fn check_item<T: Body>(signed: &Signed<T>) -> Result<(), IssueError> {
    crate::model::Item::decode(&T::item(signed).encode())
        .map(|_| ())
        .map_err(IssueError::Encoding)
}

/// Signs `body` with `signers`, all of whose keys must be in `authority`,
/// at least `k` of them distinct. This is the raw entry point: it applies
/// the encoding rules and [`Body::check_signable`], not the issuing rules
/// of [`issue()`], [`rotate`] or [`sign_data`] (well-formedness, the
/// log's head, `max-validity`), so it can also make the deliberately
/// irregular items that tests and vectors need.
pub fn sign_with_authority<T: Body + PartialEq>(
    body: T,
    authority: &Authority,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<Signed<T>, IssueError> {
    body.check_signable().map_err(IssueError::Rule)?;
    check_decodable(&body)?;
    let msg = body.message();
    let mut sigs: Vec<Sig> = Vec::new();
    for signer in signers {
        let PublicKey::Root(key) = signer.public_key() else {
            return Err(IssueError::NotInAuthority);
        };
        let index = authority.index_of(&key).ok_or(IssueError::NotInAuthority)?;
        if sigs.iter().any(|s| s.index == index) {
            continue;
        }
        sigs.push(Sig {
            index,
            bytes: signer.sign(&msg, rng)?,
        });
    }
    if sigs.len() < authority.k() {
        return Err(IssueError::BelowThreshold {
            k: authority.k(),
            have: sigs.len(),
        });
    }
    sigs.sort_by_key(|s| s.index);
    let signed = Signed { body, sigs };
    check_item(&signed)?;
    Ok(signed)
}

/// Creates an identity: event 0, signed by `k` of `authority`, committing
/// to `next` (DESIGN.md §4.2).
pub fn incept(
    authority: Authority,
    next: &Authority,
    max_validity: Option<u64>,
    publish: Option<Publish>,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<(Id, Signed<Event>), IssueError> {
    if max_validity == Some(0) {
        return Err(IssueError::Rule("max-validity must be positive"));
    }
    let event = Event::Inception(Inception {
        authority: authority.clone(),
        next: next.hash(),
        max_validity,
        publish,
    });
    let id = event.id();
    Ok((id, sign_with_authority(event, &authority, signers, rng)?))
}

/// What a rotation sets (DESIGN.md §4.3).
#[derive(Clone, Debug)]
pub struct RotationPlan {
    /// The next authority the log committed to. It signs the rotation.
    pub revealed: Authority,
    /// The new current authority, which signs statements from now on.
    pub authority: Authority,
    /// The authority allowed to sign the following rotation. It may be
    /// `revealed` again: next keys can serve for many rotations.
    pub next: Authority,
    /// The statement lifetime limit from now on.
    pub max_validity: Option<u64>,
    /// Where the identity publishes revocation records from now on.
    pub publish: Option<Publish>,
    /// Earlier statements and signatures that stay valid.
    pub keep: Vec<Hash>,
}

/// Extends `log` with a rotation. `plan.revealed` must hash to the head's
/// `next`; `k` of its keys sign.
pub fn rotate(
    log: &Log,
    plan: RotationPlan,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<Signed<Event>, IssueError> {
    let RotationPlan {
        revealed,
        authority,
        next,
        max_validity,
        publish,
        mut keep,
    } = plan;
    if revealed.hash() != *log.head().next() {
        return Err(IssueError::WrongNext);
    }
    if max_validity == Some(0) {
        return Err(IssueError::Rule("max-validity must be positive"));
    }
    keep.sort();
    keep.dedup();
    let prev = log
        .event_hash(log.head_n())
        .ok_or(IssueError::Rule("empty log"))?;
    let event = Event::Rotation(Rotation {
        id: log.id(),
        n: log.head_n() + 1,
        prev,
        revealed: revealed.clone(),
        authority,
        next: next.hash(),
        max_validity,
        publish,
        keep,
    });
    sign_with_authority(event, &revealed, signers, rng)
}

/// Issues a statement as the identity of `log`, under its latest event.
pub fn issue(
    statement: Statement,
    log: &Log,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<Signed<Statement>, IssueError> {
    statement.check_wellformed().map_err(IssueError::Rule)?;
    match statement.issuer {
        Issuer::Identity { id, event } if id == log.id() && event == log.head_n() => {}
        _ => return Err(IssueError::WrongIssuer),
    }
    if let Some(mv) = log.head().max_validity()
        && !matches!(statement.claim, Claim::Revoke { .. })
    {
        match statement.expires {
            Some(e) if e - statement.issued <= mv => {}
            _ => return Err(IssueError::MaxValidity(mv)),
        }
    }
    sign_with_authority(statement, log.head().authority(), signers, rng)
}

/// Issues a statement as a leaf key.
pub fn issue_leaf(
    statement: Statement,
    signer: &dyn Signer,
    rng: &mut dyn Rng,
) -> Result<Signed<Statement>, IssueError> {
    statement.check_wellformed().map_err(IssueError::Rule)?;
    sign_leaf(statement, signer, rng)
}

/// Signs data as the identity of `log` (DESIGN.md §8).
pub fn sign_data(
    data: Hash,
    context: &[u8],
    issued: crate::Time,
    log: &Log,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<Signed<DataSig>, IssueError> {
    check_context(context)?;
    let body = DataSig {
        signer: Issuer::Identity {
            id: log.id(),
            event: log.head_n(),
        },
        issued,
        context: context.to_vec(),
        data,
    };
    sign_with_authority(body, log.head().authority(), signers, rng)
}

/// Signs a revocation record (DESIGN.md §18.4) as the identity of `log`,
/// under its head: everything in `revoked` is revoked, and the record is
/// fresh from `issued`. `revoked` may be in any order; duplicates are dropped.
pub fn sign_record(
    log: &Log,
    mut revoked: Vec<Hash>,
    issued: crate::Time,
    signers: &[&dyn Signer],
    rng: &mut dyn Rng,
) -> Result<Signed<Record>, IssueError> {
    revoked.sort();
    revoked.dedup();
    let head = log
        .event_hash(log.head_n())
        .ok_or(IssueError::Rule("empty log"))?;
    let body = Record {
        id: log.id(),
        event: log.head_n(),
        issued,
        head,
        revoked,
    };
    sign_with_authority(body, log.head().authority(), signers, rng)
}

/// Signs data with a leaf key.
pub fn sign_data_leaf(
    data: Hash,
    context: &[u8],
    issued: crate::Time,
    signer: &dyn Signer,
    rng: &mut dyn Rng,
) -> Result<Signed<DataSig>, IssueError> {
    check_context(context)?;
    sign_data_leaf_any(data, context, issued, signer, rng)
}

/// [`sign_data_leaf`] without refusing writ's own contexts: for writ's
/// own uses, such as channel binding.
pub(crate) fn sign_data_leaf_any(
    data: Hash,
    context: &[u8],
    issued: crate::Time,
    signer: &dyn Signer,
    rng: &mut dyn Rng,
) -> Result<Signed<DataSig>, IssueError> {
    if context.is_empty() || context.len() > crate::model::MAX_ATOM {
        return Err(IssueError::Rule("context must be 1 to 255 bytes"));
    }
    let PublicKey::Leaf(key) = signer.public_key() else {
        return Err(IssueError::LeafSigner);
    };
    let body = DataSig {
        signer: Issuer::Leaf(key.id()),
        issued,
        context: context.to_vec(),
        data,
    };
    sign_leaf(body, signer, rng)
}

/// Contexts starting with this are writ's own (channel binding, DESIGN.md
/// §18.3): applications can't sign data under them, so a file signature can
/// never pass for one.
pub const RESERVED_CONTEXT: &[u8] = b"writ/";

fn check_context(context: &[u8]) -> Result<(), IssueError> {
    if context.is_empty() || context.len() > crate::model::MAX_ATOM {
        return Err(IssueError::Rule("context must be 1 to 255 bytes"));
    }
    if context.starts_with(RESERVED_CONTEXT) {
        return Err(IssueError::Rule(
            "contexts starting with writ/ are reserved for writ",
        ));
    }
    Ok(())
}

fn sign_leaf<T: Body + LeafIssued + PartialEq>(
    body: T,
    signer: &dyn Signer,
    rng: &mut dyn Rng,
) -> Result<Signed<T>, IssueError> {
    check_decodable(&body)?;
    let PublicKey::Leaf(key) = signer.public_key() else {
        return Err(IssueError::LeafSigner);
    };
    if body.leaf_issuer() != Some(key.id()) {
        return Err(IssueError::WrongIssuer);
    }
    let bytes = signer.sign(&body.message(), rng)?;
    let signed = Signed {
        body,
        sigs: vec![Sig { index: 0, bytes }],
    };
    check_item(&signed)?;
    Ok(signed)
}

trait LeafIssued {
    fn leaf_issuer(&self) -> Option<crate::LeafId>;
}

impl LeafIssued for Statement {
    fn leaf_issuer(&self) -> Option<crate::LeafId> {
        match &self.issuer {
            Issuer::Leaf(k) => Some(*k),
            Issuer::Identity { .. } => None,
        }
    }
}

impl LeafIssued for DataSig {
    fn leaf_issuer(&self) -> Option<crate::LeafId> {
        match &self.signer {
            Issuer::Leaf(k) => Some(*k),
            Issuer::Identity { .. } => None,
        }
    }
}
