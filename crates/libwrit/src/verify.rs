//! Verification (DESIGN.md §9): `check`, `resolve`, `verify`, with proofs
//! and reasons.
//!
//! Search is structural first: a statement's signatures are checked only
//! once it lies on a candidate path, and results are cached by hash in the
//! [`Material`].

use crate::hash::{Hash, Id};
use crate::keys::{LeafKey, Suite};
use crate::log::{Evidence, Log, LogError};
use crate::material::{Material, Principal};
use crate::model::{
    Body, Claim, DataSig, Issuer, Item, LEAF_CEILING, NamePath, OpaqueKey, Sig, Signed, Statement,
    Subject,
};
use crate::tag::Tag;
use crate::time::{Rfc3339, Time};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::rc::Rc;

/// Verifier policy (DESIGN.md §9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Accepted suites. Default: both v1 suites.
    pub suites: Vec<Suite>,
    /// Longest accepted leaf grant, ≤ [`LEAF_CEILING`].
    pub leaf_ceiling: u64,
    /// Tolerance for `issued` in the future, in seconds.
    pub skew: u64,
    /// Most grants in a chain.
    pub max_chain: usize,
    /// Deepest name derivation.
    pub max_name_depth: usize,
    /// Most distinct statements examined per query.
    pub max_statements: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            suites: vec![Suite::SlhDsaShake128s, Suite::MlDsa65Ed25519],
            leaf_ceiling: LEAF_CEILING,
            skew: 300,
            max_chain: 16,
            max_name_depth: 8,
            max_statements: 10_000,
        }
    }
}

impl Policy {
    fn accepts(&self, suite: Suite) -> bool {
        self.suites.contains(&suite)
    }
}

/// A concrete subject: something a query can be about.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Holder {
    /// An identity.
    Id(Id),
    /// A leaf key.
    Leaf(LeafKey),
    /// An application key.
    Opaque(OpaqueKey),
}

impl Holder {
    fn principal(&self) -> Option<Principal> {
        match self {
            Holder::Id(id) => Some(Principal::Id(*id)),
            Holder::Leaf(k) => Some(Principal::Leaf(k.clone())),
            Holder::Opaque(_) => None,
        }
    }

    /// As a subject.
    pub fn to_subject(&self) -> Subject {
        match self {
            Holder::Id(id) => Subject::Id(*id),
            Holder::Leaf(k) => Subject::Leaf(k.clone()),
            Holder::Opaque(k) => Subject::Opaque(k.clone()),
        }
    }
}

/// Why one statement (or data signature) is not valid now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Breaks a rule every statement must satisfy.
    Malformed(&'static str),
    /// The issuer's log is unusable.
    Log(LogError),
    /// Claims an event the issuer's log doesn't reach.
    UnknownEvent {
        /// Claimed event.
        event: u64,
        /// The log's head.
        head: u64,
    },
    /// Issued under an earlier event and not in the latest rotation's `keep`.
    NotKept {
        /// The issuing event.
        event: u64,
        /// The log's head.
        head: u64,
    },
    /// Not signed by `k` of the authority (or by the leaf key).
    BadSignature,
    /// Signed under a suite the policy doesn't accept.
    Suite(Suite),
    /// Revoked by its issuer.
    Revoked(Hash),
    /// `issued` is beyond now + skew.
    NotYetValid(Time),
    /// `now ≥ expires`.
    Expired(Time),
    /// Violates the issuer's `max-validity`.
    MaxValidity(u64),
    /// A leaf grant longer than the policy's leaf ceiling.
    LeafCeiling(u64),
    /// Valid and reaches the subject, but conveys only this tag (narrower
    /// than asked).
    Covers(Tag),
    /// Valid and reaches the subject, but grants a tag outside what its issuer holds.
    OutsideIssuer {
        /// What the statement grants.
        granted: Tag,
        /// What its issuer holds on this chain.
        held: Tag,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::time::Duration;
        match self {
            Reason::Malformed(why) => write!(f, "malformed: {why}"),
            Reason::Log(e) => write!(f, "issuer log: {e}"),
            Reason::UnknownEvent { event, head } => {
                write!(
                    f,
                    "issued under event {event}, but the log only reaches {head}"
                )
            }
            Reason::NotKept { event, head } => write!(
                f,
                "issued under event {event} and not kept by rotation {head}"
            ),
            Reason::BadSignature => write!(f, "bad or missing signatures"),
            Reason::Suite(s) => write!(f, "suite {s} not accepted"),
            Reason::Revoked(by) => write!(f, "revoked by {}", by.to_hex().get(..16).unwrap_or("")),
            Reason::NotYetValid(t) => write!(f, "not valid until {}", Rfc3339(*t)),
            Reason::Expired(t) => write!(f, "expired {}", Rfc3339(*t)),
            Reason::MaxValidity(mv) => {
                write!(
                    f,
                    "longer than the issuer's max-validity of {}",
                    Duration(*mv)
                )
            }
            Reason::LeafCeiling(c) => {
                write!(f, "leaf grant longer than the ceiling of {}", Duration(*c))
            }
            Reason::Covers(t) => write!(f, "only conveys {t} here"),
            Reason::OutsideIssuer { granted, held } => write!(
                f,
                "grants {granted}, outside the {held} its issuer holds on this chain"
            ),
        }
    }
}

/// A statement that was considered and rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    /// The statement.
    pub statement: Hash,
    /// Why.
    pub reason: Reason,
}

/// Why a query was denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// No valid chain. `rejected` lists candidate statements that failed
    /// (bounded), to explain near misses.
    NotFound {
        /// Candidates that failed, and why.
        rejected: Vec<Rejection>,
    },
    /// An identity the answer depends on has equivocated.
    Compromised(Box<Evidence>),
    /// A root's log is unusable.
    Root {
        /// The root.
        id: Id,
        /// Why.
        error: LogError,
    },
    /// A resource limit was hit.
    Limit(&'static str),
    /// The data signature itself is invalid.
    Signature(Reason),
    /// The data signature is for another context.
    Context,
    /// The data signature is for other data.
    Data,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::NotFound { .. } => write!(f, "no valid chain from the roots"),
            Denial::Compromised(e) => write!(
                f,
                "identity {} equivocated at event {}: it is compromised",
                e.id(),
                e.n()
            ),
            Denial::Root { id, error } => write!(f, "root {id}: {error}"),
            Denial::Limit(what) => write!(f, "resource limit exceeded: {what}"),
            Denial::Signature(r) => write!(f, "signature invalid: {r}"),
            Denial::Context => write!(f, "signature is for a different context"),
            Denial::Data => write!(f, "signature does not match the data"),
        }
    }
}

/// One grant in a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The grant statement.
    pub grant: Hash,
    /// Name statements that put `holder` in the grant's subject, in order.
    pub names: Vec<Hash>,
    /// Who holds the grant at this step.
    pub holder: Holder,
    /// The effective tag after this step.
    pub tag: Tag,
}

/// A justification: the minimal material for an answer (DESIGN.md §9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The root the chain starts from.
    pub root: Id,
    /// Grants from the root to the subject (empty if the subject is the root).
    pub steps: Vec<Step>,
    /// Name statements, for `resolve` proofs.
    pub names: Vec<Hash>,
    /// Effective tag: the intersection of all grant tags.
    pub tag: Tag,
    /// Effective expiry: the earliest expiry of any statement used.
    pub expires: Option<Time>,
    /// Identities whose logs the proof needs.
    pub ids: BTreeSet<Id>,
    /// Data signature, for `verify` proofs.
    pub signature: Option<Hash>,
}

impl Proof {
    /// Every statement the proof uses, in chain order.
    pub fn statements(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        for step in &self.steps {
            out.extend(step.names.iter().copied());
            out.push(step.grant);
        }
        out.extend(self.names.iter().copied());
        let mut seen = BTreeSet::new();
        out.retain(|h| seen.insert(*h));
        out
    }

    /// The proof as a bundle: logs, then statements, then the signature.
    pub fn items(&self, material: &Material) -> Vec<Item> {
        let mut items = Vec::new();
        for id in &self.ids {
            if let Ok(log) = &*material.log(id) {
                items.extend(log.items());
            }
        }
        for h in self.statements() {
            if let Some(st) = material.statement(&h) {
                items.push(Item::Statement(shippable(st, &st.body.issuer, material)));
            }
        }
        if let Some(st) = self.signature.and_then(|h| material.signature(&h)) {
            items.push(Item::Signature(shippable(st, &st.body.signer, material)));
        }
        items
    }

    fn merge_expiry(&mut self, e: Option<Time>) {
        self.expires = match (self.expires, e) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
}

/// A copy fit to ship: only signatures that verify, one per index, so the
/// item encodes canonically and junk merged alongside never travels. Falls
/// back to the first signature per index if none verify (a kept statement
/// whose issuing event this material can't reach).
fn shippable<T: Body + Clone>(s: &Signed<T>, issuer: &Issuer, material: &Material) -> Signed<T> {
    let verified = match issuer {
        Issuer::Identity { id, event } => match &*material.log(id) {
            Ok(log) => log
                .event(*event)
                .map(|ev| s.valid_sigs(ev.authority()))
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        },
        Issuer::Leaf(k) => s.valid_leaf_sigs(k),
    };
    let sigs = if verified.is_empty() {
        let mut first: Vec<Sig> = Vec::new();
        for sig in &s.sigs {
            if first.last().is_none_or(|l| l.index < sig.index) {
                first.push(sig.clone());
            }
        }
        first
    } else {
        verified
    };
    Signed {
        body: s.body.clone(),
        sigs,
    }
}

/// Answers questions about the material from the point of view of `roots`.
pub struct Verifier<'a> {
    roots: &'a [Id],
    material: &'a Material,
    policy: &'a Policy,
}

const MAX_REJECTIONS: usize = 32;
/// Name-resolution work allowed per statement of budget.
const NAME_STEPS_PER_STATEMENT: usize = 100;

impl<'a> Verifier<'a> {
    /// A verifier for `roots`.
    pub fn new(roots: &'a [Id], material: &'a Material, policy: &'a Policy) -> Self {
        Verifier {
            roots,
            material,
            policy,
        }
    }

    /// Does `subject` hold `tag` at `now`?
    pub fn check(&self, subject: &Holder, tag: &Tag, now: Time) -> Result<Proof, Denial> {
        let mut q = Query::new(self, now);
        q.check(subject, tag)
    }

    /// Who does `path` refer to at `now`? Each subject comes with its proof.
    pub fn resolve(&self, path: &NamePath, now: Time) -> Result<Vec<(Holder, Proof)>, Denial> {
        let mut q = Query::new(self, now);
        if let Err(LogError::Equivocation(e)) = &*self.material.log(&path.base) {
            return Err(Denial::Compromised(e.clone()));
        }
        let members = q.resolve_path(&path.base, &path.names, q.v.policy.max_name_depth)?;
        if members.is_empty() {
            if let Some(e) = q.evidence.take() {
                return Err(Denial::Compromised(e));
            }
            return Err(Denial::NotFound {
                rejected: q.rejected,
            });
        }
        Ok(members
            .into_iter()
            .map(|(holder, names)| {
                let mut proof = Proof {
                    root: path.base,
                    steps: Vec::new(),
                    names: names.clone(),
                    tag: Tag::everything(),
                    expires: None,
                    ids: BTreeSet::from([path.base]),
                    signature: None,
                };
                for h in &names {
                    q.note_statement(&mut proof, h);
                }
                (holder, proof)
            })
            .collect())
    }

    /// Is `sig` a valid signature over `data` in `context` by someone who
    /// holds `tag` at `now`?
    pub fn verify(
        &self,
        sig: &Signed<DataSig>,
        data: &Hash,
        context: &[u8],
        tag: &Tag,
        now: Time,
    ) -> Result<Proof, Denial> {
        if sig.body.context != context {
            return Err(Denial::Context);
        }
        if sig.body.data != *data {
            return Err(Denial::Data);
        }
        let mut q = Query::new(self, now);
        let hash = sig.body.hash();
        let holder = match &sig.body.signer {
            Issuer::Identity { id, event } => {
                q.signed_by_identity(sig, &hash, *id, *event, None)
                    .and_then(|()| q.check_revoked(*id, &hash))
                    .map_err(Denial::Signature)?;
                Holder::Id(*id)
            }
            Issuer::Leaf(k) => {
                if !self.policy.accepts(Suite::MlDsa65Ed25519) {
                    return Err(Denial::Signature(Reason::Suite(Suite::MlDsa65Ed25519)));
                }
                let key = leaf_cache_key(k);
                if !self
                    .material
                    .sig_cached(hash, key, &sig.sigs, || sig.verify_leaf(k))
                {
                    return Err(Denial::Signature(Reason::BadSignature));
                }
                Holder::Leaf(k.clone())
            }
        };
        if sig.body.issued > now.saturating_add(self.policy.skew) {
            return Err(Denial::Signature(Reason::NotYetValid(sig.body.issued)));
        }
        let mut proof = q.check(&holder, tag)?;
        if let Issuer::Identity { id, .. } = &sig.body.signer {
            proof.ids.insert(*id);
        }
        proof.signature = Some(hash);
        Ok(proof)
    }

    /// The newest `issued` on a statement by one of the roots whose
    /// signatures (or keep endorsement) verify — a witness for the clock
    /// [`Floor`](crate::Floor). Expiry and revocation don't matter here.
    pub fn time_witness(&self) -> Option<Time> {
        let mut q = Query::new(self, Time::MAX);
        let mut best = None;
        for root in self.roots {
            for h in self.material.issued_by(root) {
                let Some(st) = self.material.statement(h) else {
                    continue;
                };
                if best.is_some_and(|b| st.body.issued <= b) {
                    continue;
                }
                if let Issuer::Identity { id, event } = &st.body.issuer
                    && q.signed_by_identity(st, h, *id, *event, None).is_ok()
                {
                    best = Some(st.body.issued);
                }
            }
        }
        best
    }

    /// Whether a statement is valid at `now`, and if not, why.
    pub fn statement_status(&self, hash: &Hash, now: Time) -> Result<(), Reason> {
        Query::new(self, now).status(hash)
    }
}

fn leaf_cache_key(k: &LeafKey) -> Hash {
    Hash::of_data(&k.to_sexp().encode())
}

/// Per-query state: the clock, counters, and memo tables.
struct Query<'v, 'a> {
    v: &'v Verifier<'a>,
    now: Time,
    status: HashMap<Hash, Result<(), Reason>>,
    names: HashMap<(Id, Vec<u8>, usize), Rc<Members>>,
    steps: usize,
    rejected: Vec<Rejection>,
    evidence: Option<Box<Evidence>>,
}

/// Holders a name refers to, each with its derivation (name statements).
type Members = BTreeMap<Holder, Vec<Hash>>;

impl<'v, 'a> Query<'v, 'a> {
    fn new(v: &'v Verifier<'a>, now: Time) -> Self {
        Query {
            v,
            now,
            status: HashMap::new(),
            names: HashMap::new(),
            steps: 0,
            rejected: Vec::new(),
            evidence: None,
        }
    }

    fn log(&mut self, id: &Id) -> Result<Rc<Result<Log, LogError>>, Reason> {
        let log = self.v.material.log(id);
        match &*log {
            Ok(_) => Ok(log),
            Err(e) => {
                if let LogError::Equivocation(ev) = e
                    && self.evidence.is_none()
                {
                    self.evidence = Some(ev.clone());
                }
                Err(Reason::Log(e.clone()))
            }
        }
    }

    /// The event/keep/signature rule for a body issued by an identity
    /// (DESIGN.md §9.3 items 1–2), and the revocation check (item 3) unless
    /// `skip_revocation` is set for revocations themselves.
    fn signed_by_identity<T: Body>(
        &mut self,
        signed: &Signed<T>,
        hash: &Hash,
        id: Id,
        event: u64,
        max_validity_of: Option<&Statement>,
    ) -> Result<(), Reason> {
        let log = self.log(&id)?;
        let Ok(log) = &*log else {
            return Err(Reason::BadSignature);
        };
        let head = log.head_n();
        let Some(ev) = log.event(event) else {
            return Err(Reason::UnknownEvent { event, head });
        };
        if event == head {
            if !self.v.policy.accepts(Suite::SlhDsaShake128s) {
                return Err(Reason::Suite(Suite::SlhDsaShake128s));
            }
            let authority = ev.authority();
            let ok = self
                .v
                .material
                .sig_cached(*hash, authority.hash(), &signed.sigs, || {
                    signed.verify_threshold(authority)
                });
            if !ok {
                return Err(Reason::BadSignature);
            }
        } else if !log.keeps(hash) {
            return Err(Reason::NotKept { event, head });
        }
        if let Some(st) = max_validity_of
            && let Some(mv) = ev.max_validity()
            && !matches!(st.claim, Claim::Revoke { .. })
        {
            match st.expires {
                Some(e) if e - st.issued <= mv => {}
                _ => return Err(Reason::MaxValidity(mv)),
            }
        }
        Ok(())
    }

    /// Full validity of a statement at `now` (DESIGN.md §9.3 items 1–4, §7).
    fn status(&mut self, hash: &Hash) -> Result<(), Reason> {
        if let Some(s) = self.status.get(hash) {
            return s.clone();
        }
        let result = self.compute_status(hash);
        self.status.insert(*hash, result.clone());
        result
    }

    fn compute_status(&mut self, hash: &Hash) -> Result<(), Reason> {
        let Some(st) = self.v.material.statement(hash) else {
            return Err(Reason::Malformed("unknown statement"));
        };
        let body = &st.body;
        body.check_wellformed().map_err(Reason::Malformed)?;
        match &body.issuer {
            Issuer::Identity { id, event } => {
                self.signed_by_identity(st, hash, *id, *event, Some(body))?;
                if !matches!(body.claim, Claim::Revoke { .. }) {
                    self.check_revoked(*id, hash)?;
                }
            }
            Issuer::Leaf(k) => {
                if !self.v.policy.accepts(Suite::MlDsa65Ed25519) {
                    return Err(Reason::Suite(Suite::MlDsa65Ed25519));
                }
                let ok = self
                    .v
                    .material
                    .sig_cached(*hash, leaf_cache_key(k), &st.sigs, || st.verify_leaf(k));
                if !ok {
                    return Err(Reason::BadSignature);
                }
            }
        }
        if body.issued > self.now.saturating_add(self.v.policy.skew) {
            return Err(Reason::NotYetValid(body.issued));
        }
        if let Some(e) = body.expires
            && self.now >= e
        {
            return Err(Reason::Expired(e));
        }
        if let Claim::Grant {
            subject: Subject::Leaf(_),
            ..
        } = &body.claim
        {
            let ceiling = self.v.policy.leaf_ceiling.min(LEAF_CEILING);
            match body.expires {
                Some(e) if e - body.issued <= ceiling => {}
                _ => return Err(Reason::LeafCeiling(ceiling)),
            }
        }
        Ok(())
    }

    /// A valid revocation by `id` of `hash` (or of a data signature).
    fn check_revoked(&mut self, id: Id, hash: &Hash) -> Result<(), Reason> {
        for r in self.v.material.revocations(&id, hash).to_vec() {
            if self.status(&r).is_ok() {
                return Err(Reason::Revoked(r));
            }
        }
        Ok(())
    }

    fn reject(&mut self, statement: Hash, reason: Reason) {
        if self.rejected.len() < MAX_REJECTIONS
            && !self.rejected.iter().any(|r| r.statement == statement)
        {
            self.rejected.push(Rejection { statement, reason });
        }
    }

    fn budget(&self) -> Result<(), Denial> {
        if self.status.len() > self.v.policy.max_statements {
            Err(Denial::Limit("statements examined"))
        } else {
            Ok(())
        }
    }

    /// Records a statement's expiry and issuer in a proof.
    fn note_statement(&self, proof: &mut Proof, h: &Hash) {
        if let Some(st) = self.v.material.statement(h) {
            proof.merge_expiry(st.body.expires);
            if let Some(id) = st.body.issuer.id() {
                proof.ids.insert(id);
            }
        }
    }

    // -- names --------------------------------------------------------------

    /// Members of `(base names…)` using derivations of depth ≤ `depth`.
    fn resolve_path(
        &mut self,
        base: &Id,
        names: &[Vec<u8>],
        depth: usize,
    ) -> Result<Members, Denial> {
        // Level by level over a de-duplicated set of holders, so a path's
        // cost is (levels × holders), never (holders ^ levels).
        let mut current = Members::from([(Holder::Id(*base), Vec::new())]);
        for name in names {
            let mut next = Members::new();
            for (holder, derivation) in &current {
                let Holder::Id(id) = holder else {
                    continue;
                };
                for (m, d) in self.pair(id, name, depth)?.iter() {
                    self.steps += 1;
                    if self.steps > NAME_STEPS_PER_STATEMENT * self.v.policy.max_statements {
                        return Err(Denial::Limit("name resolution steps"));
                    }
                    next.entry(m.clone()).or_insert_with(|| {
                        let mut all = derivation.clone();
                        all.extend(d.iter().copied());
                        all
                    });
                }
            }
            current = next;
        }
        Ok(current)
    }

    /// Members of the single name `(issuer name)` with derivations of depth
    /// ≤ `depth`: the value of round `depth` of the Jacobi iteration
    /// `M_d(X, n) = ∪ { denote_{d−1}(s) : X says n → s }`.
    fn pair(&mut self, issuer: &Id, name: &[u8], depth: usize) -> Result<Rc<Members>, Denial> {
        if depth == 0 {
            return Ok(Rc::new(Members::new()));
        }
        let key = (*issuer, name.to_vec(), depth);
        if let Some(m) = self.names.get(&key) {
            return Ok(m.clone());
        }
        let mut out = Members::new();
        let mut candidates = self.v.material.names(issuer, name).to_vec();
        candidates.sort();
        for h in candidates {
            self.budget()?;
            if let Err(reason) = self.status(&h) {
                self.reject(h, reason);
                continue;
            }
            let Some(Claim::Name { subject, .. }) =
                self.v.material.statement(&h).map(|s| s.body.claim.clone())
            else {
                continue;
            };
            for (holder, d) in self.denote(&subject, depth - 1)? {
                out.entry(holder).or_insert_with(|| {
                    let mut all = vec![h];
                    all.extend(d);
                    all
                });
            }
        }
        let out = Rc::new(out);
        self.names.insert(key, out.clone());
        Ok(out)
    }

    /// The holders a subject denotes.
    fn denote(&mut self, subject: &Subject, depth: usize) -> Result<Members, Denial> {
        Ok(match subject {
            Subject::Id(id) => BTreeMap::from([(Holder::Id(*id), Vec::new())]),
            Subject::Leaf(k) => BTreeMap::from([(Holder::Leaf(k.clone()), Vec::new())]),
            Subject::Opaque(k) => BTreeMap::from([(Holder::Opaque(k.clone()), Vec::new())]),
            Subject::Name(p) => self.resolve_path(&p.base, &p.names, depth)?,
        })
    }

    // -- grants -------------------------------------------------------------

    /// After a failed search, explains near misses: valid grants, from
    /// principals the search reached, that reach `want` but convey less than
    /// `tag`. Runs only on denial, so the success path stays structural-first.
    fn near_misses(&mut self, reached: &[(Principal, Tag)], want: &Holder, tag: &Tag) {
        let max_depth = self.v.policy.max_name_depth;
        for (principal, held) in reached {
            let mut grants = self.v.material.grants_by(principal).to_vec();
            grants.sort();
            for h in grants {
                if self.budget().is_err() || self.rejected.len() >= MAX_REJECTIONS {
                    return;
                }
                let Some(Claim::Grant {
                    subject, tag: gtag, ..
                }) = self.v.material.statement(&h).map(|s| s.body.claim.clone())
                else {
                    continue;
                };
                let eff = held.intersect(&gtag);
                if eff.as_ref().is_some_and(|e| tag.is_within(e)) {
                    continue;
                }
                let reaches = self
                    .denote(&subject, max_depth)
                    .is_ok_and(|m| m.contains_key(want));
                if reaches && self.status(&h).is_ok() {
                    let reason = match eff {
                        Some(e) => Reason::Covers(e),
                        None => Reason::OutsideIssuer {
                            granted: gtag,
                            held: held.clone(),
                        },
                    };
                    self.reject(h, reason);
                }
            }
        }
    }

    fn check(&mut self, subject: &Holder, tag: &Tag) -> Result<Proof, Denial> {
        if let Holder::Id(id) = subject
            && let Err(LogError::Equivocation(e)) = &*self.v.material.log(id)
        {
            return Err(Denial::Compromised(e.clone()));
        }
        let max_depth = self.v.policy.max_name_depth;
        // BFS over (holder, effective tag). Each node remembers how it was reached.
        struct Node {
            principal: Principal,
            tag: Tag,
            root: Id,
            parent: Option<usize>,
            step: Option<Step>,
            depth: usize,
        }
        let mut nodes: Vec<Node> = Vec::new();
        let mut visited: BTreeSet<(Principal, Tag)> = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut root_error = None;
        for root in self.v.roots {
            if let Err(e) = &*self.v.material.log(root) {
                if let LogError::Equivocation(ev) = e {
                    self.evidence.get_or_insert_with(|| ev.clone());
                }
                root_error.get_or_insert((*root, e.clone()));
                continue;
            }
            if *subject == Holder::Id(*root) {
                return Ok(Proof {
                    root: *root,
                    steps: Vec::new(),
                    names: Vec::new(),
                    tag: Tag::everything(),
                    expires: None,
                    ids: BTreeSet::from([*root]),
                    signature: None,
                });
            }
            if visited.insert((Principal::Id(*root), Tag::everything())) {
                nodes.push(Node {
                    principal: Principal::Id(*root),
                    tag: Tag::everything(),
                    root: *root,
                    parent: None,
                    step: None,
                    depth: 0,
                });
                queue.push_back(nodes.len() - 1);
            }
        }
        let want = subject.clone();
        let mut found: Option<(usize, Step)> = None;
        'search: while let Some(ni) = queue.pop_front() {
            let Some(node) = nodes.get(ni) else { break };
            if node.depth >= self.v.policy.max_chain {
                continue;
            }
            let (principal, node_tag, node_depth, node_root) = (
                node.principal.clone(),
                node.tag.clone(),
                node.depth,
                node.root,
            );
            let mut grants = self.v.material.grants_by(&principal).to_vec();
            grants.sort();
            for h in grants {
                self.budget()?;
                let Some(Claim::Grant {
                    subject: gsubject,
                    tag: gtag,
                    delegate,
                }) = self.v.material.statement(&h).map(|s| s.body.claim.clone())
                else {
                    continue;
                };
                // Structural checks first: is this grant useful at all?
                let Some(eff) = node_tag.intersect(&gtag) else {
                    continue;
                };
                let can_finish = tag.is_within(&eff);
                if !can_finish && !delegate {
                    continue;
                }
                let members = self.denote(&gsubject, max_depth)?;
                let finishes = can_finish && members.contains_key(&want);
                let continues = delegate && members.keys().any(|m| m.principal().is_some());
                if !finishes && !continues {
                    continue;
                }
                if let Err(reason) = self.status(&h) {
                    self.reject(h, reason);
                    continue;
                }
                if finishes && let Some(names) = members.get(&want) {
                    found = Some((
                        ni,
                        Step {
                            grant: h,
                            names: names.clone(),
                            holder: want.clone(),
                            tag: eff.clone(),
                        },
                    ));
                    break 'search;
                }
                for (m, names) in members {
                    let Some(p) = m.principal() else { continue };
                    if !visited.insert((p.clone(), eff.clone())) {
                        continue;
                    }
                    nodes.push(Node {
                        principal: p,
                        tag: eff.clone(),
                        root: node_root,
                        parent: Some(ni),
                        step: Some(Step {
                            grant: h,
                            names,
                            holder: m,
                            tag: eff.clone(),
                        }),
                        depth: node_depth + 1,
                    });
                    queue.push_back(nodes.len() - 1);
                }
            }
        }
        let Some((last, final_step)) = found else {
            if let Some(e) = self.evidence.take() {
                return Err(Denial::Compromised(e));
            }
            if let Some((id, error)) = root_error
                && nodes.is_empty()
            {
                return Err(Denial::Root { id, error });
            }
            let reached: Vec<(Principal, Tag)> = nodes
                .iter()
                .map(|n| (n.principal.clone(), n.tag.clone()))
                .collect();
            self.near_misses(&reached, &want, tag);
            return Err(Denial::NotFound {
                rejected: std::mem::take(&mut self.rejected),
            });
        };
        let Some(root) = nodes.get(last).map(|n| n.root) else {
            return Err(Denial::NotFound {
                rejected: std::mem::take(&mut self.rejected),
            });
        };
        let mut steps = vec![final_step];
        let mut cursor = Some(last);
        while let Some(i) = cursor {
            let Some(node) = nodes.get(i) else { break };
            if let Some(step) = &node.step {
                steps.push(step.clone());
            }
            cursor = node.parent;
        }
        steps.reverse();
        let mut proof = Proof {
            root,
            tag: steps.last().map(|s| s.tag.clone()).unwrap_or_default(),
            steps,
            names: Vec::new(),
            expires: None,
            ids: BTreeSet::from([root]),
            signature: None,
        };
        for h in proof.statements() {
            self.note_statement(&mut proof, &h);
        }
        Ok(proof)
    }
}
