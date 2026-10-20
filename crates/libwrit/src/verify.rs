//! Verification (DESIGN.md §9): `check`, `resolve`, `verify`, with proofs
//! and reasons.
//!
//! Search is structural first: a statement's signatures are checked only
//! once it lies on a candidate path, and results are cached by hash in the
//! [`Material`].

use crate::hash::{Hash, Id, LeafId};
use crate::keys::{LeafKey, Suite};
use crate::log::{Evidence, Log, LogError};
use crate::material::{Material, Principal};
use crate::model::{
    Body, Claim, DataSig, Issuer, Item, LEAF_CEILING, NamePath, OpaqueKey, Sig, Signed, Statement,
    Subject,
};
use crate::tag::{Tag, Tags};
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
    /// Most signatures verified per query (cached results are free).
    pub max_signatures: usize,
    /// Refuse statements and data signatures, short-lived ones included, by
    /// identities that publish no records, unless they are local
    /// (DESIGN.md §18.6). Off by default.
    pub require_records: bool,
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
            max_signatures: 2_000,
            require_records: false,
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
            Holder::Leaf(k) => Some(Principal::Leaf(k.id())),
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
    /// Issued by a leaf key the material doesn't contain. The key travels
    /// in the grant to the leaf.
    UnknownLeaf(LeafId),
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
    /// Valid and reaches the subject, but conveys only these tags (narrower
    /// than asked, or beside it).
    Covers(Vec<Tag>),
    /// Valid and reaches the subject, but grants a tag outside what its issuer holds.
    OutsideIssuer {
        /// What the statement grants.
        granted: Tags,
        /// What its issuer holds on this chain.
        held: Tag,
    },
    /// Not decided: the query's resource limits ran out first. Treated as
    /// invalid.
    Limit,
    /// Its issuer publishes records, and none in the material is younger
    /// than `max_age` seconds (DESIGN.md §18.6).
    NoFreshRecord {
        /// The issuer's `max-age`.
        max_age: u64,
    },
    /// Its issuer publishes no records, and the policy requires them.
    NoRecords,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::time::Duration;
        match self {
            Reason::Malformed(why) => write!(f, "invalid: {why}"),
            Reason::Log(e) => write!(f, "issuer: {e}"),
            Reason::UnknownEvent { event, head } => {
                write!(
                    f,
                    "names event {event} of its issuer, but the issuer's log ends at event {head}"
                )
            }
            Reason::NotKept { head, .. } => {
                write!(f, "issued before rotation {head}, which did not keep it")
            }
            Reason::UnknownLeaf(k) => write!(
                f,
                "issued by leaf:{}, whose key is missing (it comes with the grant to the leaf)",
                k.fingerprint()
            ),
            Reason::BadSignature => write!(f, "its signatures are missing or invalid"),
            Reason::Suite(s) => write!(f, "signed with {s}, which this verifier does not accept"),
            Reason::Revoked(by) => write!(f, "revoked by {}", by.to_hex().get(..16).unwrap_or("")),
            Reason::NotYetValid(t) => write!(f, "not valid until {}", Rfc3339(*t)),
            Reason::Expired(t) => write!(f, "expired {}", Rfc3339(*t)),
            Reason::MaxValidity(mv) => {
                write!(f, "lasts longer than its issuer allows ({})", Duration(*mv))
            }
            Reason::LeafCeiling(c) => {
                write!(
                    f,
                    "a name or grant for a leaf key may last at most {}",
                    Duration(*c)
                )
            }
            Reason::Covers(ts) => {
                f.write_str("grants only")?;
                for t in ts {
                    write!(f, " {t}")?;
                }
                f.write_str(" on this chain")
            }
            Reason::OutsideIssuer { granted, held } => write!(
                f,
                "grants {granted}, but its issuer holds only {held} on this chain"
            ),
            Reason::Limit => write!(f, "not checked: the query hit its resource limits"),
            Reason::NoFreshRecord { max_age } => write!(
                f,
                "its issuer requires a record no older than {}, and there is none",
                Duration(*max_age)
            ),
            Reason::NoRecords => write!(
                f,
                "its issuer publishes no records, and this verifier requires them"
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
            Denial::NotFound { .. } => write!(f, "no chain of valid grants leads to it"),
            Denial::Compromised(e) => write!(
                f,
                "identity {} signed two different versions of event {}, so it can't be trusted",
                e.id(),
                e.n()
            ),
            Denial::Root { id, error } => write!(f, "{id}: {error}"),
            Denial::Limit(what) => write!(f, "gave up: too many {what}"),
            Denial::Signature(r) => write!(f, "the signature is not valid: {r}"),
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
    /// Revocation records the answer relied on for freshness (DESIGN.md
    /// §18.6): shipped with the proof, so its holder can staple them.
    pub records: BTreeSet<Hash>,
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
        items.extend(
            self.statements()
                .iter()
                .filter_map(|h| material.shippable(h)),
        );
        if let Some(st) = self.signature.and_then(|h| material.signature(&h)) {
            items.push(Item::Signature(shippable(st, &st.body.signer, material)));
        }
        items.extend(
            self.records
                .iter()
                .filter_map(|h| material.shippable_record(h)),
        );
        items
    }

    fn merge_expiry(&mut self, e: Option<Time>) {
        self.expires = match (self.expires, e) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
}

impl Material {
    /// The statement `hash` as it should travel: only signatures that
    /// verify, one per index, so junk merged alongside is left behind.
    pub fn shippable(&self, hash: &Hash) -> Option<Item> {
        let st = self.statement(hash)?;
        Some(Item::Statement(shippable(st, &st.body.issuer, self)))
    }

    /// The record `hash` as it should travel: only signatures that verify,
    /// one per index, so junk merged alongside never makes it undecodable.
    pub fn shippable_record(&self, hash: &Hash) -> Option<Item> {
        let r = self.record(hash)?;
        let issuer = Issuer::Identity {
            id: r.body.id,
            event: r.body.event,
        };
        Some(Item::Record(shippable(r, &issuer, self)))
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
        Issuer::Leaf(k) => material
            .leaf_key(k)
            .map(|key| s.valid_leaf_sigs(key))
            .unwrap_or_default(),
    };
    let sigs = if verified.is_empty() {
        let mut all = s.sigs.clone();
        all.sort_by_key(|s| s.index);
        let mut first: Vec<Sig> = Vec::new();
        for sig in &all {
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
    local: &'a [Id],
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
            local: &[],
            material,
            policy,
        }
    }

    /// Identities whose whole issuance log the caller supplied (usually its
    /// own roots, given as directories): their revocations are all in the
    /// material, so they need no records (DESIGN.md §18.6).
    pub fn with_local(mut self, local: &'a [Id]) -> Self {
        self.local = local;
        self
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
            .map(|(holder, derivation)| {
                let names = derivation.hashes();
                let mut proof = Proof {
                    root: path.base,
                    steps: Vec::new(),
                    names: names.clone(),
                    tag: Tag::everything(),
                    expires: None,
                    ids: BTreeSet::from([path.base]),
                    signature: None,
                    records: BTreeSet::new(),
                };
                for h in &names {
                    q.note_statement(&mut proof, h);
                }
                q.attach_records(&mut proof);
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
        q.data_sig_status(sig, &hash).map_err(|r| match r {
            Reason::Log(LogError::Equivocation(e)) => Denial::Compromised(e),
            r => Denial::Signature(r),
        })?;
        let holder = match &sig.body.signer {
            Issuer::Identity { id, .. } => Holder::Id(*id),
            Issuer::Leaf(k) => Holder::Leaf(
                self.material
                    .leaf_key(k)
                    .cloned()
                    .ok_or(Denial::Signature(Reason::UnknownLeaf(*k)))?,
            ),
        };
        let mut proof = q.check(&holder, tag)?;
        if let Issuer::Identity { id, .. } = &sig.body.signer {
            proof.ids.insert(*id);
        }
        proof.signature = Some(hash);
        q.attach_records(&mut proof);
        Ok(proof)
    }

    /// The newest `issued` on a statement by one of the roots whose
    /// signatures (or keep endorsement) verify — a witness for the clock
    /// [`Floor`](crate::Floor). Expiry and revocation don't matter here.
    ///
    /// Unlike a query, this is not bounded by [`Policy::max_signatures`]:
    /// running out would leave the floor where it was, which is the
    /// permissive direction, and junk claiming to be from a root could
    /// arrange that. Like building a log, the work is one signature check
    /// per candidate, linear in the material (SPEC §11). Candidates are
    /// tried newest first, so the usual cost is one check.
    pub fn time_witness(&self) -> Option<Time> {
        let mut q = Query::new(self, Time::MAX);
        let mut candidates: Vec<(&Hash, &Signed<Statement>)> = self
            .roots
            .iter()
            .flat_map(|root| self.material.issued_by(root))
            .filter_map(|h| Some((h, self.material.statement(h)?)))
            .collect();
        candidates.sort_by_key(|(_, st)| std::cmp::Reverse(st.body.issued));
        for (h, st) in candidates {
            q.signatures = 0;
            if let Issuer::Identity { id, event } = &st.body.issuer
                && q.signed_by_identity(st, h, *id, *event, None).is_ok()
            {
                return Some(st.body.issued);
            }
        }
        None
    }

    /// Whether a statement is valid at `now`, and if not, why.
    pub fn statement_status(&self, hash: &Hash, now: Time) -> Result<(), Reason> {
        Query::new(self, now).status(hash)
    }

    /// Whether `id` publishes records and the material holds a valid one
    /// young enough at `now` for its long-lived statements (SPEC §7).
    pub fn has_fresh_record(&self, id: &Id, now: Time) -> bool {
        let max_age = match &*self.material.log(id) {
            Ok(log) => log.head().publish().map(|p| p.max_age()),
            Err(_) => None,
        };
        let Some(max_age) = max_age else {
            return false;
        };
        let mut q = Query::new(self, now);
        matches!(q.newest_record(*id), Ok(Some((_, t))) if t >= now.saturating_sub(max_age))
    }

    /// Whether a revocation record in the material is valid (SPEC §5.6):
    /// made under its issuer's head, and signed by its current keys. `now`
    /// does not enter: a valid record revokes what it lists whatever the
    /// clock says; see [`Verifier::has_fresh_record`] for freshness.
    pub fn record_status(&self, hash: &Hash, now: Time) -> Result<(), Reason> {
        Query::new(self, now).record_status(hash)
    }

    /// Whether a data signature in the material is valid at `now` (SPEC §7),
    /// and if not, why. Says nothing about what its signer holds.
    pub fn signature_status(&self, hash: &Hash, now: Time) -> Result<(), Reason> {
        let Some(sig) = self.material.signature(hash) else {
            return Err(Reason::Malformed("unknown signature"));
        };
        Query::new(self, now).data_sig_status(sig, hash)
    }
}

/// Per-query state: the clock, counters, and memo tables.
struct Query<'v, 'a> {
    v: &'v Verifier<'a>,
    now: Time,
    status: HashMap<Hash, Result<(), Reason>>,
    names: HashMap<(Id, Vec<u8>, usize), Rc<Members>>,
    steps: usize,
    signatures: usize,
    rejected: Vec<Rejection>,
    evidence: Option<Box<Evidence>>,
    /// Per identity, its newest valid record, if any: (hash, issued).
    newest: HashMap<Id, Option<(Hash, Time)>>,
    /// Records that made something fresh, by issuer.
    fresh_by: BTreeMap<Id, Hash>,
}

/// Holders a name refers to, each with its derivation.
type Members = BTreeMap<Holder, Derivation>;

/// The name statements that put a holder in a name. Derivations share
/// their parts instead of copying them, so extending one costs O(1) however
/// long its expansion: a path through repeated names would otherwise grow
/// exponentially with depth. Flattened, each statement once, only for proofs.
#[derive(Clone, Default)]
struct Derivation(Option<Rc<Link>>);

enum Link {
    /// A name statement, then the derivation of its subject's members.
    Statement(Hash, Derivation),
    /// One derivation after another (successive labels of a name path).
    Join(Derivation, Derivation),
}

impl Derivation {
    fn statement(h: Hash, rest: Derivation) -> Derivation {
        Derivation(Some(Rc::new(Link::Statement(h, rest))))
    }

    fn join(&self, other: &Derivation) -> Derivation {
        match (&self.0, &other.0) {
            (None, _) => other.clone(),
            (_, None) => self.clone(),
            _ => Derivation(Some(Rc::new(Link::Join(self.clone(), other.clone())))),
        }
    }

    /// The statements in order, each once. Shared parts are walked once, so
    /// this costs no more than building the derivation did.
    fn hashes(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut walked = BTreeSet::new();
        let mut stack = vec![self.clone()];
        while let Some(d) = stack.pop() {
            let Some(link) = d.0 else { continue };
            if !walked.insert(Rc::as_ptr(&link).addr()) {
                continue;
            }
            match &*link {
                Link::Statement(h, rest) => {
                    if seen.insert(*h) {
                        out.push(*h);
                    }
                    stack.push(rest.clone());
                }
                Link::Join(a, b) => {
                    stack.push(b.clone());
                    stack.push(a.clone());
                }
            }
        }
        out
    }
}

impl<'v, 'a> Query<'v, 'a> {
    fn new(v: &'v Verifier<'a>, now: Time) -> Self {
        Query {
            v,
            now,
            status: HashMap::new(),
            names: HashMap::new(),
            steps: 0,
            signatures: 0,
            rejected: Vec::new(),
            evidence: None,
            newest: HashMap::new(),
            fresh_by: BTreeMap::new(),
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
            let ok = self.sig_check(*hash, authority.hash(), &signed.sigs, || {
                signed.verify_threshold(authority)
            })?;
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

    /// A signature check, cached in the material by body, signer and
    /// signatures. A check not in the cache is charged one unit of
    /// [`Policy::max_signatures`] per signature it may verify before it
    /// runs; past the limit it doesn't run (and isn't cached).
    fn sig_check(
        &mut self,
        body: Hash,
        signer: Hash,
        sigs: &[Sig],
        check: impl FnOnce() -> bool,
    ) -> Result<bool, Reason> {
        let key = Material::sig_key(body, signer, sigs);
        if let Some(ok) = self.v.material.cached_sig(&key) {
            return Ok(ok);
        }
        self.signatures = self.signatures.saturating_add(sigs.len());
        if self.signatures > self.v.policy.max_signatures {
            return Err(Reason::Limit);
        }
        let ok = check();
        self.v.material.cache_sig(key, ok);
        Ok(ok)
    }

    /// Whether the leaf key `id`, found in the material, signed `signed`.
    fn signed_by_leaf<T: Body>(
        &mut self,
        signed: &Signed<T>,
        hash: &Hash,
        id: &LeafId,
    ) -> Result<(), Reason> {
        if !self.v.policy.accepts(Suite::MlDsa65Ed25519) {
            return Err(Reason::Suite(Suite::MlDsa65Ed25519));
        }
        let Some(key) = self.v.material.leaf_key(id) else {
            return Err(Reason::UnknownLeaf(*id));
        };
        let ok = self.sig_check(*hash, Hash(id.0), &signed.sigs, || signed.verify_leaf(key))?;
        if ok {
            Ok(())
        } else {
            Err(Reason::BadSignature)
        }
    }

    /// A data signature's validity (SPEC §7): signed (or kept), not revoked,
    /// not issued in the future.
    fn data_sig_status(&mut self, sig: &Signed<DataSig>, hash: &Hash) -> Result<(), Reason> {
        match &sig.body.signer {
            Issuer::Identity { id, event } => {
                self.signed_by_identity(sig, hash, *id, *event, None)?;
                self.check_revoked(*id, hash)?;
                self.fresh(*id, sig.body.issued, None)?;
            }
            Issuer::Leaf(k) => self.signed_by_leaf(sig, hash, k)?,
        }
        if sig.body.issued > self.now.saturating_add(self.v.policy.skew) {
            return Err(Reason::NotYetValid(sig.body.issued));
        }
        Ok(())
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
                    self.fresh(*id, body.issued, body.expires)?;
                }
            }
            Issuer::Leaf(k) => self.signed_by_leaf(st, hash, k)?,
        }
        // A revocation from the future still revokes (SPEC §7 rule 4): it
        // can only deny, and a clock set back must not bring back what its
        // issuer revoked.
        if !matches!(body.claim, Claim::Revoke { .. })
            && body.issued > self.now.saturating_add(self.v.policy.skew)
        {
            return Err(Reason::NotYetValid(body.issued));
        }
        if let Some(e) = body.expires
            && self.now >= e
        {
            return Err(Reason::Expired(e));
        }
        if body.claim.is_about_leaf() {
            let ceiling = self.v.policy.leaf_ceiling.min(LEAF_CEILING);
            match body.expires {
                Some(e) if e - body.issued <= ceiling => {}
                _ => return Err(Reason::LeafCeiling(ceiling)),
            }
        }
        Ok(())
    }

    /// A valid revocation by `id` of `hash` (or of a data signature). Each
    /// revocation examined counts against the budget; if the budget runs
    /// out before a valid one is found, the answer is [`Reason::Limit`],
    /// never "not revoked".
    fn check_revoked(&mut self, id: Id, hash: &Hash) -> Result<(), Reason> {
        for r in self.v.material.revocations(&id, hash).to_vec() {
            match self.status(&r) {
                Ok(()) => return Err(Reason::Revoked(r)),
                Err(Reason::Limit) => return Err(Reason::Limit),
                Err(_) => {}
            }
            if self.over_budget() {
                return Err(Reason::Limit);
            }
        }
        // Valid records list revocations too; they are combined, so any
        // one listing `hash` revokes it (DESIGN.md §18.4).
        for r in self.v.material.records_by(&id).to_vec() {
            if !self
                .v
                .material
                .record(&r)
                .is_some_and(|rec| rec.body.revokes(hash))
            {
                continue;
            }
            match self.record_status(&r) {
                Ok(()) => return Err(Reason::Revoked(r)),
                Err(Reason::Limit) => return Err(Reason::Limit),
                Err(_) => {}
            }
            if self.over_budget() {
                return Err(Reason::Limit);
            }
        }
        Ok(())
    }

    /// Whether a record is valid (DESIGN.md §18.4): made under its issuer's
    /// head, naming it, and signed by its current authority. Its `issued`
    /// plays no part: what it revokes stays revoked whatever the clock says;
    /// only freshness ([`Query::newest_record`]) reads the time. Memoized
    /// with statements (the labels differ, so the hashes cannot collide).
    fn record_status(&mut self, h: &Hash) -> Result<(), Reason> {
        if let Some(s) = self.status.get(h) {
            return s.clone();
        }
        let result = self.compute_record_status(h);
        self.status.insert(*h, result.clone());
        result
    }

    fn compute_record_status(&mut self, h: &Hash) -> Result<(), Reason> {
        let Some(rec) = self.v.material.record(h) else {
            return Err(Reason::Malformed("unknown record"));
        };
        let log = self.log(&rec.body.id)?;
        let Ok(log) = &*log else {
            return Err(Reason::BadSignature);
        };
        let head = log.head_n();
        if rec.body.event != head {
            return Err(Reason::UnknownEvent {
                event: rec.body.event,
                head,
            });
        }
        if log.event_hash(head) != Some(rec.body.head) {
            return Err(Reason::Malformed("record names another head event"));
        }
        if !self.v.policy.accepts(Suite::SlhDsaShake128s) {
            return Err(Reason::Suite(Suite::SlhDsaShake128s));
        }
        let authority = log.head().authority();
        if !self.sig_check(*h, authority.hash(), &rec.sigs, || {
            rec.verify_threshold(authority)
        })? {
            return Err(Reason::BadSignature);
        }
        Ok(())
    }

    /// The newest valid record by `id` that is not from the future
    /// (`issued ≤ now + skew`): (hash, issued). This is the record that
    /// counts for freshness.
    fn newest_record(&mut self, id: Id) -> Result<Option<(Hash, Time)>, Reason> {
        if let Some(n) = self.newest.get(&id) {
            return Ok(*n);
        }
        let mut best: Option<(Hash, Time)> = None;
        let latest = self.now.saturating_add(self.v.policy.skew);
        for r in self.v.material.records_by(&id).to_vec() {
            let Some(issued) = self.v.material.record(&r).map(|rec| rec.body.issued) else {
                continue;
            };
            if issued > latest || best.is_some_and(|(_, b)| issued <= b) {
                continue;
            }
            match self.record_status(&r) {
                Ok(()) => best = Some((r, issued)),
                Err(Reason::Limit) => return Err(Reason::Limit),
                Err(_) => {}
            }
        }
        self.newest.insert(id, best);
        Ok(best)
    }

    /// The freshness rule (DESIGN.md §18.6) for something `id` issued at
    /// `issued`, expiring at `expires`: if `id` publishes records with
    /// max-age D, anything that lives longer than D needs a valid record by
    /// `id` no older than D. Local identities are exempt; so are
    /// revocations, which callers don't pass here.
    fn fresh(&mut self, id: Id, issued: Time, expires: Option<Time>) -> Result<(), Reason> {
        if self.v.local.contains(&id) {
            return Ok(());
        }
        let log = self.log(&id)?;
        let Ok(log) = &*log else {
            return Err(Reason::BadSignature);
        };
        let Some(max_age) = log.head().publish().map(|p| p.max_age()) else {
            return if self.v.policy.require_records {
                Err(Reason::NoRecords)
            } else {
                Ok(())
            };
        };
        if expires.is_some_and(|e| e.saturating_sub(issued) <= max_age) {
            return Ok(());
        }
        match self.newest_record(id)? {
            Some((h, t)) if t >= self.now.saturating_sub(max_age) => {
                self.fresh_by.insert(id, h);
                Ok(())
            }
            _ => Err(Reason::NoFreshRecord { max_age }),
        }
    }

    /// Adds to `proof` the records its identities' freshness relied on.
    fn attach_records(&self, proof: &mut Proof) {
        for id in &proof.ids {
            if let Some(h) = self.fresh_by.get(id) {
                proof.records.insert(*h);
            }
        }
    }

    fn reject(&mut self, statement: Hash, reason: Reason) {
        if self.rejected.len() < MAX_REJECTIONS
            && !self.rejected.iter().any(|r| r.statement == statement)
        {
            self.rejected.push(Rejection { statement, reason });
        }
    }

    fn over_budget(&self) -> bool {
        self.status.len() > self.v.policy.max_statements
            || self.signatures > self.v.policy.max_signatures
    }

    fn budget(&self) -> Result<(), Denial> {
        if self.status.len() > self.v.policy.max_statements {
            Err(Denial::Limit("statements examined"))
        } else if self.signatures > self.v.policy.max_signatures {
            Err(Denial::Limit("signatures checked"))
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
        let mut current = Members::from([(Holder::Id(*base), Derivation::default())]);
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
                    next.entry(m.clone()).or_insert_with(|| derivation.join(d));
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
                out.entry(holder)
                    .or_insert_with(|| Derivation::statement(h, d));
            }
        }
        let out = Rc::new(out);
        self.names.insert(key, out.clone());
        Ok(out)
    }

    /// The holders a subject denotes.
    fn denote(&mut self, subject: &Subject, depth: usize) -> Result<Members, Denial> {
        Ok(match subject {
            Subject::Id(id) => BTreeMap::from([(Holder::Id(*id), Derivation::default())]),
            Subject::Leaf(k) => BTreeMap::from([(Holder::Leaf(k.clone()), Derivation::default())]),
            Subject::Opaque(k) => {
                BTreeMap::from([(Holder::Opaque(k.clone()), Derivation::default())])
            }
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
                let Some(Claim::Grant { subject, tags, .. }) =
                    self.v.material.statement(&h).map(|s| s.body.claim.clone())
                else {
                    continue;
                };
                let effs: Vec<Tag> = tags.iter().filter_map(|t| held.intersect(t)).collect();
                if effs.iter().any(|e| tag.is_within(e)) {
                    continue;
                }
                // As in the search: names only under a valid grant.
                if matches!(subject, Subject::Name(_)) && self.status(&h).is_err() {
                    continue;
                }
                let reaches = self
                    .denote(&subject, max_depth)
                    .is_ok_and(|m| m.contains_key(want));
                if reaches && self.status(&h).is_ok() {
                    let reason = if effs.is_empty() {
                        Reason::OutsideIssuer {
                            granted: tags,
                            held: held.clone(),
                        }
                    } else {
                        Reason::Covers(effs)
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
        // BFS over (holder, effective tag). Each node remembers how it was
        // reached; derivations are flattened only for the chain found.
        struct Edge {
            grant: Hash,
            names: Derivation,
            holder: Holder,
            tag: Tag,
        }
        impl Edge {
            fn step(&self) -> Step {
                Step {
                    grant: self.grant,
                    names: self.names.hashes(),
                    holder: self.holder.clone(),
                    tag: self.tag.clone(),
                }
            }
        }
        struct Node {
            principal: Principal,
            tag: Tag,
            root: Id,
            parent: Option<usize>,
            step: Option<Edge>,
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
                    records: BTreeSet::new(),
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
                    tags,
                    delegate,
                }) = self.v.material.statement(&h).map(|s| s.body.claim.clone())
                else {
                    continue;
                };
                // A grant with several tags is several grants (§18.2), but
                // only one of them can lead to `tag`: two that both did would
                // be prefixes of `tag`, so one would cover the other, which
                // Tags forbids.
                let Some(gtag) = tags.iter().find(|t| tag.is_within(t)) else {
                    continue;
                };
                // Structural checks first: is this grant useful at all? Tags
                // only lengthen along a chain, so once the effective tag is
                // not a prefix of `tag` no extension can cover `tag`. This
                // also bounds the search to (principal, prefix of `tag`).
                let Some(eff) = node_tag.intersect(gtag) else {
                    continue;
                };
                if !tag.is_within(&eff) {
                    continue;
                }
                // A name path is resolved only under a grant that is itself
                // valid: otherwise a forged grant could make the search read
                // (and report on) names by any identity it likes.
                if matches!(gsubject, Subject::Name(_))
                    && let Err(reason) = self.status(&h)
                {
                    self.reject(h, reason);
                    continue;
                }
                let members = self.denote(&gsubject, max_depth)?;
                let finishes = members.contains_key(&want);
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
                        Edge {
                            grant: h,
                            names: names.clone(),
                            holder: want.clone(),
                            tag: eff.clone(),
                        }
                        .step(),
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
                        step: Some(Edge {
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
            if let Some(edge) = &node.step {
                steps.push(edge.step());
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
            records: BTreeSet::new(),
        };
        for h in proof.statements() {
            self.note_statement(&mut proof, &h);
        }
        // The subject's log too, so a proof checked alone still sees an
        // equivocating subject (SPEC §10).
        if let Holder::Id(id) = subject {
            proof.ids.insert(*id);
        }
        self.attach_records(&mut proof);
        Ok(proof)
    }
}
