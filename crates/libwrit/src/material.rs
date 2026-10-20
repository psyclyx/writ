//! Material: an indexed pile of log events, statements, and signatures, in
//! any order (DESIGN.md §9.1). Adding is idempotent; duplicates merge.

use crate::hash::{Hash, Id, LeafId};
use crate::keys::{LeafKey, PublicKey};
use crate::log::{Evidence, Log, LogError};
use crate::model::{
    Body, Claim, DataSig, Event, Issuer, Item, Record, Sig, Signed, Statement, Subject,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

/// Something that can issue statements.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    /// An identity.
    Id(Id),
    /// A leaf key, by id.
    Leaf(LeafId),
}

/// An indexed pile of items.
#[derive(Default)]
pub struct Material {
    inceptions: BTreeMap<Id, Signed<Event>>,
    /// Rotation candidates per `(id, n)`, by body hash: every index here is
    /// keyed by hash, so adding stays linear in the material.
    rotations: BTreeMap<(Id, u64), BTreeMap<Hash, Signed<Event>>>,
    statements: BTreeMap<Hash, Signed<Statement>>,
    signatures: BTreeMap<Hash, Signed<DataSig>>,
    records: BTreeMap<Hash, Signed<Record>>,
    records_by: BTreeMap<Id, Vec<Hash>>,
    /// Records by `(issuer, revoked hash)`, so checking whether a hash is
    /// revoked by a record costs a lookup, not a scan of every record.
    records_revoking: BTreeMap<(Id, Hash), Vec<Hash>>,
    names: BTreeMap<(Id, Vec<u8>), Vec<Hash>>,
    grants: BTreeMap<Principal, Vec<Hash>>,
    revocations: BTreeMap<(Id, Hash), Vec<Hash>>,
    by_issuer: BTreeMap<Id, Vec<Hash>>,
    leaf_keys: BTreeMap<LeafId, LeafKey>,
    logs: RefCell<HashMap<Id, Rc<Result<Log, LogError>>>>,
    sig_cache: RefCell<HashMap<SigKey, bool>>,
    /// Per body hash, the signatures merged so far as (index, digest of the
    /// bytes). Built on a body's first merge, so merging stays linear
    /// however many copies arrive.
    merged: HashMap<Hash, HashSet<(u8, Hash)>>,
}

/// What a signature check is cached under: body hash, signer (authority
/// hash or leaf id), and a digest of the signatures. A result is a fact
/// about exactly those signatures, so it never goes stale: a copy that
/// arrives with more signatures is checked afresh under a new key.
pub(crate) type SigKey = (Hash, Hash, Hash);

impl Material {
    /// Empty material.
    pub fn new() -> Material {
        Material::default()
    }

    /// Material from items.
    pub fn from_items(items: impl IntoIterator<Item = Item>) -> Material {
        let mut m = Material::new();
        for item in items {
            m.add(item);
        }
        m
    }

    /// Adds an item. Root keys and authorities are ignored; everything else
    /// is indexed, including leaf keys by id. Adding a body already present
    /// merges its signatures.
    pub fn add(&mut self, item: Item) {
        match item {
            Item::Event(ev) => {
                self.logs.get_mut().clear();
                match &ev.body {
                    Event::Inception(_) => {
                        let id = ev.body.id();
                        match self.inceptions.get_mut(&id) {
                            Some(existing) => {
                                merge_sigs(
                                    &mut self.merged,
                                    ev.body.hash(),
                                    &mut existing.sigs,
                                    ev.sigs,
                                );
                            }
                            None => {
                                self.inceptions.insert(id, ev);
                            }
                        }
                    }
                    Event::Rotation(r) => {
                        let slot = self.rotations.entry((r.id, r.n)).or_default();
                        let h = ev.body.hash();
                        match slot.get_mut(&h) {
                            Some(existing) => {
                                merge_sigs(&mut self.merged, h, &mut existing.sigs, ev.sigs);
                            }
                            None => {
                                slot.insert(h, ev);
                            }
                        }
                    }
                }
            }
            Item::Statement(st) => {
                let h = st.body.hash();
                if let Some(existing) = self.statements.get_mut(&h) {
                    merge_sigs(&mut self.merged, h, &mut existing.sigs, st.sigs);
                    return;
                }
                if let Some(Subject::Leaf(k)) = st.body.claim.subject() {
                    self.leaf_keys.entry(k.id()).or_insert_with(|| k.clone());
                }
                let issuer_id = st.body.issuer.id();
                match (&st.body.claim, &st.body.issuer) {
                    (Claim::Name { name, .. }, Issuer::Identity { id, .. }) => {
                        self.names.entry((*id, name.clone())).or_default().push(h);
                    }
                    (Claim::Grant { .. }, issuer) => {
                        let p = match issuer {
                            Issuer::Identity { id, .. } => Principal::Id(*id),
                            Issuer::Leaf(k) => Principal::Leaf(*k),
                        };
                        self.grants.entry(p).or_default().push(h);
                    }
                    (Claim::Revoke { target }, Issuer::Identity { id, .. }) => {
                        self.revocations.entry((*id, *target)).or_default().push(h);
                    }
                    // Leaf-issued names and revocations are never valid.
                    _ => {}
                }
                if let Some(id) = issuer_id {
                    self.by_issuer.entry(id).or_default().push(h);
                }
                self.statements.insert(h, st);
            }
            Item::Signature(sig) => {
                let h = sig.body.hash();
                match self.signatures.get_mut(&h) {
                    Some(existing) => {
                        merge_sigs(&mut self.merged, h, &mut existing.sigs, sig.sigs);
                    }
                    None => {
                        self.signatures.insert(h, sig);
                    }
                }
            }
            Item::Record(r) => {
                let h = r.body.hash();
                match self.records.get_mut(&h) {
                    Some(existing) => {
                        merge_sigs(&mut self.merged, h, &mut existing.sigs, r.sigs);
                    }
                    None => {
                        self.records_by.entry(r.body.id).or_default().push(h);
                        for target in &r.body.revoked {
                            self.records_revoking
                                .entry((r.body.id, *target))
                                .or_default()
                                .push(h);
                        }
                        self.records.insert(h, r);
                    }
                }
            }
            Item::PublicKey(PublicKey::Leaf(k)) => {
                self.leaf_keys.entry(k.id()).or_insert(k);
            }
            Item::PublicKey(_) | Item::Authority(_) => {}
        }
    }

    /// Adds every item of a bundle.
    pub fn add_bundle(&mut self, bytes: &[u8]) -> Result<usize, crate::DecodeError> {
        let items = Item::decode_bundle(bytes)?;
        let n = items.len();
        for item in items {
            self.add(item);
        }
        Ok(n)
    }

    /// The identity's validated log. Cached until the next event is added.
    pub fn log(&self, id: &Id) -> Rc<Result<Log, LogError>> {
        if let Some(log) = self.logs.borrow().get(id) {
            return log.clone();
        }
        let result = match self.inceptions.get(id) {
            None => Err(LogError::NoInception),
            Some(inception) => Log::build(inception, |n| {
                self.rotations
                    .get(&(*id, n))
                    .map(|v| v.values().collect())
                    .unwrap_or_default()
            }),
        };
        let result = Rc::new(result);
        self.logs.borrow_mut().insert(*id, result.clone());
        result
    }

    /// Every identity with an inception in the material.
    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.inceptions.keys()
    }

    /// Equivocation evidence for every identity that has any.
    pub fn evidence(&self) -> Vec<Evidence> {
        self.inceptions
            .keys()
            .filter_map(|id| match &*self.log(id) {
                Err(LogError::Equivocation(e)) => Some((**e).clone()),
                _ => None,
            })
            .collect()
    }

    /// A statement by hash.
    pub fn statement(&self, hash: &Hash) -> Option<&Signed<Statement>> {
        self.statements.get(hash)
    }

    /// A data signature by hash.
    pub fn signature(&self, hash: &Hash) -> Option<&Signed<DataSig>> {
        self.signatures.get(hash)
    }

    /// Every statement, by hash.
    pub fn statements(&self) -> impl Iterator<Item = (&Hash, &Signed<Statement>)> {
        self.statements.iter()
    }

    /// Hashes of name statements by `issuer` for `name`.
    pub fn names(&self, issuer: &Id, name: &[u8]) -> &[Hash] {
        self.names
            .get(&(*issuer, name.to_vec()))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// A leaf key by id, from a statement about it or a key item.
    pub fn leaf_key(&self, id: &LeafId) -> Option<&LeafKey> {
        self.leaf_keys.get(id)
    }

    /// Hashes of grants issued by `principal`.
    pub fn grants_by(&self, principal: &Principal) -> &[Hash] {
        self.grants
            .get(principal)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Hashes of revocations by `issuer` of `target`.
    pub fn revocations(&self, issuer: &Id, target: &Hash) -> &[Hash] {
        self.revocations
            .get(&(*issuer, *target))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// A revocation record by hash.
    pub fn record(&self, hash: &Hash) -> Option<&Signed<Record>> {
        self.records.get(hash)
    }

    /// Every revocation record, by hash.
    pub fn records(&self) -> impl Iterator<Item = (&Hash, &Signed<Record>)> {
        self.records.iter()
    }

    /// Hashes of the revocation records made by `id`.
    pub fn records_by(&self, id: &Id) -> &[Hash] {
        self.records_by
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Hashes of the revocation records made by `id` that list `target`.
    pub fn records_revoking(&self, id: &Id, target: &Hash) -> &[Hash] {
        self.records_revoking
            .get(&(*id, *target))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Hashes of statements issued by `id`.
    pub fn issued_by(&self, id: &Id) -> &[Hash] {
        self.by_issuer
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The key a check of `sigs` over `body` by `signer` is cached under.
    /// The signatures are part of the key: the same body may arrive with
    /// different signatures.
    pub(crate) fn sig_key(body: Hash, signer: Hash, sigs: &[Sig]) -> SigKey {
        let mut bytes = Vec::with_capacity(sigs.iter().map(|s| s.bytes.len() + 1).sum());
        for s in sigs {
            bytes.push(s.index);
            bytes.extend_from_slice(&s.bytes);
        }
        (body, signer, Hash::of_data(&bytes))
    }

    /// A cached signature check result.
    pub(crate) fn cached_sig(&self, key: &SigKey) -> Option<bool> {
        self.sig_cache.borrow().get(key).copied()
    }

    /// Caches a signature check result.
    pub(crate) fn cache_sig(&self, key: SigKey, ok: bool) {
        self.sig_cache.borrow_mut().insert(key, ok);
    }
}

/// Adds signatures not already present (same index and bytes) to the copy
/// of `body` held in `into`. Merged
/// signatures are appended unsorted, possibly several per index; readers
/// pick the valid ones ([`Signed::valid_sigs`]).
fn merge_sigs(
    merged: &mut HashMap<Hash, HashSet<(u8, Hash)>>,
    body: Hash,
    into: &mut Vec<Sig>,
    from: Vec<Sig>,
) {
    let seen = merged.entry(body).or_insert_with(|| {
        into.iter()
            .map(|s| (s.index, Hash::of_data(&s.bytes)))
            .collect()
    });
    for sig in from {
        if seen.insert((sig.index, Hash::of_data(&sig.bytes))) {
            into.push(sig);
        }
    }
}

impl core::fmt::Debug for Material {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Material")
            .field("identities", &self.inceptions.len())
            .field("statements", &self.statements.len())
            .field("signatures", &self.signatures.len())
            .finish()
    }
}
