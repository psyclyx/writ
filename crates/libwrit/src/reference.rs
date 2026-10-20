//! A brute-force reference verifier: small, slow, written from DESIGN.md
//! §9.3 without the real verifier's indexes, caches, pruning or search
//! order. Property tests check that both agree on generated material.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use crate::model::{LEAF_CEILING, MIN_MAX_AGE};
use crate::scenarios::{Ident, grant_tags, name, path};
use crate::testing::{FakeLeaf, TestRng};
use crate::*;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

type Table = BTreeMap<(Id, Vec<u8>), BTreeSet<Holder>>;

/// Generated times are small numbers scaled by this, so that the one-hour
/// minimum max-age (§18.5) falls inside them: records can be too old, and
/// statements can be inside or outside the short-lived exemption.
const SCALE: u64 = 100;

struct Reference<'a> {
    m: &'a Material,
    policy: &'a Policy,
    roots: &'a [Id],
    /// Identities whose whole issuance the caller holds: need no records.
    local: &'a [Id],
    now: Time,
}

impl Reference<'_> {
    fn valid(&self, h: &Hash) -> bool {
        let Some(st) = self.m.statement(h) else {
            return false;
        };
        let s = &st.body;
        if s.check_wellformed().is_err() {
            return false;
        }
        match &s.issuer {
            Issuer::Identity { id, event } => {
                let log = self.m.log(id);
                let Ok(log) = &*log else { return false };
                let head = log.head_n();
                if *event > head {
                    return false;
                }
                let signed_ok = if *event == head {
                    st.verify_threshold(log.head().authority())
                } else {
                    log.head().keep().contains(h)
                };
                if !signed_ok {
                    return false;
                }
                let is_revoke = matches!(s.claim, Claim::Revoke { .. });
                if let Some(mv) = log.event(*event).unwrap().max_validity()
                    && !is_revoke
                    && !s.expires.is_some_and(|e| e - s.issued <= mv)
                {
                    return false;
                }
                if !is_revoke {
                    for (rh, r) in self.m.statements() {
                        if let Claim::Revoke { target } = &r.body.claim
                            && target == h
                            && r.body.issuer.id() == Some(*id)
                            && self.valid(rh)
                        {
                            return false;
                        }
                    }
                    // Any valid record by the issuer that lists it (§18.4),
                    // found by scanning every record.
                    let records: Vec<&Signed<Record>> = self
                        .m
                        .records()
                        .filter(|(rh, r)| r.body.id == *id && self.record_valid(rh))
                        .map(|(_, r)| r)
                        .collect();
                    if records.iter().any(|r| r.body.revoked.contains(h)) {
                        return false;
                    }
                    // Freshness (§18.6), unless the issuer is local.
                    if !self.local.contains(id) {
                        match log.head().publish() {
                            Some(p) => {
                                let long = !s.expires.is_some_and(|e| e - s.issued <= p.max_age());
                                let cutoff = self.now.saturating_sub(p.max_age());
                                if long && !records.iter().any(|r| r.body.issued >= cutoff) {
                                    return false;
                                }
                            }
                            None if self.policy.require_records => return false,
                            None => {}
                        }
                    }
                }
            }
            Issuer::Leaf(k) => {
                // The key comes from any statement about it.
                let key = self
                    .m
                    .statements()
                    .find_map(|(_, s)| match s.body.claim.subject() {
                        Some(Subject::Leaf(key)) if key.id() == *k => Some(key),
                        _ => None,
                    });
                if !key.is_some_and(|key| st.verify_leaf(key)) {
                    return false;
                }
            }
        }
        if s.issued > self.now + self.policy.skew {
            return false;
        }
        if s.expires.is_some_and(|e| self.now >= e) {
            return false;
        }
        if s.claim.is_about_leaf() {
            let ceiling = self.policy.leaf_ceiling.min(LEAF_CEILING);
            if !s.expires.is_some_and(|e| e - s.issued <= ceiling) {
                return false;
            }
        }
        true
    }

    /// A record counts when it is made under its issuer's head, names it,
    /// is signed by the head's authority, and is not from the future.
    fn record_valid(&self, r: &Hash) -> bool {
        let Some(rec) = self.m.record(r) else {
            return false;
        };
        let log = self.m.log(&rec.body.id);
        let Ok(log) = &*log else { return false };
        rec.body.event == log.head_n()
            && log.event_hash(log.head_n()) == Some(rec.body.head)
            && rec.verify_threshold(log.head().authority())
            && rec.body.issued <= self.now + self.policy.skew
    }

    /// Jacobi iteration: `tables[d]` holds members with derivations of depth ≤ d.
    fn tables(&self) -> Vec<Table> {
        let mut tables = vec![Table::new()];
        for _ in 0..self.policy.max_name_depth {
            let prev = tables.last().unwrap().clone();
            let mut next = Table::new();
            for (h, st) in self.m.statements() {
                if let Claim::Name { name, subject } = &st.body.claim
                    && let Issuer::Identity { id, .. } = &st.body.issuer
                    && self.valid(h)
                {
                    next.entry((*id, name.clone()))
                        .or_default()
                        .extend(eval(subject, &prev));
                }
            }
            tables.push(next);
        }
        tables
    }

    fn check(&self, subject: &Holder, tag: &Tag) -> bool {
        if let Holder::Id(id) = subject
            && matches!(&*self.m.log(id), Err(LogError::Equivocation(_)))
        {
            return false;
        }
        let names = self.tables().pop().unwrap();
        for root in self.roots {
            if self.m.log(root).is_err() {
                continue;
            }
            if *subject == Holder::Id(*root) {
                return true;
            }
            if self.chains(
                &Holder::Id(*root),
                &Tag::everything(),
                0,
                subject,
                tag,
                &names,
            ) {
                return true;
            }
        }
        false
    }

    fn chains(
        &self,
        from: &Holder,
        eff: &Tag,
        depth: usize,
        want: &Holder,
        tag: &Tag,
        names: &Table,
    ) -> bool {
        for (h, st) in self.m.statements() {
            if !issued_by(&st.body.issuer, from) {
                continue;
            }
            let Claim::Grant {
                subject,
                tags,
                delegate,
            } = &st.body.claim
            else {
                continue;
            };
            if !self.valid(h) {
                continue;
            }
            // Literally one grant per tag (§18.2).
            for gtag in tags.iter() {
                let Some(next) = eff.intersect(gtag) else {
                    continue;
                };
                let members = eval(subject, names);
                if members.contains(want) && tag.is_within(&next) {
                    return true;
                }
                if *delegate && depth + 1 < self.policy.max_chain {
                    for m in &members {
                        if !matches!(m, Holder::Opaque(_))
                            && self.chains(m, &next, depth + 1, want, tag, names)
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

/// Whether `holder` is `issuer`.
fn issued_by(issuer: &Issuer, holder: &Holder) -> bool {
    match (issuer, holder) {
        (Issuer::Identity { id, .. }, Holder::Id(h)) => id == h,
        (Issuer::Leaf(k), Holder::Leaf(h)) => *k == h.id(),
        _ => false,
    }
}

fn eval(subject: &Subject, table: &Table) -> BTreeSet<Holder> {
    match subject {
        Subject::Id(id) => BTreeSet::from([Holder::Id(*id)]),
        Subject::Leaf(k) => BTreeSet::from([Holder::Leaf(k.clone())]),
        Subject::Opaque(k) => BTreeSet::from([Holder::Opaque(k.clone())]),
        Subject::Name(p) => {
            let mut set = BTreeSet::from([Holder::Id(p.base)]);
            for n in &p.names {
                let mut next = BTreeSet::new();
                for h in &set {
                    if let Holder::Id(z) = h
                        && let Some(ms) = table.get(&(*z, n.clone()))
                    {
                        next.extend(ms.iter().cloned());
                    }
                }
                set = next;
            }
            set
        }
    }
}

// ---------------------------------------------------------------------------
// Generated worlds

const IDS: usize = 4;
const LEAVES: usize = 2;

#[derive(Clone, Debug)]
enum GenSubject {
    Id(usize),
    Leaf(usize),
    Opaque,
    Name(usize, Vec<bool>),
}

#[derive(Clone, Debug)]
enum GenClaim {
    /// Indices into TAGS: one or two tags (DESIGN.md §18.2).
    Grant(GenSubject, Vec<usize>, bool),
    Name(bool, GenSubject),
    Revoke(usize),
}

#[derive(Clone, Debug)]
struct GenStatement {
    /// Leave the statement as generated; otherwise nudge it towards well-formed.
    raw: bool,
    issuer: Result<(usize, u64), usize>,
    claim: GenClaim,
    issued: u64,
    lifetime: Option<u64>,
    good_sig: bool,
}

#[derive(Clone, Debug)]
struct GenWorld {
    rotated: [bool; IDS],
    keep_mask: [u16; IDS],
    max_validity: [bool; IDS],
    equivocate: bool,
    statements: Vec<GenStatement>,
    max_chain: usize,
    max_name_depth: usize,
    /// Which identities publish records (DESIGN.md §18.5).
    publish: [bool; IDS],
    records: Vec<GenRecord>,
    /// The verifier holds the root's whole issuance (§18.6).
    local_root: bool,
    require_records: bool,
}

/// A record by identity `id`, revoking the statements at `revoke` (indices
/// into the generated statements), made before the identity's rotation (so
/// it no longer counts) or after, with a good or broken signature.
#[derive(Clone, Debug)]
struct GenRecord {
    id: usize,
    revoke: Vec<usize>,
    issued: u64,
    before_rotation: bool,
    good_sig: bool,
}

fn arb_record() -> impl Strategy<Value = GenRecord> {
    (
        0..IDS,
        proptest::collection::vec(0..24usize, 0..3),
        0..50u64,
        proptest::bool::weighted(0.2),
        proptest::bool::weighted(0.9),
    )
        .prop_map(
            |(id, revoke, issued, before_rotation, good_sig)| GenRecord {
                id,
                revoke,
                issued,
                before_rotation,
                good_sig,
            },
        )
}

const TAGS: [&str; 5] = ["()", "(a)", "(a b)", "(b)", "(a b c)"];

fn arb_subject() -> impl Strategy<Value = GenSubject> {
    prop_oneof![
        4 => (0..IDS).prop_map(GenSubject::Id),
        1 => (0..LEAVES).prop_map(GenSubject::Leaf),
        1 => Just(GenSubject::Opaque),
        3 => (
            prop_oneof![2 => Just(0usize), 1 => 1..IDS],
            prop_oneof![3 => proptest::collection::vec(any::<bool>(), 1..2), 1 => proptest::collection::vec(any::<bool>(), 2..3)],
        )
            .prop_map(|(b, n)| GenSubject::Name(b, n)),
    ]
}

fn arb_tag_index() -> impl Strategy<Value = usize> {
    prop_oneof![3 => Just(0usize), 3 => Just(1usize), 1 => Just(2usize), 1 => Just(3usize)]
}

fn arb_statement() -> impl Strategy<Value = GenStatement> {
    let issuer = prop_oneof![
        6 => (
            prop_oneof![3 => Just(0usize), 2 => 1..IDS],
            prop_oneof![8 => Just(0u64), 3 => Just(1u64), 1 => Just(2u64)],
        )
            .prop_map(Ok),
        1 => (0..LEAVES).prop_map(Err),
    ];
    let claim = prop_oneof![
        6 => (
            arb_subject(),
            prop_oneof![
                5 => arb_tag_index().prop_map(|t| vec![t]),
                // Pairs where neither covers the other: (a)+(b), (a b)+(b), (b)+(a b c).
                1 => prop_oneof![3 => Just(vec![1, 3]), 1 => Just(vec![2, 3]), 1 => Just(vec![3, 4])],
            ],
            proptest::bool::weighted(0.7),
        ).prop_map(|(s, t, d)| GenClaim::Grant(s, t, d)),
        4 => (any::<bool>(), arb_subject()).prop_map(|(n, s)| GenClaim::Name(n, s)),
        1 => (0..24usize).prop_map(GenClaim::Revoke),
    ];
    (
        issuer,
        claim,
        0..50u64,
        prop_oneof![2 => Just(None), 1 => (1..40u64).prop_map(Some), 1 => (1..20u64).prop_map(Some)],
        proptest::bool::weighted(0.95),
        proptest::bool::weighted(0.1),
    )
        .prop_map(|(issuer, claim, issued, lifetime, good_sig, raw)| GenStatement {
            raw,
            issuer,
            claim,
            issued,
            lifetime,
            good_sig,
        })
}

fn arb_world() -> impl Strategy<Value = GenWorld> {
    (
        any::<[bool; IDS]>(),
        any::<[u16; IDS]>(),
        proptest::array::uniform4(proptest::bool::weighted(0.1)),
        proptest::bool::weighted(0.1),
        proptest::collection::vec(arb_statement(), 0..24),
        2..5usize,
        1..4usize,
        proptest::array::uniform4(proptest::bool::weighted(0.3)),
        proptest::collection::vec(arb_record(), 0..8),
        (proptest::bool::weighted(0.3), proptest::bool::weighted(0.2)),
    )
        .prop_map(
            |(
                rotated,
                keep_mask,
                max_validity,
                equivocate,
                statements,
                max_chain,
                max_name_depth,
                publish,
                records,
                (local_root, require_records),
            )| {
                GenWorld {
                    rotated,
                    keep_mask,
                    max_validity,
                    equivocate,
                    statements,
                    max_chain,
                    max_name_depth,
                    publish,
                    records,
                    local_root,
                    require_records,
                }
            },
        )
}

struct Built {
    material: Material,
    ids: Vec<Id>,
    /// The root, when the world treats it as local.
    local: Vec<Id>,
    leaves: Vec<FakeLeaf>,
    opaque: OpaqueKey,
    policy: Policy,
}

fn build(w: &GenWorld) -> Built {
    let make = |i: usize| {
        let publish = w.publish[i]
            .then(|| Publish::new(MIN_MAX_AGE, vec![]))
            .flatten();
        Ident::incept(
            i as u8 + 1,
            w.max_validity[i].then_some(30 * SCALE),
            publish,
        )
    };
    let mut idents: Vec<Ident> = (0..IDS).map(make).collect();
    let ids: Vec<Id> = idents.iter().map(|i| i.id).collect();
    let leaves: Vec<FakeLeaf> = (0..LEAVES).map(|i| FakeLeaf::new(i as u8 + 50)).collect();
    let opaque = OpaqueKey {
        kind: b"app".to_vec(),
        bytes: vec![7],
    };
    let subject = |s: &GenSubject| match s {
        GenSubject::Id(i) => Subject::Id(ids[*i]),
        GenSubject::Leaf(i) => Subject::Leaf(leaves[*i].0.clone()),
        GenSubject::Opaque => Subject::Opaque(opaque.clone()),
        GenSubject::Name(b, ns) => {
            let names: Vec<&str> = ns.iter().map(|x| if *x { "x" } else { "y" }).collect();
            path(ids[*b], &names)
        }
    };
    let mut items = Vec::new();
    let mut hashes: Vec<Hash> = Vec::new();
    let mut by_issuer: Vec<Vec<Hash>> = vec![Vec::new(); IDS];
    for g in &w.statements {
        let mut g = g.clone();
        if !g.raw {
            match (&mut g.claim, &mut g.issuer) {
                (GenClaim::Grant(_, _, d), Err(_)) => *d = false,
                (claim, Err(_)) => *claim = GenClaim::Grant(GenSubject::Opaque, vec![0], false),
                (GenClaim::Revoke(_), _) => g.lifetime = None,
                (GenClaim::Grant(GenSubject::Opaque, _, d), _) => *d = false,
                _ => {}
            }
            if let Ok((i, event)) = &mut g.issuer
                && *event == 1
                && !w.rotated[*i]
            {
                *event = 0;
            }
            if let GenClaim::Grant(GenSubject::Leaf(_), _, _)
            | GenClaim::Name(_, GenSubject::Leaf(_)) = g.claim
            {
                g.lifetime = Some(g.lifetime.unwrap_or(10).min(20));
            }
        }
        let g = &g;
        let claim = match &g.claim {
            GenClaim::Grant(s, t, d) => {
                let names: Vec<&str> = t.iter().map(|i| TAGS[*i]).collect();
                grant_tags(subject(s), &names, *d)
            }
            GenClaim::Name(n, s) => name(if *n { "x" } else { "y" }, subject(s)),
            GenClaim::Revoke(i) => Claim::Revoke {
                target: hashes.get(*i).copied().unwrap_or(Hash([0; 32])),
            },
        };
        let expires = g.lifetime.map(|l| (g.issued + l) * SCALE);
        let issued = g.issued * SCALE;
        let mut signed = match g.issuer {
            Ok((i, event)) => {
                // Sign with the key of the claimed event (or event 0's for
                // events that don't exist).
                let key_event = if event == 1 && w.rotated[i] { 1 } else { 0 };
                let mut s = idents[i].say_as(key_event, claim, issued, expires);
                if event != key_event {
                    s.body.issuer = Issuer::Identity { id: ids[i], event };
                    let key = idents[i].key(key_event);
                    s = sign_with_authority(
                        s.body,
                        &Authority::single(key.0),
                        &[&key],
                        &mut TestRng::new(0),
                    )
                    .unwrap();
                }
                if event == 0 {
                    by_issuer[i].push(s.body.hash());
                }
                s
            }
            Err(l) => {
                let body = Statement {
                    issuer: Issuer::Leaf(leaves[l].0.id()),
                    issued,
                    expires,
                    note: None,
                    claim,
                };
                let bytes = leaves[l]
                    .sign(&body.message(), &mut TestRng::new(0))
                    .unwrap();
                Signed {
                    body,
                    sigs: vec![Sig { index: 0, bytes }],
                }
            }
        };
        if !g.good_sig {
            signed.sigs[0].bytes[0] ^= 1;
        }
        hashes.push(signed.body.hash());
        items.push(Item::Statement(signed));
    }
    let record = |ident: &Ident, r: &GenRecord| {
        let revoked = r
            .revoke
            .iter()
            .filter_map(|j| hashes.get(*j).copied())
            .collect();
        let mut rec = ident.record(revoked, r.issued * SCALE);
        if !r.good_sig {
            rec.sigs[0].bytes[0] ^= 1;
        }
        Item::Record(rec)
    };
    for i in 0..IDS {
        let mine: Vec<&GenRecord> = w.records.iter().filter(|r| r.id == i).collect();
        // Records made before a rotation no longer count after it.
        items.extend(
            mine.iter()
                .filter(|r| r.before_rotation)
                .map(|r| record(&idents[i], r)),
        );
        if w.rotated[i] {
            let keep: Vec<Hash> = by_issuer[i]
                .iter()
                .enumerate()
                .filter(|(j, _)| w.keep_mask[i] >> (j % 16) & 1 == 1)
                .map(|(_, h)| *h)
                .collect();
            let mv = idents[i].events[0].body.max_validity();
            idents[i].rotate(keep, mv);
        }
        items.extend(
            mine.iter()
                .filter(|r| !r.before_rotation)
                .map(|r| record(&idents[i], r)),
        );
        items.extend(idents[i].items());
    }
    if w.equivocate {
        let mut twin = make(1);
        items.push(Item::Event(twin.rotate(vec![Hash([1; 32])], Some(12_345))));
    }
    Built {
        material: Material::from_items(items),
        local: if w.local_root {
            vec![ids[0]]
        } else {
            Vec::new()
        },
        ids,
        leaves,
        opaque,
        policy: Policy {
            skew: 5 * SCALE,
            leaf_ceiling: 20 * SCALE,
            require_records: w.require_records,
            max_chain: w.max_chain,
            max_name_depth: w.max_name_depth,
            ..Policy::default()
        },
    }
}

fn arb_holder() -> impl Strategy<Value = GenSubject> {
    prop_oneof![
        (0..IDS).prop_map(GenSubject::Id),
        (0..LEAVES).prop_map(GenSubject::Leaf),
        Just(GenSubject::Opaque),
    ]
}

fn holder(b: &Built, s: &GenSubject) -> Holder {
    match s {
        GenSubject::Id(i) => Holder::Id(b.ids[*i]),
        GenSubject::Leaf(i) => Holder::Leaf(b.leaves[*i].0.clone()),
        _ => Holder::Opaque(b.opaque.clone()),
    }
}

/// Independently re-checks a proof's chain.
fn proof_is_sound(r: &Reference<'_>, proof: &Proof, want: &Holder, tag: &Tag) -> bool {
    let names = r.tables().pop().unwrap();
    let mut from = Holder::Id(proof.root);
    let mut eff = Tag::everything();
    if !r.roots.contains(&proof.root) {
        return false;
    }
    for (i, step) in proof.steps.iter().enumerate() {
        let Some(st) = r.m.statement(&step.grant) else {
            return false;
        };
        let Claim::Grant {
            subject,
            tags,
            delegate,
        } = &st.body.claim
        else {
            return false;
        };
        let last = i + 1 == proof.steps.len();
        if !issued_by(&st.body.issuer, &from) || !r.valid(&step.grant) || (!last && !delegate) {
            return false;
        }
        if !eval(subject, &names).contains(&step.holder) {
            return false;
        }
        for n in &step.names {
            if !r.valid(n) {
                return false;
            }
        }
        // One of the grant's tags must give the step's recorded tag.
        let Some(next) = tags
            .iter()
            .filter_map(|t| eff.intersect(t))
            .find(|n| *n == step.tag)
        else {
            return false;
        };
        eff = next;
        from = step.holder.clone();
    }
    from == *want && tag.is_within(&eff) && eff == proof.tag
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn check_agrees_with_reference(
        w in arb_world(),
        q in arb_holder(),
        t in 0..TAGS.len(),
        now in (0..100u64).prop_map(|n| n * SCALE),
    ) {
        let b = build(&w);
        let roots = [b.ids[0]];
        let want = holder(&b, &q);
        let tag = Tag::parse(TAGS[t]).unwrap();
        let real = Verifier::new(&roots, &b.material, &b.policy).with_local(&b.local).check(&want, &tag, now);
        let r = Reference { m: &b.material, policy: &b.policy, roots: &roots, local: &b.local, now };
        let expected = r.check(&want, &tag);
        prop_assert_eq!(real.is_ok(), expected, "real: {:?}", real);
        if let Ok(proof) = real {
            prop_assert!(proof_is_sound(&r, &proof, &want, &tag), "unsound proof {:?}", proof);
            // The proof alone convinces a fresh verifier.
            let alone = Material::from_items(proof.items(&b.material));
            let again = Verifier::new(&roots, &alone, &b.policy).with_local(&b.local).check(&want, &tag, now);
            prop_assert!(again.is_ok(), "proof not self-contained: {:?}", again);
        }
    }

    #[test]
    fn resolve_agrees_with_reference(
        w in arb_world(),
        base in 0..IDS,
        names in proptest::collection::vec(any::<bool>(), 1..3),
        now in (0..100u64).prop_map(|n| n * SCALE),
    ) {
        let b = build(&w);
        let roots = [b.ids[0]];
        let p = NamePath {
            base: b.ids[base],
            names: names.iter().map(|x| if *x { b"x".to_vec() } else { b"y".to_vec() }).collect(),
        };
        let real = Verifier::new(&roots, &b.material, &b.policy).with_local(&b.local).resolve(&p, now);
        let r = Reference { m: &b.material, policy: &b.policy, roots: &roots, local: &b.local, now };
        let expected = eval(&Subject::Name(p.clone()), r.tables().last().unwrap());
        match real {
            Ok(members) => {
                let got: BTreeSet<Holder> = members.iter().map(|(h, _)| h.clone()).collect();
                prop_assert_eq!(got, expected);
                for (_, proof) in members {
                    for h in &proof.names {
                        prop_assert!(r.valid(h));
                    }
                }
            }
            Err(Denial::NotFound { .. } | Denial::Compromised(_)) => {
                prop_assert!(expected.is_empty(), "missed {:?}", expected);
            }
            Err(e) => prop_assert!(false, "unexpected {e:?}"),
        }
    }

    #[test]
    fn statement_status_agrees(w in arb_world(), now in (0..100u64).prop_map(|n| n * SCALE)) {
        let b = build(&w);
        let roots = [b.ids[0]];
        let v = Verifier::new(&roots, &b.material, &b.policy).with_local(&b.local);
        let r = Reference { m: &b.material, policy: &b.policy, roots: &roots, local: &b.local, now };
        for (h, _) in b.material.statements() {
            prop_assert_eq!(v.statement_status(h, now).is_ok(), r.valid(h));
        }
    }
}

/// The generator must exercise both outcomes and the interesting paths, or
/// agreement with the reference means little.
#[test]
fn generator_coverage() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let (mut ok, mut multi_step, mut named, mut denied, mut compromised) = (0, 0, 0, 0, 0);
    let mut several = 0;
    let mut with_records = 0;
    let mut stale = 0;
    for _ in 0..3000 {
        let w = arb_world().new_tree(&mut runner).unwrap().current();
        let q = arb_holder().new_tree(&mut runner).unwrap().current();
        let b = build(&w);
        let roots = [b.ids[0]];
        let want = holder(&b, &q);
        for t in ["(a)", "(b)"] {
            match Verifier::new(&roots, &b.material, &b.policy)
                .with_local(&b.local)
                .check(&want, &Tag::parse(t).unwrap(), 40 * SCALE)
            {
                Ok(p) => {
                    ok += 1;
                    multi_step += usize::from(p.steps.len() > 1);
                    named += usize::from(p.steps.iter().any(|s| !s.names.is_empty()));
                    with_records += usize::from(!p.records.is_empty());
                    several += usize::from(p.steps.iter().any(|s| {
                        matches!(
                            b.material.statement(&s.grant).map(|st| &st.body.claim),
                            Some(Claim::Grant { tags, .. }) if tags.as_slice().len() > 1
                        )
                    }));
                }
                Err(Denial::Compromised(_)) => compromised += 1,
                Err(Denial::NotFound { rejected }) => {
                    denied += 1;
                    stale += usize::from(rejected.iter().any(|r| {
                        matches!(r.reason, Reason::NoFreshRecord { .. } | Reason::NoRecords)
                    }));
                }
                Err(_) => denied += 1,
            }
        }
    }
    eprintln!(
        "ok {ok} (multi-step {multi_step}, via names {named}, several tags {several}, records {with_records}), denied {denied} (no fresh record {stale}), compromised {compromised}"
    );
    assert!(ok > 300 && denied > 300, "ok {ok} denied {denied}");
    assert!(
        multi_step > 20
            && named > 20
            && compromised > 5
            && several > 20
            && with_records > 20
            && stale > 20
    );
}
