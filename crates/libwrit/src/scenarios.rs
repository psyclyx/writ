//! Scenario tests for chain semantics (DESIGN.md §4–§9), with fake signers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use crate::testing::{FakeLeaf, FakeRoot, TestRng};
use crate::*;

pub(crate) struct Ident {
    pub id: Id,
    /// keys[n] is the current key at event n.
    pub keys: Vec<FakeRoot>,
    /// next[n] is the next key committed to at event n.
    pub next: Vec<FakeRoot>,
    pub events: Vec<Signed<Event>>,
    pub seed: u8,
}

impl Ident {
    pub fn new(seed: u8) -> Ident {
        Ident::with_policy(seed, None)
    }

    pub fn with_policy(seed: u8, max_validity: Option<u64>) -> Ident {
        Ident::incept(seed, max_validity, None)
    }

    /// An identity that publishes records with max-age `max_age` (§18.5).
    pub fn publishing(seed: u8, max_age: u64) -> Ident {
        Ident::incept(
            seed,
            None,
            Publish::new(max_age, vec!["https://example.org/r".into()]),
        )
    }

    pub(crate) fn incept(seed: u8, max_validity: Option<u64>, publish: Option<Publish>) -> Ident {
        let k0 = FakeRoot::new(seed.wrapping_mul(16));
        let k1 = FakeRoot::new(seed.wrapping_mul(16) + 1);
        let (id, ev) = incept(
            Authority::single(k0.0),
            &Authority::single(k1.0),
            max_validity,
            publish,
            &[&k0],
            &mut TestRng::new(0),
        )
        .unwrap();
        Ident {
            id,
            keys: vec![k0],
            next: vec![k1],
            events: vec![ev],
            seed,
        }
    }

    pub fn log(&self) -> Log {
        let rest: Vec<&Signed<Event>> = self.events[1..].iter().collect();
        Log::build(&self.events[0], |n| {
            rest.iter().copied().filter(|e| e.body.n() == n).collect()
        })
        .unwrap()
    }

    /// The current key at `event`, whether or not the log has reached it yet.
    pub fn key(&self, event: u64) -> FakeRoot {
        match event {
            0 => FakeRoot::new(self.seed.wrapping_mul(16)),
            n => FakeRoot::new(self.seed.wrapping_mul(16) + 2 * n as u8),
        }
    }

    pub fn head(&self) -> u64 {
        self.events.len() as u64 - 1
    }

    pub fn rotate(&mut self, keep: Vec<Hash>, max_validity: Option<u64>) -> Signed<Event> {
        let n = self.keys.len() as u8;
        let revealed = self.next[self.next.len() - 1];
        let current = FakeRoot::new(self.seed.wrapping_mul(16) + 2 * n);
        let next = FakeRoot::new(self.seed.wrapping_mul(16) + 2 * n + 1);
        let ev = rotate(
            &self.log(),
            RotationPlan {
                revealed: Authority::single(revealed.0),
                authority: Authority::single(current.0),
                next: Authority::single(next.0),
                max_validity,
                publish: self.log().head().publish().cloned(),
                keep,
            },
            &[&revealed],
            &mut TestRng::new(0),
        )
        .unwrap();
        self.keys.push(current);
        self.next.push(next);
        self.events.push(ev.clone());
        ev
    }

    pub fn issuer(&self) -> Issuer {
        Issuer::Identity {
            id: self.id,
            event: self.head(),
        }
    }

    /// A statement under the head event, signed by the head key.
    pub fn say(&self, claim: Claim, issued: Time, expires: Option<Time>) -> Signed<Statement> {
        self.say_as(self.head(), claim, issued, expires)
    }

    /// A statement claiming `event`, signed by that event's key (as a thief
    /// holding an old warm key would).
    pub fn say_as(
        &self,
        event: u64,
        claim: Claim,
        issued: Time,
        expires: Option<Time>,
    ) -> Signed<Statement> {
        let body = Statement {
            issuer: Issuer::Identity { id: self.id, event },
            issued,
            expires,
            note: None,
            claim,
        };
        let key = self.key(event);
        sign_with_authority(
            body,
            &Authority::single(key.0),
            &[&key],
            &mut TestRng::new(0),
        )
        .unwrap()
    }

    pub fn items(&self) -> Vec<Item> {
        self.events.iter().cloned().map(Item::Event).collect()
    }

    /// A record under the head, signed by the head's key (§18.4).
    pub fn record(&self, revoked: Vec<Hash>, issued: Time) -> Signed<Record> {
        sign_record(
            &self.log(),
            revoked,
            issued,
            &[&self.key(self.head())],
            &mut TestRng::new(0),
        )
        .unwrap()
    }
}

pub(crate) fn tag(s: &str) -> Tag {
    Tag::parse(s).unwrap()
}

pub(crate) fn grant(subject: Subject, t: &str, delegate: bool) -> Claim {
    grant_tags(subject, &[t], delegate)
}

/// A grant with several tags; any tag another one covers is left out, so
/// generated combinations are always well formed.
pub(crate) fn grant_tags(subject: Subject, ts: &[&str], delegate: bool) -> Claim {
    let mut kept: Vec<Tag> = Vec::new();
    for t in ts.iter().map(|t| tag(t)) {
        if !kept.iter().any(|k| t.is_within(k) || k.is_within(&t)) {
            kept.push(t);
        }
    }
    Claim::Grant {
        subject,
        tags: Tags::new(kept).unwrap(),
        delegate,
    }
}

pub(crate) fn name(n: &str, subject: Subject) -> Claim {
    Claim::Name {
        name: n.as_bytes().to_vec(),
        subject,
    }
}

pub(crate) fn path(base: Id, names: &[&str]) -> Subject {
    Subject::Name(NamePath {
        base,
        names: names.iter().map(|n| n.as_bytes().to_vec()).collect(),
    })
}

fn st(s: Signed<Statement>) -> Item {
    Item::Statement(s)
}

struct World {
    material: Material,
    roots: Vec<Id>,
    policy: Policy,
}

impl World {
    fn new(root: &Ident, items: impl IntoIterator<Item = Item>) -> World {
        let mut material = Material::new();
        for i in root.items().into_iter().chain(items) {
            material.add(i);
        }
        World {
            material,
            roots: vec![root.id],
            policy: Policy {
                skew: 5,
                ..Policy::default()
            },
        }
    }

    fn check(&self, h: Holder, t: &str, now: Time) -> Result<Proof, Denial> {
        Verifier::new(&self.roots, &self.material, &self.policy).check(&h, &tag(t), now)
    }
}

fn rejected_for(d: &Denial, h: Hash) -> Option<Reason> {
    match d {
        Denial::NotFound { rejected } => rejected
            .iter()
            .find(|r| r.statement == h)
            .map(|r| r.reason.clone()),
        _ => None,
    }
}

#[test]
fn direct_grant_and_tags() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "(zuko home)", false), 10, None);
    let w = World::new(&a, [st(g.clone())]);
    let proof = w.check(Holder::Id(b.id), "(zuko home relay)", 50).unwrap();
    assert_eq!(proof.steps.len(), 1);
    assert_eq!(proof.statements(), vec![g.body.hash()]);
    assert_eq!(proof.tag, tag("(zuko home)"));
    assert!(w.check(Holder::Id(b.id), "(zuko)", 50).is_err());
    assert!(w.check(Holder::Id(b.id), "(zuko homework)", 50).is_err());
    // The root holds everything.
    assert!(w.check(Holder::Id(a.id), "()", 50).is_ok());
}

#[test]
fn delegation_and_narrowing() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let c = Ident::new(3);
    let ab = a.say(grant(Subject::Id(b.id), "(zuko home)", true), 10, None);
    let bc = b.say(grant(Subject::Id(c.id), "(zuko)", false), 10, None);
    let w = World::new(
        &a,
        [st(ab.clone()), st(bc.clone())]
            .into_iter()
            .chain(b.items()),
    );
    let proof = w.check(Holder::Id(c.id), "(zuko home x)", 50).unwrap();
    assert_eq!(proof.tag, tag("(zuko home)"), "clamped, not rejected");
    assert_eq!(proof.steps.len(), 2);
    assert!(w.check(Holder::Id(c.id), "(zuko other)", 50).is_err());

    // Without delegate, B can't pass anything on.
    let ab2 = a.say(grant(Subject::Id(b.id), "(zuko home)", false), 11, None);
    let w = World::new(&a, [st(ab2), st(bc)].into_iter().chain(b.items()));
    assert!(w.check(Holder::Id(c.id), "(zuko home)", 50).is_err());
}

#[test]
fn names_and_compound_names() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let leaf = FakeLeaf::new(9);
    let alice = a.say(name("alice", Subject::Id(b.id)), 10, None);
    let devices = b.say(
        name("devices", Subject::Leaf(leaf.0.clone())),
        10,
        Some(1000),
    );
    let g = a.say(
        grant(path(a.id, &["alice", "devices"]), "(ssh)", false),
        10,
        None,
    );
    let w = World::new(
        &a,
        [st(alice.clone()), st(devices.clone()), st(g.clone())]
            .into_iter()
            .chain(b.items()),
    );
    let proof = w
        .check(Holder::Leaf(leaf.0.clone()), "(ssh nas)", 50)
        .unwrap();
    assert_eq!(
        proof.statements(),
        vec![alice.body.hash(), devices.body.hash(), g.body.hash()]
    );
    assert!(proof.ids.contains(&b.id));

    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let members = v
        .resolve(
            &NamePath {
                base: a.id,
                names: vec![b"alice".to_vec()],
            },
            50,
        )
        .unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, Holder::Id(b.id));
}

#[test]
fn name_cycles_terminate() {
    let a = Ident::new(1);
    let x = a.say(name("x", path(a.id, &["y"])), 10, None);
    let y = a.say(name("y", path(a.id, &["x"])), 10, None);
    let g = a.say(grant(path(a.id, &["x"]), "()", false), 10, None);
    let w = World::new(&a, [st(x), st(y), st(g)]);
    assert!(w.check(Holder::Id(Ident::new(2).id), "()", 50).is_err());
}

#[test]
fn expiry_and_issued_in_future() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "()", false), 10, Some(100));
    let w = World::new(&a, [st(g.clone())]);
    assert!(w.check(Holder::Id(b.id), "()", 99).is_ok());
    let d = w.check(Holder::Id(b.id), "()", 100).unwrap_err();
    assert_eq!(rejected_for(&d, g.body.hash()), Some(Reason::Expired(100)));
    // issued ≤ now + skew.
    let f = a.say(grant(Subject::Id(b.id), "()", false), 200, None);
    let w = World::new(&a, [st(f.clone())]);
    assert!(w.check(Holder::Id(b.id), "()", 195).is_ok());
    let d = w.check(Holder::Id(b.id), "()", 194).unwrap_err();
    assert_eq!(
        rejected_for(&d, f.body.hash()),
        Some(Reason::NotYetValid(200))
    );
}

#[test]
fn revocation() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "()", false), 10, None);
    let r = a.say(
        Claim::Revoke {
            target: g.body.hash(),
        },
        20,
        None,
    );
    let w = World::new(&a, [st(g.clone()), st(r.clone())]);
    let d = w.check(Holder::Id(b.id), "()", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, g.body.hash()),
        Some(Reason::Revoked(r.body.hash()))
    );
    // Only the issuer can revoke.
    let r2 = b.say(
        Claim::Revoke {
            target: g.body.hash(),
        },
        20,
        None,
    );
    let w = World::new(&a, [st(g.clone()), st(r2)].into_iter().chain(b.items()));
    assert!(w.check(Holder::Id(b.id), "()", 50).is_ok());
    // A revocation "from the future" counts all the same: rule 4 does not
    // apply to revocations, so a clock set back cannot un-revoke.
    let w = World::new(&a, [st(g), st(r)]);
    assert!(w.check(Holder::Id(b.id), "()", 10).is_err());
}

#[test]
fn rotation_keep_and_thief() {
    let mut a = Ident::new(1);
    let b = Ident::new(2);
    let kept = a.say(grant(Subject::Id(b.id), "(kept)", false), 10, None);
    let dropped = a.say(grant(Subject::Id(b.id), "(dropped)", false), 10, None);
    let warm_revocation = a.say(
        Claim::Revoke {
            target: kept.body.hash(),
        },
        11,
        None,
    );
    a.rotate(vec![kept.body.hash()], None);
    let fresh = a.say(grant(Subject::Id(b.id), "(fresh)", false), 20, None);
    // The thief has the event-0 key and signs after the rotation.
    let thief = a.say_as(0, grant(Subject::Id(b.id), "(thief)", false), 30, None);
    // The thief also tries to claim event 1 with the old key.
    let mut forged = a.say_as(0, grant(Subject::Id(b.id), "(forged)", false), 30, None);
    forged.body.issuer = Issuer::Identity { id: a.id, event: 1 };
    let w = World::new(
        &a,
        [
            kept,
            dropped.clone(),
            warm_revocation,
            fresh,
            thief.clone(),
            forged.clone(),
        ]
        .into_iter()
        .map(st),
    );
    assert!(
        w.check(Holder::Id(b.id), "(kept)", 50).is_ok(),
        "the warm revocation is dropped too"
    );
    assert!(w.check(Holder::Id(b.id), "(fresh)", 50).is_ok());
    let d = w.check(Holder::Id(b.id), "(dropped)", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, dropped.body.hash()),
        Some(Reason::NotKept { event: 0, head: 1 })
    );
    let d = w.check(Holder::Id(b.id), "(thief)", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, thief.body.hash()),
        Some(Reason::NotKept { event: 0, head: 1 })
    );
    let d = w.check(Holder::Id(b.id), "(forged)", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, forged.body.hash()),
        Some(Reason::BadSignature)
    );
}

#[test]
fn statements_from_the_future_event_are_unknown() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let mut g = a.say(grant(Subject::Id(b.id), "()", false), 10, None);
    g.body.issuer = Issuer::Identity { id: a.id, event: 3 };
    let w = World::new(&a, [st(g.clone())]);
    let d = w.check(Holder::Id(b.id), "()", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, g.body.hash()),
        Some(Reason::UnknownEvent { event: 3, head: 0 })
    );
}

/// A record made before a rotation says nothing after it (SPEC §5.6), and
/// the reason says so, as distinct from a record claiming an event the log
/// never reached.
#[test]
fn records_under_an_older_event_are_outdated() {
    let mut a = Ident::publishing(1, 3600);
    let old = a.record(vec![], 10);
    a.rotate(vec![], None);
    let mut future = a.record(vec![], 20);
    future.body.event = 5;
    let w = World::new(
        &a,
        [Item::Record(old.clone()), Item::Record(future.clone())],
    );
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(
        v.record_status(&old.body.hash(), 50),
        Err(Reason::OutdatedRecord { event: 0, head: 1 })
    );
    assert_eq!(
        v.record_status(&future.body.hash(), 50),
        Err(Reason::UnknownEvent { event: 5, head: 1 })
    );
}

#[test]
fn max_validity() {
    let a = Ident::with_policy(1, Some(50));
    let b = Ident::new(2);
    let forever = a.say_as(0, grant(Subject::Id(b.id), "(a)", false), 10, None);
    let long = a.say_as(0, grant(Subject::Id(b.id), "(b)", false), 10, Some(61));
    let ok = a.say(grant(Subject::Id(b.id), "(c)", false), 10, Some(60));
    let w = World::new(&a, [st(forever.clone()), st(long), st(ok)]);
    let d = w.check(Holder::Id(b.id), "(a)", 20).unwrap_err();
    assert_eq!(
        rejected_for(&d, forever.body.hash()),
        Some(Reason::MaxValidity(50))
    );
    assert!(w.check(Holder::Id(b.id), "(b)", 20).is_err());
    assert!(w.check(Holder::Id(b.id), "(c)", 20).is_ok());
    // Issuing refuses too.
    let body = Statement {
        issuer: a.issuer(),
        issued: 10,
        expires: None,
        note: None,
        claim: grant(Subject::Id(b.id), "()", false),
    };
    assert_eq!(
        issue(body, &a.log(), &[&a.keys[0]], &mut TestRng::new(0)),
        Err(IssueError::MaxValidity(50))
    );
}

#[test]
fn leaf_keys() {
    let a = Ident::new(1);
    let leaf = FakeLeaf::new(7);
    let app = OpaqueKey {
        kind: b"ssh-ed25519".to_vec(),
        bytes: vec![1, 2, 3],
    };
    let al = a.say(
        grant(Subject::Leaf(leaf.0.clone()), "(svc)", true),
        10,
        Some(10 + 3600),
    );
    let body = Statement {
        issuer: Issuer::Leaf(leaf.0.id()),
        issued: 20,
        expires: Some(20 + 7200),
        note: None,
        claim: grant(Subject::Opaque(app.clone()), "(svc read)", false),
    };
    // What a leaf issues lives at most the ceiling too: otherwise a grant
    // by a stolen leaf key would stay valid for as long as the same key
    // kept being renewed, with no way to revoke it.
    for expires in [None, Some(20 + 86_401)] {
        let long = Statement {
            expires,
            ..body.clone()
        };
        assert!(matches!(
            issue_leaf(long.clone(), &leaf, &mut TestRng::new(0)),
            Err(IssueError::Rule(_))
        ));
        let bytes = leaf.sign(&long.message(), &mut TestRng::new(0)).unwrap();
        let raw = Signed {
            body: long,
            sigs: vec![Sig { index: 0, bytes }],
        };
        let w = World::new(&a, [st(al.clone()), st(raw.clone())]);
        let d = w
            .check(Holder::Opaque(app.clone()), "(svc read)", 30)
            .unwrap_err();
        assert!(matches!(
            rejected_for(&d, raw.body.hash()),
            Some(Reason::Malformed(_))
        ));
    }
    let lk = issue_leaf(body, &leaf, &mut TestRng::new(0)).unwrap();
    let w = World::new(&a, [st(al.clone()), st(lk)]);
    let proof = w
        .check(Holder::Opaque(app.clone()), "(svc read)", 30)
        .unwrap();
    assert_eq!(proof.expires, Some(3610), "the leaf grant bounds the chain");
    assert!(w.check(Holder::Opaque(app.clone()), "(svc)", 30).is_err());
    assert!(w.check(Holder::Opaque(app), "(svc read)", 3610).is_err());

    // Leaf grants must expire within the ceiling.
    let body = Statement {
        issuer: a.issuer(),
        issued: 10,
        expires: None,
        note: None,
        claim: grant(Subject::Leaf(leaf.0.clone()), "()", false),
    };
    assert!(matches!(
        issue(body.clone(), &a.log(), &[&a.keys[0]], &mut TestRng::new(0)),
        Err(IssueError::Rule(_))
    ));
    let long = Statement {
        expires: Some(10 + 86_401),
        ..body.clone()
    };
    assert!(issue(long, &a.log(), &[&a.keys[0]], &mut TestRng::new(0)).is_err());
    // So must names of leaf keys, or a grant to the name would outlive the
    // ceiling (and survive rotation).
    let leaf_name = Statement {
        claim: name("svc", Subject::Leaf(leaf.0.clone())),
        ..body.clone()
    };
    assert!(matches!(
        issue(leaf_name, &a.log(), &[&a.keys[0]], &mut TestRng::new(0)),
        Err(IssueError::Rule(_))
    ));
    let via = a.say(grant(path(a.id, &["svc"]), "(svc)", false), 10, None);
    let forever = a.say(name("svc", Subject::Leaf(leaf.0.clone())), 10, None);
    let w = World::new(&a, [st(forever), st(via.clone())]);
    assert!(w.check(Holder::Leaf(leaf.0.clone()), "(svc)", 20).is_err());
    let day = a.say(name("svc", Subject::Leaf(leaf.0.clone())), 10, Some(1000));
    let w = World::new(&a, [st(day), st(via)]);
    let proof = w.check(Holder::Leaf(leaf.0.clone()), "(svc)", 20).unwrap();
    assert_eq!(proof.expires, Some(1000));
    assert!(
        w.check(Holder::Leaf(leaf.0.clone()), "(svc)", 1000)
            .is_err()
    );
    // The verifier may lower the ceiling.
    let mut w = World::new(&a, [st(al.clone())]);
    w.policy.leaf_ceiling = 1800;
    let d = w
        .check(Holder::Leaf(leaf.0.clone()), "(svc)", 20)
        .unwrap_err();
    assert_eq!(
        rejected_for(&d, al.body.hash()),
        Some(Reason::LeafCeiling(1800))
    );
    // Leaves can't name, revoke, or delegate.
    for claim in [
        name("x", Subject::Id(a.id)),
        Claim::Revoke {
            target: Hash([0; 32]),
        },
        grant(Subject::Id(a.id), "()", true),
    ] {
        let body = Statement {
            issuer: Issuer::Leaf(leaf.0.id()),
            issued: 20,
            expires: None,
            note: None,
            claim,
        };
        assert!(issue_leaf(body, &leaf, &mut TestRng::new(0)).is_err());
    }
    // Opaque keys can't delegate.
    let body = Statement {
        issuer: a.issuer(),
        issued: 10,
        expires: None,
        note: None,
        claim: grant(
            Subject::Opaque(OpaqueKey {
                kind: b"x".to_vec(),
                bytes: vec![1],
            }),
            "()",
            true,
        ),
    };
    assert!(issue(body, &a.log(), &[&a.keys[0]], &mut TestRng::new(0)).is_err());
}

#[test]
fn data_signatures() {
    let mut a = Ident::new(1);
    let b = Ident::new(2);
    let leaf = FakeLeaf::new(5);
    let al = a.say(
        grant(Subject::Leaf(leaf.0.clone()), "(release)", false),
        10,
        Some(1000),
    );
    let data = Hash::of_data(b"hello");
    let sig = sign_data_leaf(data, b"app/v1", 20, &leaf, &mut TestRng::new(0)).unwrap();
    let w = World::new(&a, [st(al.clone())]);
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let proof = v
        .verify(&sig, &data, b"app/v1", &tag("(release)"), 30)
        .unwrap();
    assert_eq!(proof.signature, Some(sig.body.hash()));
    assert_eq!(
        v.verify(&sig, &data, b"app/v2", &tag("(release)"), 30),
        Err(Denial::Context)
    );
    assert_eq!(
        v.verify(&sig, &Hash::of_data(b"x"), b"app/v1", &tag("(release)"), 30),
        Err(Denial::Data)
    );
    let mut bad = sig.clone();
    bad.sigs[0].bytes[0] ^= 1;
    assert_eq!(
        v.verify(&bad, &data, b"app/v1", &tag("(release)"), 30),
        Err(Denial::Signature(Reason::BadSignature))
    );
    // The signature names its leaf by id; the key comes with the grant.
    assert_eq!(sig.body.signer, Issuer::Leaf(leaf.0.id()));
    let w = World::new(&a, [Item::Signature(sig.clone())]);
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(
        v.signature_status(&sig.body.hash(), 30),
        Err(Reason::UnknownLeaf(leaf.0.id()))
    );
    assert_eq!(
        v.verify(&sig, &data, b"app/v1", &tag("(release)"), 30),
        Err(Denial::Signature(Reason::UnknownLeaf(leaf.0.id())))
    );
    // A key item supplies it too.
    let w = World::new(
        &a,
        [
            Item::Signature(sig.clone()),
            Item::PublicKey(PublicKey::Leaf(leaf.0.clone())),
        ],
    );
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(v.signature_status(&sig.body.hash(), 30), Ok(()));
    // The same check, for signatures in the material (what `rotate` keeps).
    let mut forged = sig.clone();
    forged.body.data = Hash::of_data(b"evil");
    let w = World::new(
        &a,
        [
            st(al),
            Item::Signature(sig.clone()),
            Item::Signature(forged.clone()),
        ],
    );
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(v.signature_status(&sig.body.hash(), 30), Ok(()));
    assert_eq!(
        v.signature_status(&forged.body.hash(), 30),
        Err(Reason::BadSignature)
    );

    // Identity signatures: valid while current, then only if kept.
    let ab = a.say(grant(Subject::Id(b.id), "(release)", false), 10, None);
    let by_b = sign_data(
        data,
        b"app/v1",
        20,
        &b.log(),
        &[&b.keys[0]],
        &mut TestRng::new(0),
    )
    .unwrap();
    let by_a0 = sign_data(
        data,
        b"app/v1",
        20,
        &a.log(),
        &[&a.keys[0]],
        &mut TestRng::new(0),
    )
    .unwrap();
    let by_a0_too = sign_data(
        data,
        b"app/v1",
        21,
        &a.log(),
        &[&a.keys[0]],
        &mut TestRng::new(0),
    )
    .unwrap();
    a.rotate(vec![by_a0.body.hash(), ab.body.hash()], None);
    let w = World::new(&a, [st(ab)].into_iter().chain(b.items()));
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert!(
        v.verify(&by_b, &data, b"app/v1", &tag("(release)"), 30)
            .is_ok()
    );
    assert!(
        v.verify(&by_a0, &data, b"app/v1", &tag("(release)"), 30)
            .is_ok()
    );
    assert_eq!(
        v.verify(&by_a0_too, &data, b"app/v1", &tag("(release)"), 30),
        Err(Denial::Signature(Reason::NotKept { event: 0, head: 1 }))
    );
    // Revoking a signature.
    let r = b.say(
        Claim::Revoke {
            target: by_b.body.hash(),
        },
        25,
        None,
    );
    let mut w = World::new(
        &a,
        [st(a.say(
            grant(Subject::Id(b.id), "(release)", false),
            10,
            None,
        ))],
    );
    for i in b.items().into_iter().chain([st(r.clone())]) {
        w.material.add(i);
    }
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(
        v.verify(&by_b, &data, b"app/v1", &tag("(release)"), 30),
        Err(Denial::Signature(Reason::Revoked(r.body.hash())))
    );
}

#[test]
fn equivocation_is_detected_and_fails_closed() {
    let a = Ident::new(1);
    let mut b = Ident::new(2);
    let c = Ident::new(3);
    let ab = a.say(grant(Subject::Id(b.id), "()", true), 10, None);
    let bc = b.say(grant(Subject::Id(c.id), "()", false), 10, None);
    let ac = a.say(grant(Subject::Id(c.id), "(direct)", false), 10, None);
    let r1 = b.rotate(vec![bc.body.hash()], None);
    // The same next key signs a different rotation 1.
    let mut b2 = Ident::new(2);
    let r1b = b2.rotate(vec![], Some(99));
    assert_ne!(r1.body.hash(), r1b.body.hash());
    let w = World::new(
        &a,
        [st(ab), st(bc), st(ac), Item::Event(r1b.clone())]
            .into_iter()
            .chain(b.items()),
    );
    let d = w.check(Holder::Id(c.id), "(x)", 50).unwrap_err();
    let Denial::Compromised(ev) = &d else {
        panic!("{d:?}")
    };
    assert_eq!(ev.id(), b.id);
    assert_eq!(ev.n(), 1);
    assert!(ev.verify());
    assert_eq!(w.material.evidence().len(), 1);
    // The evidence travels on its own.
    let m = Material::from_items(ev.items());
    assert!(matches!(&*m.log(&b.id), Err(LogError::Equivocation(_))));
    // Queries about B itself fail; chains avoiding B still work.
    assert!(matches!(
        w.check(Holder::Id(b.id), "()", 50),
        Err(Denial::Compromised(_))
    ));
    assert!(w.check(Holder::Id(c.id), "(direct)", 50).is_ok());
    assert!(crate::equivocation(&r1, &r1b));
    assert!(!crate::equivocation(&r1, &r1));
}

/// A name's members exclude an equivocating identity (SPEC §10), and the
/// evidence is reported when nothing else remains.
#[test]
fn resolve_excludes_an_equivocating_member() {
    let a = Ident::new(1);
    let mut b = Ident::new(2);
    let c = Ident::new(3);
    let r1 = b.rotate(vec![], None);
    let mut b2 = Ident::new(2);
    let r1b = b2.rotate(vec![], Some(99));
    assert_ne!(r1.body.hash(), r1b.body.hash());
    let to_b = a.say(name("friend", Subject::Id(b.id)), 10, None);
    let to_c = a.say(name("friend", Subject::Id(c.id)), 10, None);
    let items = [st(to_b), st(to_c), Item::Event(r1b)]
        .into_iter()
        .chain(b.items())
        .collect::<Vec<_>>();
    let w = World::new(&a, items.clone());
    let friend = NamePath {
        base: a.id,
        names: vec![b"friend".to_vec()],
    };
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let members = v.resolve(&friend, 50).unwrap();
    assert_eq!(
        members.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>(),
        vec![Holder::Id(c.id)]
    );
    // With B the only member, the answer is the evidence.
    let only_b = items
        .into_iter()
        .filter(|i| !matches!(i, Item::Statement(s) if s.body.claim.subject() == Some(&Subject::Id(c.id))))
        .collect::<Vec<_>>();
    let w = World::new(&a, only_b);
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert!(matches!(
        v.resolve(&friend, 50),
        Err(Denial::Compromised(e)) if e.id() == b.id
    ));
}

#[test]
fn broken_and_garbage_rotations() {
    let a = Ident::new(1);
    let mut b = Ident::new(2);
    let r1 = b.rotate(vec![], None);
    // Signed by the committed key, wrong prev: the log is broken (fail closed).
    let Event::Rotation(mut bad) = r1.body.clone() else {
        panic!()
    };
    bad.prev = Hash([9; 32]);
    let key = b.next[0];
    let bad = sign_with_authority(
        Event::Rotation(bad),
        &Authority::single(key.0),
        &[&key],
        &mut TestRng::new(0),
    )
    .unwrap();
    let m = Material::from_items([Item::Event(b.events[0].clone()), Item::Event(bad)]);
    assert_eq!(
        m.log(&b.id).as_ref().as_ref().err(),
        Some(&LogError::Broken { n: 1 })
    );
    // Anyone can make a rotation with some other authority: ignored.
    let Event::Rotation(mut garbage) = r1.body.clone() else {
        panic!()
    };
    let mallory = FakeRoot::new(200);
    garbage.revealed = Authority::single(mallory.0);
    let garbage = sign_with_authority(
        Event::Rotation(garbage),
        &Authority::single(mallory.0),
        &[&mallory],
        &mut TestRng::new(0),
    )
    .unwrap();
    let m = Material::from_items([
        Item::Event(b.events[0].clone()),
        Item::Event(garbage.clone()),
    ]);
    assert_eq!(m.log(&b.id).as_ref().as_ref().map(Log::head_n), Ok(0));
    let m = Material::from_items(b.items().into_iter().chain([Item::Event(garbage)]));
    assert_eq!(m.log(&b.id).as_ref().as_ref().map(Log::head_n), Ok(1));
    // Rotation with a bad signature is ignored.
    let mut unsigned = r1.clone();
    unsigned.sigs[0].bytes[5] ^= 1;
    let m = Material::from_items([Item::Event(b.events[0].clone()), Item::Event(unsigned)]);
    assert_eq!(m.log(&b.id).as_ref().as_ref().map(Log::head_n), Ok(0));
    let _ = a;
}

#[test]
fn k_of_n() {
    let keys: Vec<FakeRoot> = (0..3).map(|i| FakeRoot::new(100 + i)).collect();
    let authority = Authority::new(2, keys.iter().map(|k| k.0).collect()).unwrap();
    let next = Authority::single(FakeRoot::new(110).0);
    let mut rng = TestRng::new(0);
    assert_eq!(
        incept(authority.clone(), &next, None, None, &[&keys[0]], &mut rng).map(|_| ()),
        Err(IssueError::BelowThreshold { k: 2, have: 1 })
    );
    // Signing twice with one key doesn't count twice.
    assert!(
        incept(
            authority.clone(),
            &next,
            None,
            None,
            &[&keys[0], &keys[0]],
            &mut rng
        )
        .is_err()
    );
    let (id, ev) = incept(
        authority.clone(),
        &next,
        None,
        None,
        &[&keys[0], &keys[2]],
        &mut rng,
    )
    .unwrap();
    let m = Material::from_items([Item::Event(ev.clone())]);
    let log = m.log(&id);
    let log = log.as_ref().as_ref().unwrap();
    let b = Ident::new(9);
    let body = Statement {
        issuer: Issuer::Identity { id, event: 0 },
        issued: 1,
        expires: None,
        note: None,
        claim: grant(Subject::Id(b.id), "()", false),
    };
    let one = sign_with_authority(
        body.clone(),
        &Authority::single(keys[1].0),
        &[&keys[1]],
        &mut rng,
    )
    .unwrap();
    let mut one = one;
    one.sigs[0].index = 1;
    let two = issue(body, log, &[&keys[1], &keys[2]], &mut rng).unwrap();
    let mut m = Material::from_items([Item::Event(ev), Item::Statement(one.clone())]);
    let roots = [id];
    let policy = Policy::default();
    let v = Verifier::new(&roots, &m, &policy);
    assert_eq!(
        v.statement_status(&one.body.hash(), 5),
        Err(Reason::BadSignature)
    );
    m.add(Item::Statement(two.clone()));
    let v = Verifier::new(&roots, &m, &policy);
    assert_eq!(v.statement_status(&two.body.hash(), 5), Ok(()));
    // Duplicates and bad authorities.
    assert_eq!(
        Authority::new(1, vec![keys[0].0, keys[0].0]),
        Err(crate::model::AuthorityError::Duplicate)
    );
    assert_eq!(
        Authority::new(4, keys.iter().map(|k| k.0).collect()),
        Err(crate::model::AuthorityError::Threshold)
    );
}

#[test]
fn proofs_are_self_contained() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let c = Ident::new(3);
    let unrelated = Ident::new(4);
    let alice = a.say(name("alice", Subject::Id(b.id)), 10, None);
    let ab = a.say(grant(path(a.id, &["alice"]), "(x)", true), 10, None);
    let bc = b.say(grant(Subject::Id(c.id), "(x y)", false), 10, Some(500));
    let noise = a.say(grant(Subject::Id(unrelated.id), "(x)", false), 10, None);
    let w = World::new(
        &a,
        [st(alice), st(ab), st(bc), st(noise.clone())]
            .into_iter()
            .chain(b.items())
            .chain(unrelated.items()),
    );
    let proof = w.check(Holder::Id(c.id), "(x y z)", 50).unwrap();
    assert_eq!(proof.expires, Some(500));
    let items = proof.items(&w.material);
    assert!(!items.contains(&st(noise)), "minimal disclosure");
    let m = Material::from_items(items);
    let v = Verifier::new(&w.roots, &m, &w.policy);
    assert_eq!(v.check(&Holder::Id(c.id), &tag("(x y z)"), 50), Ok(proof));
}

#[test]
fn chain_length_limit() {
    let idents: Vec<Ident> = (1..=6).map(Ident::new).collect();
    let mut items = Vec::new();
    for pair in idents.windows(2) {
        items.push(st(pair[0].say(
            grant(Subject::Id(pair[1].id), "()", true),
            10,
            None,
        )));
        items.extend(pair[1].items());
    }
    let mut w = World::new(&idents[0], items);
    let last = Holder::Id(idents[5].id);
    assert_eq!(w.check(last.clone(), "()", 50).unwrap().steps.len(), 5);
    w.policy.max_chain = 4;
    assert!(w.check(last.clone(), "()", 50).is_err());
    w.policy.max_chain = 16;
    w.policy.max_statements = 2;
    assert_eq!(
        w.check(last, "()", 50),
        Err(Denial::Limit("statements examined"))
    );
}

#[test]
fn time_witness() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let w = World::new(
        &a,
        [
            st(a.say(grant(Subject::Id(b.id), "()", false), 10, Some(20))),
            st(a.say(name("x", Subject::Id(b.id)), 70, None)),
            st(b.say(name("y", Subject::Id(a.id)), 900, None)),
        ]
        .into_iter()
        .chain(b.items()),
    );
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(v.time_witness(), Some(70));
}

/// Junk claiming to be from a root must not stop the floor from rising: the
/// witness is not bounded by `max_signatures`, and the newest candidate is
/// tried first.
#[test]
fn time_witness_is_not_starved_by_junk() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let real = a.say(name("x", Subject::Id(b.id)), 70, None);
    // Junk newer than the real statement, so it is tried first.
    let mut items: Vec<Item> = (0..30u8)
        .map(|i| {
            let mut junk = a.say(name("j", Subject::Id(b.id)), 100 + u64::from(i), None);
            junk.sigs = vec![Sig {
                index: 0,
                bytes: vec![i; crate::keys::ROOT_SIGNATURE_SIZE],
            }];
            st(junk)
        })
        .collect();
    items.push(st(real));
    let mut w = World::new(&a, items);
    w.policy.max_signatures = 10;
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(v.time_witness(), Some(70));
}

/// Junk signatures merged onto one copy of the newest statement must not
/// push it over the signature budget and out of the witness search either
/// (the permissive direction, SPEC §12).
#[test]
fn time_witness_is_not_starved_by_merged_junk() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let older = a.say(name("x", Subject::Id(b.id)), 10, None);
    let newest = a.say(name("y", Subject::Id(b.id)), 70, None);
    let newest_hash = newest.body.hash();
    let mut items = vec![st(older)];
    // The genuine copy, buried under 30 copies with different junk
    // signatures; Material merges them all onto one body.
    for i in 0..30u8 {
        let mut junk = newest.clone();
        junk.sigs = vec![Sig {
            index: 0,
            bytes: vec![i; crate::keys::ROOT_SIGNATURE_SIZE],
        }];
        items.push(st(junk));
    }
    items.push(st(newest));
    let mut w = World::new(&a, items);
    w.policy.max_signatures = 10;
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    // A query is budgeted: that statement is undecided, and nothing is
    // cached for it.
    assert_eq!(v.statement_status(&newest_hash, 100), Err(Reason::Limit));
    // The witness is not.
    assert_eq!(v.time_witness(), Some(70));
}

/// A clock set back (below a revocation's `issued`, above the floor) must
/// not bring back what was revoked: rule 4 does not apply to revocations or
/// to the revoking effect of records (SPEC §7, §5.6).
#[test]
fn a_clock_set_back_does_not_unrevoke() {
    let me = Ident::new(1);
    let alice = Ident::new(2);
    let bob = Ident::new(3);
    let to_alice = me.say(grant(Subject::Id(alice.id), "()", true), 10, None);
    let to_bob = alice.say(grant(Subject::Id(bob.id), "(x)", false), 20, None);
    let revoke = alice.say(
        Claim::Revoke {
            target: to_bob.body.hash(),
        },
        100,
        None,
    );
    let mut items = vec![st(to_alice.clone()), st(to_bob.clone()), st(revoke)];
    items.extend(alice.items());
    let w = World::new(&me, items);
    assert!(w.check(Holder::Id(bob.id), "(x)", 200).is_err());
    // At 50 the revocation is "from the future", and still counts.
    assert!(w.check(Holder::Id(bob.id), "(x)", 50).is_err());
    // The same through a record.
    let pub_alice = Ident::publishing(4, 3600);
    let to_pub = me.say(grant(Subject::Id(pub_alice.id), "()", true), 10, None);
    let to_bob = pub_alice.say(grant(Subject::Id(bob.id), "(x)", false), 20, Some(1000));
    let record = pub_alice.record(vec![to_bob.body.hash()], 100);
    let mut items = vec![st(to_pub), st(to_bob), Item::Record(record)];
    items.extend(pub_alice.items());
    let w = World::new(&me, items);
    assert!(w.check(Holder::Id(bob.id), "(x)", 50).is_err());
    // But a record from the future does not make anything fresh.
    let long = pub_alice.say(grant(Subject::Id(bob.id), "(y)", false), 20, None);
    let future = pub_alice.record(vec![], 5000);
    let mut items = vec![
        st(me.say(grant(Subject::Id(pub_alice.id), "()", true), 10, None)),
        st(long.clone()),
        Item::Record(future),
    ];
    items.extend(pub_alice.items());
    let w = World::new(&me, items);
    let d = w.check(Holder::Id(bob.id), "(y)", 50).unwrap_err();
    assert!(matches!(
        rejected_for(&d, long.body.hash()),
        Some(Reason::NoFreshRecord { .. })
    ));
    let fresh = pub_alice.record(vec![], 40);
    w_with(&w, Item::Record(fresh), |w| {
        assert!(w.check(Holder::Id(bob.id), "(y)", 50).is_ok());
    });
}

/// `w` plus one more item.
fn w_with(w: &World, item: Item, f: impl FnOnce(&World)) {
    let mut material = Material::new();
    for (_, s) in w.material.statements() {
        material.add(Item::Statement(s.clone()));
    }
    for (_, r) in w.material.records() {
        material.add(Item::Record(r.clone()));
    }
    for id in w.material.ids().copied().collect::<Vec<_>>() {
        if let Ok(log) = &*w.material.log(&id) {
            for i in log.items() {
                material.add(i);
            }
        }
    }
    material.add(item);
    f(&World {
        material,
        roots: w.roots.clone(),
        policy: w.policy.clone(),
    });
}

#[test]
fn missing_root_log() {
    let a = Ident::new(1);
    let roots = [a.id];
    let m = Material::new();
    let policy = Policy::default();
    let v = Verifier::new(&roots, &m, &policy);
    assert_eq!(
        v.check(&Holder::Id(Ident::new(2).id), &tag("()"), 5),
        Err(Denial::Root {
            id: a.id,
            error: LogError::NoInception
        })
    );
}

#[test]
fn encoding_round_trips() {
    let mut a = Ident::with_policy(1, Some(3600));
    let b = Ident::new(2);
    let leaf = FakeLeaf::new(3);
    let mut items = vec![];
    items.push(st(a.say(
        Claim::Name {
            name: b"alice".to_vec(),
            subject: path(b.id, &["x", "y"]),
        },
        10,
        Some(20),
    )));
    let mut g = a.say(
        grant(Subject::Leaf(leaf.0.clone()), "(a \"b c\")", true),
        10,
        Some(20),
    );
    g.body.note = Some("hello ✓".into());
    items.push(st(g.clone()));
    items.push(st(a.say(
        Claim::Revoke {
            target: g.body.hash(),
        },
        11,
        None,
    )));
    items.push(Item::Event(
        a.rotate(vec![g.body.hash(), Hash([1; 32])], None),
    ));
    items.push(Item::Signature(
        sign_data_leaf(Hash([2; 32]), b"ctx", 5, &leaf, &mut TestRng::new(0)).unwrap(),
    ));
    items.push(Item::PublicKey(PublicKey::Leaf(leaf.0.clone())));
    items.push(Item::Authority(Authority::single(a.keys[0].0)));
    items.extend(a.items());
    for item in &items {
        let bytes = item.encode();
        assert_eq!(Item::decode(&bytes).as_ref(), Ok(item), "{}", item.kind());
        let armored = item.armor();
        assert_eq!(
            Item::decode_bundle(armored.as_bytes()),
            Ok(vec![item.clone()])
        );
    }
    let bundle: String = items.iter().map(Item::armor).collect();
    assert_eq!(Item::decode_bundle(bundle.as_bytes()).unwrap(), items);
    let binary: Vec<u8> = items.iter().flat_map(Item::encode).collect();
    assert_eq!(Item::decode_bundle(&binary).unwrap(), items);
    // Binary bundles get the per-item limits, item by item: one item over
    // 2^18 nodes is rejected, even in a bundle well under the bundle limit.
    let wide = [b"(".as_slice(), &b"0:".repeat(1 << 18), b")"].concat();
    assert_eq!(
        Item::decode_bundle(&[binary.as_slice(), &wide].concat()),
        Err(DecodeError::Sexp(writ_sexp::DecodeError::TooLarge))
    );
    // Only the four armor whitespace bytes count as empty.
    assert_eq!(Item::decode_bundle(b" \t\r\n"), Ok(vec![]));
    assert!(Item::decode_bundle(b"\x0c").is_err());
}

#[test]
fn encoding_rejects_non_canonical() {
    use writ_sexp::Sexp;
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "()", false), 10, None);
    let good = Item::Statement(g.clone()).to_sexp();
    let mutate = |f: &dyn Fn(&mut Vec<Sexp>)| {
        let mut s = good.clone();
        if let Sexp::List(items) = &mut s {
            f(items);
        }
        Item::decode(&s.encode())
    };
    // Wrong version.
    assert_eq!(
        mutate(&|v| v[0] = Sexp::atom("writ/v2")),
        Err(DecodeError::Version)
    );
    // Leading zero in a number.
    assert!(
        mutate(&|v| {
            if let Sexp::List(body) = &mut v[1] {
                body[2] = Sexp::list(vec![Sexp::atom("issued"), Sexp::atom("010")]);
            }
        })
        .is_err()
    );
    // Unsigned.
    assert!(mutate(&|v| v.truncate(2)).is_err());
    // Wrong signature length.
    assert!(
        mutate(&|v| {
            v[2] = Sexp::list(vec![
                Sexp::atom("sig"),
                Sexp::atom("0"),
                Sexp::atom([0; 10]),
            ]);
        })
        .is_err()
    );
    // Duplicate signature index.
    assert_eq!(
        mutate(&|v| {
            let s = v[2].clone();
            v.push(s);
        }),
        Err(DecodeError::NonCanonical)
    );
    // Unknown field.
    assert!(
        mutate(&|v| {
            if let Sexp::List(body) = &mut v[1] {
                body.push(Sexp::list(vec![Sexp::atom("extra")]));
            }
        })
        .is_err()
    );
    // Trailing bytes after a valid item.
    let mut bytes = good.encode();
    bytes.push(b'x');
    assert!(Item::decode(&bytes).is_err());
}

/// k identities each naming all k as `a`; a 16-step path through them used
/// to cost k^16 resolutions.
#[test]
fn name_resolution_is_polynomial() {
    let root = Ident::new(1);
    let crowd: Vec<Ident> = (10..18).map(Ident::new).collect();
    let mut items: Vec<Item> = Vec::new();
    for x in &crowd {
        items.extend(x.items());
        for y in &crowd {
            items.push(st(x.say(name("a", Subject::Id(y.id)), 10, None)));
        }
    }
    let long = vec!["a"; 16];
    items.push(st(root.say(
        grant(path(crowd[0].id, &long), "()", false),
        10,
        None,
    )));
    let w = World::new(&root, items);
    let start = std::time::Instant::now();
    let r = w.check(Holder::Id(crowd[3].id), "()", 50);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(r.is_ok(), "{r:?}");
}

/// A copy of an item with a junk signature merged in must not make anything
/// derived from the material non-canonical (or carry the junk).
#[test]
fn junk_signatures_never_travel() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "(x)", false), 10, None);
    let junk = |s: &Sig| Sig {
        index: s.index,
        bytes: vec![0xa5; s.bytes.len()],
    };
    let mut bad_inception = a.events[0].clone();
    bad_inception.sigs = vec![junk(&a.events[0].sigs[0])];
    let mut bad_grant = g.clone();
    bad_grant.sigs = vec![junk(&g.sigs[0])];
    // Junk first, then the real thing.
    let m = Material::from_items([
        Item::Event(bad_inception),
        Item::Statement(bad_grant),
        Item::Event(a.events[0].clone()),
        Item::Statement(g.clone()),
    ]);
    let roots = [a.id];
    let policy = Policy::default();
    let proof = Verifier::new(&roots, &m, &policy)
        .check(&Holder::Id(b.id), &tag("(x)"), 50)
        .unwrap();
    for item in proof.items(&m) {
        let bytes = item.encode();
        assert_eq!(Item::decode(&bytes).as_ref(), Ok(&item));
        match &item {
            Item::Event(e) => assert_eq!(e.sigs, a.events[0].sigs),
            Item::Statement(s) => assert_eq!(s.sigs, g.sigs),
            _ => {}
        }
    }
    let log = m.log(&a.id);
    let log = log.as_ref().as_ref().unwrap();
    assert!(log.items().all(|i| Item::decode(&i.encode()).is_ok()));
}

/// Next keys sign rotations and nothing else; the new current key signs
/// statements. The same next keys can serve for several rotations.
#[test]
fn next_keys_only_rotate() {
    let mut a = Ident::new(1);
    let b = Ident::new(2);
    let recovery = a.next[0];
    a.rotate(vec![], None);
    // The revealed next key is not a current key.
    let body = Statement {
        issuer: a.issuer(),
        issued: 10,
        expires: None,
        note: None,
        claim: grant(Subject::Id(b.id), "()", false),
    };
    assert_eq!(
        issue(body.clone(), &a.log(), &[&recovery], &mut TestRng::new(0)),
        Err(IssueError::NotInAuthority)
    );
    let forged = sign_with_authority(
        body.clone(),
        &Authority::single(recovery.0),
        &[&recovery],
        &mut TestRng::new(0),
    )
    .unwrap();
    let w = World::new(&a, [st(forged.clone())]);
    let d = w.check(Holder::Id(b.id), "()", 50).unwrap_err();
    assert_eq!(
        rejected_for(&d, forged.body.hash()),
        Some(Reason::BadSignature)
    );
    // The new current key works.
    let ok = issue(body, &a.log(), &[&a.keys[1]], &mut TestRng::new(0)).unwrap();
    let w = World::new(&a, [st(ok)]);
    assert!(w.check(Holder::Id(b.id), "()", 50).is_ok());

    // Keep the same next keys across several rotations.
    let mut c = Ident::new(3);
    let recovery = c.next[0];
    let mut log = c.log();
    for n in 1..4u8 {
        let current = FakeRoot::new(150 + n);
        let ev = rotate(
            &log,
            RotationPlan {
                revealed: Authority::single(recovery.0),
                authority: Authority::single(current.0),
                next: Authority::single(recovery.0),
                max_validity: None,
                publish: None,
                keep: vec![],
            },
            &[&recovery],
            &mut TestRng::new(0),
        )
        .unwrap();
        c.events.push(ev);
        log = c.log();
        assert_eq!(log.head_n(), u64::from(n));
    }
}

#[test]
fn thresholds_must_be_a_majority() {
    let keys: Vec<RootKey> = (0..4).map(|i| FakeRoot::new(120 + i).0).collect();
    for (k, n, ok) in [
        (1, 1, true),
        (1, 2, false),
        (2, 2, true),
        (2, 3, true),
        (2, 4, false),
        (3, 4, true),
    ] {
        let got = Authority::new(k, keys[..n].to_vec());
        assert_eq!(got.is_ok(), ok, "{k} of {n}");
        if !ok {
            assert_eq!(got, Err(crate::model::AuthorityError::Quorum));
        }
    }
    // Decoding enforces it too.
    let weak = writ_sexp::Sexp::list(vec![
        writ_sexp::Sexp::atom("writ/v1"),
        writ_sexp::Sexp::list(vec![
            writ_sexp::Sexp::atom("authority"),
            writ_sexp::Sexp::atom("1"),
            keys[0].to_sexp(),
            keys[1].to_sexp(),
        ]),
    ]);
    assert!(Item::decode(&weak.encode()).is_err());
}

/// Each name refers 16 times to the one below it. Derivations used to be
/// copied in full, so their length multiplied by 16 per level and depth 8
/// needed gigabytes; shared, the proof holds each statement once.
#[test]
fn repeated_names_stay_small() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let mut items = vec![st(a.say(name("x0", Subject::Id(a.id)), 10, None))];
    for j in 1..8 {
        let below = format!("x{}", j - 1);
        let labels = vec![below.as_str(); 16];
        items.push(st(a.say(
            name(&format!("x{j}"), path(a.id, &labels)),
            10,
            None,
        )));
    }
    items.push(st(a.say(name("y", Subject::Id(b.id)), 10, None)));
    let g = a.say(grant(path(a.id, &["x7", "y"]), "()", false), 10, None);
    items.push(st(g));
    let w = World::new(&a, items);
    let proof = w.check(Holder::Id(b.id), "()", 50).unwrap();
    assert_eq!(proof.steps.len(), 1);
    assert_eq!(proof.steps[0].names.len(), 9);
}

/// Junk signatures merged onto a real statement are verified one by one;
/// each counts against `max_signatures`, and running out denies rather than
/// skipping the statement.
#[test]
fn junk_signatures_count_against_the_budget() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "()", false), 10, None);
    let mut items: Vec<Item> = (0..20u8)
        .map(|i| {
            st(Signed {
                body: g.body.clone(),
                sigs: vec![Sig {
                    index: 0,
                    bytes: vec![i; crate::keys::ROOT_SIGNATURE_SIZE],
                }],
            })
        })
        .collect();
    items.push(st(g));
    assert!(
        World::new(&a, items.clone())
            .check(Holder::Id(b.id), "()", 50)
            .is_ok()
    );
    // A fresh world: the first one cached the result.
    let mut w = World::new(&a, items);
    w.policy.max_signatures = 10;
    assert!(w.check(Holder::Id(b.id), "()", 50).is_err());
}

/// Revocations of a statement are each examined; past the budget the
/// statement counts as invalid ([`Reason::Limit`]), never as unrevoked.
#[test]
fn junk_revocations_count_against_the_budget() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "()", false), 10, None);
    let mut items = vec![st(g.clone())];
    for i in 0..20u8 {
        let mut r = a.say(
            Claim::Revoke {
                target: g.body.hash(),
            },
            11 + u64::from(i),
            None,
        );
        r.sigs[0].bytes = vec![i; crate::keys::ROOT_SIGNATURE_SIZE];
        items.push(st(r));
    }
    let mut w = World::new(&a, items);
    assert!(w.check(Holder::Id(b.id), "()", 50).is_ok());
    w.policy.max_statements = 5;
    let d = w.check(Holder::Id(b.id), "()", 50).unwrap_err();
    assert!(
        matches!(d, Denial::Limit(_)) || rejected_for(&d, g.body.hash()) == Some(Reason::Limit)
    );
}

/// writ never signs an item its own decoder would reject: here a key type
/// that isn't a token, and a rotation whose `keep` makes it too large.
#[test]
fn undecodable_items_are_not_signed() {
    let mut a = Ident::new(1);
    let bad = OpaqueKey {
        kind: b"ssh-\x1b[31mX".to_vec(),
        bytes: vec![1],
    };
    let body = Statement {
        issuer: a.issuer(),
        issued: 10,
        expires: None,
        note: None,
        claim: grant(Subject::Opaque(bad), "()", false),
    };
    assert!(matches!(
        issue(body, &a.log(), &[&a.keys[0]], &mut TestRng::new(0)),
        Err(IssueError::Encoding(DecodeError::Malformed(_)))
    ));
    let revealed = a.next[0];
    let keep: Vec<Hash> = (0..130_000u32)
        .map(|i| Hash::labelled("writ/test", &i.to_be_bytes()))
        .collect();
    let plan = RotationPlan {
        revealed: Authority::single(revealed.0),
        authority: Authority::single(FakeRoot::new(40).0),
        next: Authority::single(FakeRoot::new(41).0),
        max_validity: None,
        publish: None,
        keep,
    };
    assert_eq!(
        rotate(&a.log(), plan, &[&revealed], &mut TestRng::new(0)),
        Err(IssueError::Encoding(DecodeError::Sexp(
            writ_sexp::DecodeError::TooLarge
        )))
    );
    // A large but readable keep list is fine.
    a.rotate(
        (0..1000u32)
            .map(|i| Hash::labelled("writ/test", &i.to_be_bytes()))
            .collect(),
        None,
    );
}

/// A grant with several tags means one grant per tag (DESIGN.md §18.2):
/// each tag works, anything under one works, their parent does not, one
/// revocation ends all of them, and delegation passes on what is narrowed.
#[test]
fn grants_with_several_tags() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let c = Ident::new(3);
    let g = a.say(
        grant_tags(Subject::Id(b.id), &["(files docs)", "(files photos)"], true),
        10,
        None,
    );
    let onward = b.say(
        grant(Subject::Id(c.id), "(files photos 2026)", false),
        10,
        None,
    );
    let w = World::new(
        &a,
        [st(g.clone()), st(onward)]
            .into_iter()
            .chain(b.items())
            .chain(c.items()),
    );
    let bob = Holder::Id(b.id);
    assert!(w.check(bob.clone(), "(files docs)", 50).is_ok());
    let proof = w.check(bob.clone(), "(files photos x)", 50).unwrap();
    assert_eq!(proof.tag, tag("(files photos)"));
    assert!(w.check(bob.clone(), "(files)", 50).is_err());
    assert!(w.check(bob.clone(), "(other)", 50).is_err());
    // Through delegation, only the narrowed tag reaches c.
    let carol = Holder::Id(c.id);
    assert!(w.check(carol.clone(), "(files photos 2026)", 50).is_ok());
    assert!(w.check(carol, "(files docs)", 50).is_err());
    // One revocation ends both tags.
    let r = a.say(
        Claim::Revoke {
            target: g.body.hash(),
        },
        20,
        None,
    );
    let w = World::new(&a, [st(g), st(r)]);
    assert!(w.check(bob.clone(), "(files docs)", 50).is_err());
    assert!(w.check(bob, "(files photos)", 50).is_err());
}

#[test]
fn several_tags_encode_canonically() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    // Order given doesn't matter: Tags sorts them.
    let g1 = a.say(
        grant_tags(Subject::Id(b.id), &["(b)", "(a)"], false),
        10,
        None,
    );
    let g2 = a.say(
        grant_tags(Subject::Id(b.id), &["(a)", "(b)"], false),
        10,
        None,
    );
    assert_eq!(g1.body.hash(), g2.body.hash());
    let item = Item::Statement(g1);
    assert_eq!(Item::decode(&item.encode()).as_ref(), Ok(&item));
    // One tag encodes exactly as before: `(tag …)` once, after the subject.
    let one = a.say(grant(Subject::Id(b.id), "(a)", false), 10, None);
    let text = String::from_utf8_lossy(&one.body.encode()).into_owned();
    assert!(text.ends_with("(3:tag1:a))"), "{text}");
    assert_eq!(
        Tags::new(vec![tag("(a)"), tag("(a b)")]),
        Err(TagsError::Covered)
    );
    assert_eq!(Tags::new(vec![]), Err(TagsError::Empty));
    let many: Vec<Tag> = (0..17).map(|i| tag(&format!("(t{i})"))).collect();
    assert_eq!(Tags::new(many), Err(TagsError::TooMany));
    assert_eq!(
        Tags::new(vec![tag("(a)"), tag("(a)")]).map(|t| t.as_slice().len()),
        Ok(1)
    );
}

// -- records and freshness (DESIGN.md §18.4–§18.6) ------------------------

const HOUR: u64 = 3600;
const NOW: Time = 100_000;

/// a (root) grants b `()` to delegate; b publishes with max-age one hour
/// and grants c `(x)`. Freshness is about b's grant to c.
fn chain_through_publisher() -> (Ident, Ident, Ident, Signed<Statement>) {
    let a = Ident::new(1);
    let b = Ident::publishing(2, HOUR);
    let c = Ident::new(3);
    let g = b.say(grant(Subject::Id(c.id), "(x)", false), 10, None);
    (a, b, c, g)
}

fn world_with(a: &Ident, b: &Ident, c: &Ident, extra: Vec<Item>) -> World {
    let ab = a.say(grant(Subject::Id(b.id), "()", true), 10, None);
    World::new(
        a,
        [st(ab)]
            .into_iter()
            .chain(b.items())
            .chain(c.items())
            .chain(extra),
    )
}

#[test]
fn a_publishing_issuer_needs_a_fresh_record() {
    let (a, b, c, g) = chain_through_publisher();
    let carol = Holder::Id(c.id);
    // No record: refused, and the reason says why.
    let w = world_with(&a, &b, &c, vec![st(g.clone())]);
    let d = w.check(carol.clone(), "(x)", NOW).unwrap_err();
    assert_eq!(
        rejected_for(&d, g.body.hash()),
        Some(Reason::NoFreshRecord { max_age: HOUR })
    );
    // A record younger than the max-age: allowed, and the proof carries it.
    let fresh = b.record(vec![], NOW - HOUR + 1);
    let w = world_with(&a, &b, &c, vec![st(g.clone()), Item::Record(fresh.clone())]);
    let proof = w.check(carol.clone(), "(x)", NOW).unwrap();
    assert!(proof.records.contains(&fresh.body.hash()));
    // Too old: refused again.
    let stale = b.record(vec![], NOW - HOUR - 1);
    let w = world_with(&a, &b, &c, vec![st(g), Item::Record(stale)]);
    assert!(w.check(carol, "(x)", NOW).is_err());
}

#[test]
fn short_lived_statements_need_no_record() {
    let (a, b, c, _) = chain_through_publisher();
    let short = b.say(
        grant(Subject::Id(c.id), "(x)", false),
        NOW - 10,
        Some(NOW - 10 + HOUR),
    );
    let w = world_with(&a, &b, &c, vec![st(short)]);
    assert!(w.check(Holder::Id(c.id), "(x)", NOW).is_ok());
    // One second longer than the max-age, and it needs one.
    let long = b.say(
        grant(Subject::Id(c.id), "(x)", false),
        NOW - 10,
        Some(NOW - 10 + HOUR + 1),
    );
    let w = world_with(&a, &b, &c, vec![st(long)]);
    assert!(w.check(Holder::Id(c.id), "(x)", NOW).is_err());
}

#[test]
fn records_revoke_and_are_combined() {
    let (a, b, c, g) = chain_through_publisher();
    let carol = Holder::Id(c.id);
    let revoking = b.record(vec![g.body.hash()], NOW - 100);
    let w = world_with(
        &a,
        &b,
        &c,
        vec![st(g.clone()), Item::Record(revoking.clone())],
    );
    let d = w.check(carol.clone(), "(x)", NOW).unwrap_err();
    assert_eq!(
        rejected_for(&d, g.body.hash()),
        Some(Reason::Revoked(revoking.body.hash()))
    );
    // A newer record that leaves it out does not bring it back.
    let newer = b.record(vec![], NOW - 10);
    let w = world_with(
        &a,
        &b,
        &c,
        vec![st(g), Item::Record(revoking), Item::Record(newer)],
    );
    assert!(w.check(carol, "(x)", NOW).is_err());
}

#[test]
fn a_record_counts_only_under_the_head() {
    let a = Ident::new(1);
    let mut b = Ident::publishing(2, HOUR);
    let c = Ident::new(3);
    let old = b.record(vec![], NOW - 10);
    b.rotate(vec![], None);
    let g = b.say(grant(Subject::Id(c.id), "(x)", false), 10, None);
    // The record from before the rotation says nothing now.
    let w = world_with(&a, &b, &c, vec![st(g.clone()), Item::Record(old)]);
    assert_eq!(
        rejected_for(
            &w.check(Holder::Id(c.id), "(x)", NOW).unwrap_err(),
            g.body.hash()
        ),
        Some(Reason::NoFreshRecord { max_age: HOUR })
    );
    let new = b.record(vec![], NOW - 10);
    let w = world_with(&a, &b, &c, vec![st(g), Item::Record(new)]);
    assert!(w.check(Holder::Id(c.id), "(x)", NOW).is_ok());
}

#[test]
fn local_roots_need_no_record_and_policy_can_require_them() {
    // The root itself publishes; given as local, its grant needs no record.
    let a = Ident::publishing(1, HOUR);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "(x)", false), 10, None);
    let w = World::new(&a, [st(g)].into_iter().chain(b.items()));
    let bob = Holder::Id(b.id);
    assert!(w.check(bob.clone(), "(x)", NOW).is_err());
    let local = [a.id];
    let v = Verifier::new(&w.roots, &w.material, &w.policy).with_local(&local);
    assert!(v.check(&bob, &tag("(x)"), NOW).is_ok());
    // require_records refuses issuers that don't publish, except local ones.
    let c = Ident::new(3);
    let d = Ident::new(4);
    let g = c.say(grant(Subject::Id(d.id), "(x)", false), 10, None);
    let mut w = World::new(&c, [st(g.clone())].into_iter().chain(d.items()));
    w.policy.require_records = true;
    let denial = w.check(Holder::Id(d.id), "(x)", NOW).unwrap_err();
    assert_eq!(
        rejected_for(&denial, g.body.hash()),
        Some(Reason::NoRecords)
    );
    let local = [c.id];
    let v = Verifier::new(&w.roots, &w.material, &w.policy).with_local(&local);
    assert!(v.check(&Holder::Id(d.id), &tag("(x)"), NOW).is_ok());
}

#[test]
fn revocation_statements_need_no_record() {
    // A revocation removes; it never needs freshness to count.
    let (a, b, c, _) = chain_through_publisher();
    let short = b.say(
        grant(Subject::Id(c.id), "(x)", false),
        NOW - 10,
        Some(NOW + 100),
    );
    let r = b.say(
        Claim::Revoke {
            target: short.body.hash(),
        },
        NOW - 5,
        None,
    );
    let w = world_with(&a, &b, &c, vec![st(short), st(r)]);
    assert!(w.check(Holder::Id(c.id), "(x)", NOW).is_err());
}

#[test]
fn records_and_publish_encode_canonically() {
    let b = Ident::publishing(2, HOUR);
    let item = Item::Event(b.events[0].clone());
    assert_eq!(Item::decode(&item.encode()).as_ref(), Ok(&item));
    let rec = Item::Record(b.record(vec![Hash([2; 32]), Hash([1; 32])], 5));
    assert_eq!(Item::decode(&rec.encode()).as_ref(), Ok(&rec));
    let Item::Record(r) = &rec else { panic!() };
    assert_eq!(r.body.revoked, vec![Hash([1; 32]), Hash([2; 32])]);
    assert!(Publish::new(HOUR - 1, vec![]).is_none());
    assert!(Publish::new(HOUR, vec!["a b".into()]).is_none());
    assert!(Publish::new(HOUR, vec![String::new()]).is_none());
    assert!(Publish::new(HOUR, vec!["u".into(); 5]).is_none());
    assert!(Publish::new(HOUR, vec!["https://x".into(); 4]).is_some());
}

#[test]
fn data_signatures_by_a_publisher_need_a_fresh_record() {
    let a = Ident::new(1);
    let b = Ident::publishing(2, HOUR);
    let data = Hash::of_data(b"release");
    let ab = a.say(grant(Subject::Id(b.id), "(release)", false), 10, None);
    let sig = sign_data(
        data,
        b"app/v1",
        20,
        &b.log(),
        &[&b.keys[0]],
        &mut TestRng::new(0),
    )
    .unwrap();
    let base: Vec<Item> = [st(ab)].into_iter().chain(b.items()).collect();
    let w = World::new(&a, base.clone());
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    assert_eq!(
        v.verify(&sig, &data, b"app/v1", &tag("(release)"), NOW),
        Err(Denial::Signature(Reason::NoFreshRecord { max_age: HOUR }))
    );
    let rec = b.record(vec![], NOW - 60);
    let w = World::new(&a, base.into_iter().chain([Item::Record(rec.clone())]));
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let proof = v
        .verify(&sig, &data, b"app/v1", &tag("(release)"), NOW)
        .unwrap();
    assert!(proof.records.contains(&rec.body.hash()));
}

/// Channel binding (DESIGN.md §18.3): a binding counts for its channel, its
/// role and its application only, and only if its key holds the tag.
#[test]
fn channel_binding() {
    use crate::channel::{Role, bind, check};
    let a = Ident::new(1);
    let leaf = FakeLeaf::new(7);
    let g = a.say(
        grant(Subject::Leaf(leaf.0.clone()), "(screen view)", false),
        10,
        Some(10 + 3600),
    );
    let w = World::new(&a, [st(g)]);
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let e = [0x42u8; 32];
    let sig = bind(
        &e,
        Role::Initiator,
        "screen",
        20,
        &leaf,
        &mut TestRng::new(0),
    )
    .unwrap();
    let ok =
        |exporter: &[u8], role, app, t: &str| check(&v, &sig, exporter, role, app, &tag(t), 30);
    assert!(ok(&e, Role::Initiator, "screen", "(screen view video)").is_ok());
    // Not reflected to the other role, another channel, or another app.
    assert_eq!(
        ok(&e, Role::Responder, "screen", "(screen view)"),
        Err(Denial::Data)
    );
    assert_eq!(
        ok(&[0x43; 32], Role::Initiator, "screen", "(screen view)"),
        Err(Denial::Data)
    );
    assert_eq!(
        ok(&e, Role::Initiator, "files", "(screen view)"),
        Err(Denial::Context)
    );
    // The key must hold the tag.
    assert!(ok(&e, Role::Initiator, "screen", "(screen control)").is_err());
    // An identity refuses to sign the same body (SPEC §5.5); one signed
    // behind the library's back is still not a binding.
    let mut d = DataHasher::new();
    d.update(&[1]);
    d.update(&e);
    let body = DataSig {
        signer: a.issuer(),
        issued: 20,
        context: b"writ/v1/channel/screen".to_vec(),
        data: d.finish(),
    };
    assert!(matches!(
        sign_with_authority(
            body.clone(),
            a.log().head().authority(),
            &[&a.keys[0]],
            &mut TestRng::new(0),
        ),
        Err(IssueError::Rule(_))
    ));
    let by_identity = Signed {
        sigs: vec![Sig {
            index: 0,
            bytes: a.keys[0]
                .sign(&body.message(), &mut TestRng::new(0))
                .unwrap(),
        }],
        body,
    };
    assert!(
        check(
            &v,
            &by_identity,
            &e,
            Role::Initiator,
            "screen",
            &tag("()"),
            30
        )
        .is_err()
    );
    // Short exporters and writ's own contexts are refused when signing.
    assert!(
        bind(
            &[0; 31],
            Role::Initiator,
            "screen",
            20,
            &leaf,
            &mut TestRng::new(0)
        )
        .is_err()
    );
    assert_eq!(
        sign_data_leaf(
            Hash([0; 32]),
            b"writ/v1/channel/screen",
            20,
            &leaf,
            &mut TestRng::new(0)
        )
        .map(|_| ()),
        Err(IssueError::Rule(
            "contexts starting with writ/ are reserved for writ"
        ))
    );
}

/// A junk signature merged onto a genuine record must not travel: a proof
/// carrying the record still decodes, and still verifies alone.
#[test]
fn proofs_ship_records_without_junk_signatures() {
    let (a, b, c, g) = chain_through_publisher();
    let rec = b.record(vec![], NOW - 60);
    let mut junk = rec.clone();
    junk.sigs[0].bytes[0] ^= 1;
    let w = world_with(
        &a,
        &b,
        &c,
        vec![st(g), Item::Record(junk), Item::Record(rec)],
    );
    let proof = w.check(Holder::Id(c.id), "(x)", NOW).unwrap();
    assert_eq!(proof.records.len(), 1);
    let bundle: Vec<u8> = proof
        .items(&w.material)
        .iter()
        .flat_map(Item::encode)
        .collect();
    let items = Item::decode_bundle(&bundle).unwrap();
    let alone = World::new(&a, items);
    assert!(alone.check(Holder::Id(c.id), "(x)", NOW).is_ok());
}

/// A forged grant (bad signature) to a name path must not make the search
/// read that path's names: otherwise its rejections would name, as needing
/// a record, an identity that nothing valid leads to (and --fetch would
/// fetch from its URLs).
#[test]
fn forged_grants_do_not_lead_to_names() {
    let a = Ident::new(1);
    let x = Ident::publishing(2, HOUR);
    let c = Ident::new(3);
    let n = x.say(name("friends", Subject::Id(c.id)), 10, None);
    let mut forged = a.say(grant(path(x.id, &["friends"]), "()", false), 10, None);
    forged.sigs[0].bytes[0] ^= 1;
    let w = World::new(
        &a,
        [st(forged), st(n.clone())]
            .into_iter()
            .chain(x.items())
            .chain(c.items()),
    );
    let d = w.check(Holder::Id(c.id), "()", NOW).unwrap_err();
    assert_eq!(rejected_for(&d, n.body.hash()), None, "{d:?}");
}

/// An equivocating root fails every query, even one another root could
/// answer (DESIGN.md §4.4): a trust anchor is compromised, and the evidence
/// must reach the caller.
#[test]
fn an_equivocating_root_fails_every_query() {
    let a = Ident::new(1);
    let mut b = Ident::new(2);
    let c = Ident::new(3);
    let ac = a.say(grant(Subject::Id(c.id), "(x)", false), 10, None);
    b.rotate(vec![], None);
    let mut b2 = Ident::new(2);
    let r1b = b2.rotate(vec![], Some(99));
    let mut w = World::new(
        &a,
        [st(ac), Item::Event(r1b)]
            .into_iter()
            .chain(b.items())
            .chain(c.items()),
    );
    assert!(w.check(Holder::Id(c.id), "(x)", 50).is_ok());
    w.roots.push(b.id);
    assert!(matches!(
        w.check(Holder::Id(c.id), "(x)", 50),
        Err(Denial::Compromised(e)) if e.id() == b.id
    ));
    // The root itself, and a subject no chain reaches, get the same answer.
    assert!(matches!(
        w.check(Holder::Id(a.id), "()", 50),
        Err(Denial::Compromised(_))
    ));
    assert!(matches!(
        w.check(Holder::Id(b.id), "()", 50),
        Err(Denial::Compromised(_))
    ));
}

/// `Verifier::verify` refuses writ's reserved contexts (SPEC §5.5): a
/// channel binding is checked through `channel::check`, which still works.
#[test]
fn verify_refuses_reserved_contexts() {
    use crate::channel::{Role, bind, check};
    let a = Ident::new(1);
    let leaf = FakeLeaf::new(7);
    let g = a.say(
        grant(Subject::Leaf(leaf.0.clone()), "(screen)", false),
        10,
        Some(10 + 3600),
    );
    let w = World::new(&a, [st(g)]);
    let v = Verifier::new(&w.roots, &w.material, &w.policy);
    let e = [0x42u8; 32];
    let sig = bind(
        &e,
        Role::Initiator,
        "screen",
        20,
        &leaf,
        &mut TestRng::new(0),
    )
    .unwrap();
    assert!(
        check(
            &v,
            &sig,
            &e,
            Role::Initiator,
            "screen",
            &tag("(screen)"),
            30
        )
        .is_ok()
    );
    assert!(matches!(
        v.verify(
            &sig,
            &sig.body.data,
            &sig.body.context,
            &tag("(screen)"),
            30
        ),
        Err(Denial::Signature(Reason::Malformed(_)))
    ));
}

/// The next authority may not be the current one (DESIGN.md §4.3): a warm
/// key that could also rotate would let a thief holding it extend the log.
#[test]
fn next_must_differ_from_current() {
    let k = FakeRoot::new(50);
    let same = Authority::single(k.0);
    let mut rng = TestRng::new(0);
    assert!(matches!(
        incept(same.clone(), &same, None, None, &[&k], &mut rng),
        Err(IssueError::Rule(_))
    ));
    let mut b = Ident::new(2);
    let revealed = b.next[0];
    let plan = RotationPlan {
        revealed: Authority::single(revealed.0),
        authority: Authority::single(k.0),
        next: Authority::single(k.0),
        max_validity: None,
        publish: None,
        keep: vec![],
    };
    assert!(matches!(
        rotate(&b.log(), plan, &[&revealed], &mut rng),
        Err(IssueError::Rule(_))
    ));
    // Committing to the revealed authority again is allowed (§4.3).
    let plan = RotationPlan {
        revealed: Authority::single(revealed.0),
        authority: Authority::single(k.0),
        next: Authority::single(revealed.0),
        max_validity: None,
        publish: None,
        keep: vec![],
    };
    assert!(rotate(&b.log(), plan, &[&revealed], &mut rng).is_ok());
    let _ = b.rotate(vec![], None);
}

/// `k` valid signatures are enough: junk merged after them is never checked,
/// and what a log or proof ships is exactly those `k` (SPEC §11).
#[test]
fn k_valid_signatures_are_enough() {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let g = a.say(grant(Subject::Id(b.id), "(x)", false), 10, None);
    let junk = |n: u8| Sig {
        index: 0,
        bytes: vec![n; crate::keys::ROOT_SIGNATURE_SIZE],
    };
    let mut copies = Vec::new();
    for n in 1..4 {
        let mut c = g.clone();
        c.sigs = vec![junk(n)];
        copies.push(st(c));
    }
    let mut ev = a.events[0].clone();
    ev.sigs = vec![junk(1), junk(2)];
    let w = World::new(
        &a,
        copies.into_iter().chain([st(g.clone()), Item::Event(ev)]),
    );
    assert_eq!(w.material.statement(&g.body.hash()).unwrap().sigs.len(), 4);
    let proof = w.check(Holder::Id(b.id), "(x)", 50).unwrap();
    for item in proof.items(&w.material) {
        match item {
            Item::Statement(s) => assert_eq!(s.sigs, g.sigs),
            Item::Event(e) => assert_eq!(e.sigs, a.events[0].sigs),
            _ => {}
        }
    }
}
