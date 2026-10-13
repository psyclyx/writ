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
        let k0 = FakeRoot::new(seed.wrapping_mul(16));
        let k1 = FakeRoot::new(seed.wrapping_mul(16) + 1);
        let (id, ev) = incept(
            Authority::single(k0.0),
            &Authority::single(k1.0),
            max_validity,
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
}

pub(crate) fn tag(s: &str) -> Tag {
    Tag::parse(s).unwrap()
}

pub(crate) fn grant(subject: Subject, t: &str, delegate: bool) -> Claim {
    Claim::Grant {
        subject,
        tag: tag(t),
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
    let devices = b.say(name("devices", Subject::Leaf(leaf.0.clone())), 10, None);
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
    // A revocation not yet valid doesn't count.
    let w = World::new(&a, [st(g), st(r)]);
    assert!(w.check(Holder::Id(b.id), "()", 10).is_ok());
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
        issuer: Issuer::Leaf(leaf.0.clone()),
        issued: 20,
        expires: None,
        note: None,
        claim: grant(Subject::Opaque(app.clone()), "(svc read)", false),
    };
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
            issuer: Issuer::Leaf(leaf.0.clone()),
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
    let w = World::new(&a, [st(al)]);
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
        incept(authority.clone(), &next, None, &[&keys[0]], &mut rng).map(|_| ()),
        Err(IssueError::BelowThreshold { k: 2, have: 1 })
    );
    // Signing twice with one key doesn't count twice.
    assert!(
        incept(
            authority.clone(),
            &next,
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
