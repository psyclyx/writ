//! The published test vectors (vectors/README.md), as `cargo xtask vectors`
//! writes them. Generating them also checks what they record (decoding the
//! world bundle reproduces it, each rejection is rejected), so a generator
//! that disagrees with libwrit fails instead of publishing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use libwrit::keys::RootSigner;
use libwrit::*;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::Files;

/// Every vector file: (path from the repository root, contents).
pub fn generate() -> Files {
    let mut files = Files::new();
    keys(&mut files);
    items_and_chains(&mut files);
    rejections(&mut files);
    files
}

fn put(files: &mut Files, rel: &str, text: &str) {
    files.push((format!("vectors/{rel}"), text.to_owned()));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A deterministic, non-cryptographic byte stream for reproducible vectors.
struct VectorRng(Hash);

impl Rng for VectorRng {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.0 = Hash::labelled("writ/v1/test-vectors/rng", &self.0.0);
            chunk.copy_from_slice(&self.0.0[..chunk.len()]);
        }
    }
}

fn seed(n: u8) -> Seed {
    Seed::from_bytes(Hash::labelled("writ/v1/test-vectors/seed", &[n]).0)
}

fn keys(files: &mut Files) {
    let mut out = String::from(
        "# writ key derivation (SPEC.md §4). One block per seed.\n\
         # root = SLH-DSA-SHAKE-128s public key; leaf-mldsa = ML-DSA-65 verification key;\n\
         # leaf-ed25519 = Ed25519 public key; secret = the key-file line.\n",
    );
    for s in [
        Seed::from_bytes([0; 32]),
        Seed::from_bytes([0xff; 32]),
        seed(1),
    ] {
        let root = s.root().root_key();
        let leaf = s.leaf();
        let _ = write!(
            out,
            "\nseed = {}\nsecret = {}\nroot = {}\nleaf-mldsa = {}\nleaf-ed25519 = {}\nleaf-id = {}\n",
            hex(s.as_bytes()),
            *s.to_text(),
            hex(&root.0),
            hex(leaf.leaf_key().mldsa.as_slice()),
            hex(&leaf.leaf_key().ed25519),
            leaf.leaf_key().id(),
        );
    }
    put(files, "keys/derivation.txt", &out);
}

const T0: Time = 1_800_000_000;

struct Who {
    log: Log,
    /// The current key at each event.
    keys: Vec<RootSigner>,
    next: RootSigner,
}

impl Who {
    fn new(n: u8, max_validity: Option<u64>, rng: &mut VectorRng, m: &mut Material) -> Who {
        let k0 = seed(n * 10).root();
        let k1 = seed(n * 10 + 1).root();
        let (id, ev) = incept(
            Authority::single(k0.root_key()),
            &Authority::single(k1.root_key()),
            max_validity,
            &[&k0],
            rng,
        )
        .unwrap();
        m.add(Item::Event(ev));
        let log = m.log(&id).as_ref().clone().unwrap();
        Who {
            log,
            keys: vec![k0],
            next: k1,
        }
    }

    fn id(&self) -> Id {
        self.log.id()
    }

    fn say(
        &self,
        claim: Claim,
        issued: Time,
        expires: Option<Time>,
        rng: &mut VectorRng,
    ) -> Signed<Statement> {
        let n = self.log.head_n();
        issue(
            Statement {
                issuer: Issuer::Identity {
                    id: self.id(),
                    event: n,
                },
                issued,
                expires,
                note: None,
                claim,
            },
            &self.log,
            &[&self.keys[n as usize]],
            rng,
        )
        .unwrap()
    }
}

fn grant(subject: Subject, tag: &str, delegate: bool) -> Claim {
    grant_tags(subject, &[tag], delegate)
}

/// A grant with several tags (DESIGN.md §18.2).
fn grant_tags(subject: Subject, tags: &[&str], delegate: bool) -> Claim {
    Claim::Grant {
        subject,
        tags: Tags::new(tags.iter().map(|t| Tag::parse(t).unwrap()).collect()).unwrap(),
        delegate,
    }
}

struct World {
    items: Vec<Item>,
    material: Material,
    root: Id,
    labels: BTreeMap<Hash, &'static str>,
    subjects: BTreeMap<&'static str, Holder>,
    signature: Signed<DataSig>,
}

/// The chain-verification world: every rule exercised once.
fn world() -> World {
    let mut rng = VectorRng(Hash([7; 32]));
    let mut m = Material::new();
    let mut items = Vec::new();
    let mut labels = BTreeMap::new();
    let me = Who::new(1, None, &mut rng, &mut m);
    let mut alice = Who::new(2, None, &mut rng, &mut m);
    let bob = Who::new(3, None, &mut rng, &mut m);
    let mut quinn = Who::new(4, None, &mut rng, &mut m);
    let leaf = seed(50).leaf();
    let app = OpaqueKey {
        kind: b"ssh-ed25519".to_vec(),
        bytes: vec![0x5a; 51],
    };
    let mut add = |label: &'static str, s: Signed<Statement>, m: &mut Material| {
        labels.insert(s.body.hash(), label);
        m.add(Item::Statement(s.clone()));
        items.push(Item::Statement(s));
    };
    add(
        "me-names-alice",
        me.say(
            Claim::Name {
                name: b"alice".to_vec(),
                subject: Subject::Id(alice.id()),
            },
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "me-grants-alice-ssh",
        me.say(
            grant(
                Subject::Name(NamePath {
                    base: me.id(),
                    names: vec![b"alice".to_vec()],
                }),
                "(ssh)",
                true,
            ),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    let kept = alice.say(
        grant(Subject::Id(bob.id()), "(ssh nas)", false),
        T0,
        None,
        &mut rng,
    );
    add("alice-grants-bob-ssh-nas", kept.clone(), &mut m);
    add(
        "alice-grants-bob-old",
        alice.say(
            grant(Subject::Id(bob.id()), "(ssh old)", false),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "me-grants-bob-web",
        me.say(
            grant(Subject::Id(bob.id()), "(web)", false),
            T0,
            Some(T0 + 100),
            &mut rng,
        ),
        &mut m,
    );
    let mail = me.say(
        grant(Subject::Id(bob.id()), "(mail)", false),
        T0,
        None,
        &mut rng,
    );
    add("me-grants-bob-mail", mail.clone(), &mut m);
    add(
        "me-revokes-mail",
        me.say(
            Claim::Revoke {
                target: mail.body.hash(),
            },
            T0 + 1,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "me-grants-bob-future",
        me.say(
            grant(Subject::Id(bob.id()), "(future)", false),
            T0 + 10_000,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "me-grants-leaf",
        me.say(
            grant(Subject::Leaf(leaf.leaf_key().clone()), "(svc)", true),
            T0,
            Some(T0 + 3600),
            &mut rng,
        ),
        &mut m,
    );
    add(
        "leaf-grants-app",
        issue_leaf(
            Statement {
                issuer: Issuer::Leaf(leaf.leaf_key().id()),
                issued: T0 + 5,
                expires: None,
                note: Some("vector".into()),
                claim: grant(Subject::Opaque(app.clone()), "(svc read)", false),
            },
            &leaf,
            &mut rng,
        )
        .unwrap(),
        &mut m,
    );
    add(
        "me-grants-quinn",
        me.say(
            grant(Subject::Id(quinn.id()), "()", true),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "quinn-grants-bob",
        quinn.say(
            grant(Subject::Id(bob.id()), "(q)", false),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );

    // alice rotates, keeping one statement; then speaks under event 1.
    let alice_current = seed(23).root();
    let rotation = rotate(
        &alice.log,
        RotationPlan {
            revealed: Authority::single(alice.next.root_key()),
            authority: Authority::single(alice_current.root_key()),
            next: Authority::single(seed(22).root().root_key()),
            max_validity: None,
            keep: vec![kept.body.hash()],
        },
        &[&alice.next],
        &mut rng,
    )
    .unwrap();
    alice.keys.push(alice_current);
    m.add(Item::Event(rotation));
    alice.log = m.log(&alice.id()).as_ref().clone().unwrap();
    add(
        "alice-grants-bob-ftp",
        alice.say(
            grant(Subject::Id(bob.id()), "(ssh ftp)", false),
            T0 + 2,
            None,
            &mut rng,
        ),
        &mut m,
    );

    // After the rotation, alice's revealed next key tries to sign a
    // statement: next keys only ever sign rotations.
    let by_next = sign_with_authority(
        Statement {
            issuer: Issuer::Identity {
                id: alice.id(),
                event: 1,
            },
            issued: T0 + 3,
            expires: None,
            note: None,
            claim: grant(Subject::Id(bob.id()), "(ssh next)", false),
        },
        &Authority::single(alice.next.root_key()),
        &[&alice.next],
        &mut rng,
    )
    .unwrap();
    add("alice-next-key-grants-bob", by_next, &mut m);

    // quinn's next key signs two different rotation 1s.
    for keep in [vec![], vec![Hash([1; 32])]] {
        let r = rotate(
            &quinn.log,
            RotationPlan {
                revealed: Authority::single(quinn.next.root_key()),
                authority: Authority::single(seed(43).root().root_key()),
                next: Authority::single(seed(42).root().root_key()),
                max_validity: None,
                keep,
            },
            &[&quinn.next],
            &mut rng,
        )
        .unwrap();
        m.add(Item::Event(r));
    }
    quinn.keys.clear();

    let signature = sign_data_leaf(
        Hash::of_data(b"hello, writ\n"),
        b"writ/test-vectors/v1",
        T0 + 10,
        &leaf,
        &mut rng,
    )
    .unwrap();

    // Names for a leaf key carry the leaf ceiling too. The first is signed
    // by an issuer that ignored the rule.
    let leaf_name = |name: &str, expires: Option<Time>, rng: &mut VectorRng| {
        sign_with_authority(
            Statement {
                issuer: Issuer::Identity {
                    id: me.id(),
                    event: 0,
                },
                issued: T0,
                expires,
                note: None,
                claim: Claim::Name {
                    name: name.as_bytes().to_vec(),
                    subject: Subject::Leaf(leaf.leaf_key().clone()),
                },
            },
            &Authority::single(me.keys[0].root_key()),
            &[&me.keys[0]],
            rng,
        )
        .unwrap()
    };
    add(
        "me-names-leaf-forever",
        leaf_name("forever", None, &mut rng),
        &mut m,
    );
    add(
        "me-names-leaf-day",
        leaf_name("day", Some(T0 + 3600), &mut rng),
        &mut m,
    );
    for (label, name) in [
        ("me-grants-leaf-forever", "forever"),
        ("me-grants-leaf-day", "day"),
    ] {
        let subject = Subject::Name(NamePath {
            base: me.id(),
            names: vec![name.as_bytes().to_vec()],
        });
        add(
            label,
            me.say(
                grant(subject, &format!("(named {name})"), false),
                T0,
                None,
                &mut rng,
            ),
            &mut m,
        );
    }

    // Grants with several tags (DESIGN.md §18.2): two tags at once, a pair
    // revoked by one revocation, and a delegation that passes on one tag.
    add(
        "me-grants-bob-files",
        me.say(
            grant_tags(
                Subject::Id(bob.id()),
                &["(files docs)", "(files photos)"],
                false,
            ),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    let pair = me.say(
        grant_tags(Subject::Id(bob.id()), &["(print)", "(scan)"], false),
        T0,
        None,
        &mut rng,
    );
    add("me-grants-bob-print-scan", pair.clone(), &mut m);
    add(
        "me-revokes-print-scan",
        me.say(
            Claim::Revoke {
                target: pair.body.hash(),
            },
            T0 + 1,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "me-grants-bob-teams",
        me.say(
            grant_tags(Subject::Id(bob.id()), &["(team a)", "(team b)"], true),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );
    add(
        "bob-grants-app-team-b",
        bob.say(
            grant(Subject::Opaque(app.clone()), "(team b x)", false),
            T0,
            None,
            &mut rng,
        ),
        &mut m,
    );

    let mut all: Vec<Item> = Vec::new();
    for id in m.ids().copied().collect::<Vec<_>>() {
        match &*m.log(&id) {
            Ok(log) => all.extend(log.items()),
            Err(LogError::Equivocation(e)) => all.extend(e.items()),
            Err(e) => panic!("{e}"),
        }
    }
    all.extend(items);
    let subjects = BTreeMap::from([
        ("me", Holder::Id(me.id())),
        ("alice", Holder::Id(alice.id())),
        ("bob", Holder::Id(bob.id())),
        ("quinn", Holder::Id(quinn.id())),
        ("leaf", Holder::Leaf(leaf.leaf_key().clone())),
        ("app", Holder::Opaque(app)),
    ]);
    World {
        items: all,
        material: m,
        root: me.id(),
        labels,
        subjects,
        signature,
    }
}

fn reason_kind(r: &Reason) -> &'static str {
    match r {
        Reason::Malformed(_) => "malformed",
        Reason::Log(_) => "log",
        Reason::UnknownEvent { .. } => "unknown-event",
        Reason::NotKept { .. } => "not-kept",
        Reason::UnknownLeaf(_) => "unknown-leaf",
        Reason::BadSignature => "bad-signature",
        Reason::Suite(_) => "suite",
        Reason::Revoked(_) => "revoked",
        Reason::NotYetValid(_) => "not-yet-valid",
        Reason::Expired(_) => "expired",
        Reason::MaxValidity(_) => "max-validity",
        Reason::LeafCeiling(_) => "leaf-ceiling",
        Reason::Covers(_) => "covers",
        Reason::OutsideIssuer { .. } => "outside-issuer",
        Reason::Limit => "limit",
    }
}

fn items_and_chains(files: &mut Files) {
    let w = world();
    // The world bundle, and every item's identifiers.
    let bundle: String = w.items.iter().map(Item::armor).collect();
    put(files, "chains/world.writ", &bundle);
    let mut idx = String::from(
        "# Every item in chains/world.writ, in order: kind, body hash (or id for\n\
         # inceptions), and the canonical encoding's length. SPEC.md §6.\n",
    );
    for item in &w.items {
        let (hash, extra) = match item {
            Item::Event(e) => (e.body.hash(), format!("id = {}\n", e.body.id())),
            Item::Statement(s) => (
                s.body.hash(),
                format!(
                    "label = {}\n",
                    w.labels.get(&s.body.hash()).copied().unwrap_or("-")
                ),
            ),
            other => panic!("{}", other.kind()),
        };
        let _ = write!(
            idx,
            "\nkind = {}\nhash = {hash}\n{extra}encoded-length = {}\n",
            item.kind(),
            item.encode().len()
        );
    }
    put(files, "chains/items.txt", &idx);

    // Decoding the published bundle reproduces the world.
    let decoded = Item::decode_bundle(bundle.as_bytes()).unwrap();
    assert_eq!(decoded, w.items);

    let cases: &[(&str, &str, &str, Time)] = &[
        ("root holds everything", "me", "()", T0 + 100),
        (
            "through a name, then delegation",
            "bob",
            "(ssh nas disk)",
            T0 + 100,
        ),
        ("narrower than asked", "bob", "(ssh)", T0 + 100),
        ("before expiry", "bob", "(web)", T0 + 99),
        ("at expiry", "bob", "(web)", T0 + 100),
        ("revoked", "bob", "(mail)", T0 + 100),
        ("issued in the future", "bob", "(future)", T0 + 100),
        (
            "issued in the future, within skew",
            "bob",
            "(future)",
            T0 + 9_700,
        ),
        ("leaf, then opaque key", "app", "(svc read x)", T0 + 100),
        ("leaf grant expired", "app", "(svc read)", T0 + 3600),
        ("issued after rotation", "bob", "(ssh ftp)", T0 + 100),
        ("not kept by rotation", "bob", "(ssh old)", T0 + 100),
        ("signed by a next key", "bob", "(ssh next)", T0 + 100),
        ("through an equivocating identity", "bob", "(q)", T0 + 100),
        ("about an equivocating identity", "quinn", "()", T0 + 100),
        (
            "leaf named without expiry",
            "leaf",
            "(named forever)",
            T0 + 100,
        ),
        ("leaf named for an hour", "leaf", "(named day)", T0 + 100),
        ("leaf name expired", "leaf", "(named day)", T0 + 3600),
        ("nothing at all", "alice", "(nope)", T0 + 100),
        ("several tags: the first", "bob", "(files docs)", T0 + 100),
        (
            "several tags: below the second",
            "bob",
            "(files photos 2026)",
            T0 + 100,
        ),
        ("several tags: not their parent", "bob", "(files)", T0 + 100),
        ("several tags: revoked as one", "bob", "(scan)", T0 + 100),
        (
            "several tags: delegated, one passed on",
            "app",
            "(team b x)",
            T0 + 100,
        ),
        (
            "several tags: delegated, the other",
            "app",
            "(team a)",
            T0 + 100,
        ),
    ];
    let roots = [w.root];
    let policy = Policy::default();
    let v = Verifier::new(&roots, &w.material, &policy);
    let label = |h: &Hash| w.labels.get(h).copied().unwrap_or("?");
    let mut out = String::from(
        "# Chain verification cases against chains/world.writ (SPEC.md §9–§11).\n\
         # Root: the identity labelled me. Policy: defaults (skew 300 s).\n\
         # Statements are named by their label in chains/items.txt.\n\
         # allowed: the chain, in order (names before the grant they serve).\n\
         # denied: why, and each rejected candidate with its reason.\n",
    );
    let _ = writeln!(out, "\nroot = {}", w.root);
    for (who, holder) in &w.subjects {
        let text = holder.to_subject().to_sexp().to_readable();
        let shown = match text.char_indices().nth(100) {
            Some((i, _)) => format!("{}…", &text[..i]),
            None => text,
        };
        let _ = writeln!(out, "subject {who} = {shown}");
    }
    for (name, who, tag, now) in cases {
        let holder = &w.subjects[who];
        let _ = write!(
            out,
            "\ncase = {name}\nsubject = {who}\ntag = {tag}\nnow = {now}\n"
        );
        match v.check(holder, &Tag::parse(tag).unwrap(), *now) {
            Ok(p) => {
                let chain: Vec<&str> = p.statements().iter().map(label).collect();
                let _ = write!(
                    out,
                    "result = allowed\nchain = {}\neffective-tag = {}\nexpires = {}\n",
                    if chain.is_empty() {
                        "-".into()
                    } else {
                        chain.join(" ")
                    },
                    p.tag,
                    p.expires.map_or("never".into(), |e| e.to_string())
                );
            }
            Err(Denial::NotFound { rejected }) => {
                let _ = writeln!(out, "result = denied\nreason = not-found");
                let mut r: Vec<String> = rejected
                    .iter()
                    .map(|r| format!("{}:{}", label(&r.statement), reason_kind(&r.reason)))
                    .collect();
                r.sort();
                if !r.is_empty() {
                    let _ = writeln!(out, "rejected = {}", r.join(" "));
                }
            }
            Err(Denial::Compromised(e)) => {
                assert!(e.verify());
                let _ = writeln!(
                    out,
                    "result = denied\nreason = compromised\nevent = {}",
                    e.n()
                );
            }
            Err(d) => panic!("{name}: {d:?}"),
        }
    }
    put(files, "chains/cases.txt", &out);

    // A data signature by the leaf.
    let sig = &w.signature;
    let item = Item::Signature(sig.clone());
    let mut s =
        String::from("# A data signature (SPEC.md §8) by the leaf key in chains/world.writ.\n");
    let _ = write!(
        s,
        "\ndata = {}\ndata-hash = {}\ncontext = writ/test-vectors/v1\nsignature-hash = {}\n",
        hex(b"hello, writ\n"),
        sig.body.data,
        sig.body.hash()
    );
    let tag = Tag::parse("(svc)").unwrap();
    let ok = v.verify(
        sig,
        &Hash::of_data(b"hello, writ\n"),
        b"writ/test-vectors/v1",
        &tag,
        T0 + 100,
    );
    let _ = writeln!(
        s,
        "verify-as-root-for-(svc)-at-{} = {}",
        T0 + 100,
        if ok.is_ok() { "good" } else { "bad" }
    );
    let late = v.verify(
        sig,
        &Hash::of_data(b"hello, writ\n"),
        b"writ/test-vectors/v1",
        &tag,
        T0 + 3600,
    );
    let _ = writeln!(
        s,
        "verify-as-root-for-(svc)-at-{} = {}",
        T0 + 3600,
        if late.is_ok() { "good" } else { "bad" }
    );
    put(files, "chains/signature.txt", &s);
    put(files, "chains/signature.writ", &item.armor());
}

/// Encodings every implementation must reject (SPEC.md §5).
fn rejections(files: &mut Files) {
    use writ_sexp::Sexp;
    let mut rng = VectorRng(Hash([9; 32]));
    let mut m = Material::new();
    let me = Who::new(1, None, &mut rng, &mut m);
    let good = me.say(
        grant(Subject::Id(me.id()), "(a)", false),
        T0,
        None,
        &mut rng,
    );
    let item = Item::Statement(good.clone()).to_sexp();
    let Sexp::List(top) = &item else { panic!() };
    let Sexp::List(body) = &top[1] else { panic!() };
    let with_body = |f: &dyn Fn(&mut Vec<Sexp>)| {
        let mut b = body.clone();
        f(&mut b);
        let mut t = top.clone();
        t[1] = Sexp::List(b);
        Sexp::List(t).encode()
    };
    let with_top = |f: &dyn Fn(&mut Vec<Sexp>)| {
        let mut t = top.clone();
        f(&mut t);
        Sexp::List(t).encode()
    };
    let sig = top[2].clone();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("valid (for reference)", item.encode()),
        ("wrong version", with_top(&|t| t[0] = Sexp::atom("writ/v2"))),
        ("unsigned", with_top(&|t| t.truncate(2))),
        (
            "duplicate signature index",
            with_top(&|t| t.push(sig.clone())),
        ),
        (
            "signature index out of range",
            with_top(&|t| {
                t[2] = Sexp::list(vec![
                    Sexp::atom("sig"),
                    Sexp::atom("16"),
                    Sexp::atom([0; 7856]),
                ])
            }),
        ),
        (
            "signature index with leading zero",
            with_top(&|t| {
                t[2] = Sexp::list(vec![
                    Sexp::atom("sig"),
                    Sexp::atom("00"),
                    Sexp::atom([0; 7856]),
                ])
            }),
        ),
        (
            "short root signature",
            with_top(&|t| {
                t[2] = Sexp::list(vec![
                    Sexp::atom("sig"),
                    Sexp::atom("0"),
                    Sexp::atom([0; 7855]),
                ])
            }),
        ),
        (
            "issued with leading zero",
            with_body(&|b| {
                b[2] = Sexp::list(vec![Sexp::atom("issued"), Sexp::atom("01800000000")])
            }),
        ),
        ("fields out of order", with_body(&|b| b.swap(3, 4))),
        (
            "unknown field",
            with_body(&|b| b.push(Sexp::list(vec![Sexp::atom("extra")]))),
        ),
        (
            "empty tag atom",
            with_body(&|b| b[4] = Sexp::list(vec![Sexp::atom("tag"), Sexp::atom("")])),
        ),
        (
            "delegate with a value",
            with_body(&|b| b.push(Sexp::list(vec![Sexp::atom("delegate"), Sexp::atom("yes")]))),
        ),
        ("grant without a tag", with_body(&|b| drop(b.remove(4)))),
        (
            "tags out of order",
            with_body(&|b| {
                b[4] = Sexp::list(vec![Sexp::atom("tag"), Sexp::atom("b")]);
                b.insert(5, Sexp::list(vec![Sexp::atom("tag"), Sexp::atom("a")]));
            }),
        ),
        ("a tag twice", with_body(&|b| b.insert(5, b[4].clone()))),
        (
            "a tag covering another",
            with_body(&|b| {
                b.insert(
                    5,
                    Sexp::list(vec![Sexp::atom("tag"), Sexp::atom("a"), Sexp::atom("x")]),
                )
            }),
        ),
        (
            "17 tags",
            with_body(&|b| {
                b.remove(4);
                for i in (0..17).rev() {
                    b.insert(
                        4,
                        Sexp::list(vec![Sexp::atom("tag"), Sexp::atom(format!("t{i:02}"))]),
                    );
                }
            }),
        ),
        ("trailing byte", {
            let mut v = item.encode();
            v.push(b'0');
            v
        }),
        ("display hint", {
            let mut v = b"[1:x]".to_vec();
            v.extend(item.encode());
            v
        }),
    ];
    let mut out = String::from(
        "# Encodings that MUST be rejected (SPEC.md §5), each a mutation of the\n\
         # first, valid item. hex = the canonical-csexp bytes offered as one item.\n",
    );
    for (name, bytes) in &cases {
        let accepted = Item::decode(bytes).is_ok();
        assert_eq!(accepted, *name == "valid (for reference)", "{name}");
        let _ = write!(
            out,
            "\ncase = {name}\nresult = {}\nhex = {}\n",
            if accepted { "accept" } else { "reject" },
            hex(bytes)
        );
    }
    put(files, "items/rejections.txt", &out);
}
