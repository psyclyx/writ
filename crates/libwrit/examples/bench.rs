//! Timings for BENCHMARKS.md: `cargo run --release -p libwrit --example bench`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use libwrit::*;
use std::time::{Duration, Instant};

struct Rand(u64);

impl Rng for Rand {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
    }
}

fn median(mut f: impl FnMut(), runs: usize) -> Duration {
    f();
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    times.sort();
    times[runs / 2]
}

fn main() {
    let mut rng = Rand(0x9e37_79b9_7f4a_7c15);
    let seed = Seed::from_bytes([1; 32]);
    println!("| operation | median |\n| --- | ---: |");
    let row = |name: &str, d: Duration| println!("| {name} | {d:.2?} |");

    row(
        "root key derivation (seed → SLH-DSA keys)",
        median(|| drop(seed.root()), 11),
    );
    row(
        "leaf key derivation (seed → ML-DSA-65 + Ed25519)",
        median(|| drop(seed.leaf()), 101),
    );
    let leaf = seed.leaf();
    let msg = b"writ/v1/sig\0(signature ...)";
    let sig = leaf.sign(msg, &mut rng).unwrap();
    row(
        "leaf sign (composite, with self-check)",
        median(|| drop(leaf.sign(msg, &mut rng).unwrap()), 101),
    );
    row(
        "leaf verify (both components, strict Ed25519)",
        median(|| assert!(leaf.leaf_key().verify(msg, &sig)), 1001),
    );

    // A three-grant chain: root → a (delegate) → b (delegate) → leaf.
    let keys: Vec<_> = (0..3u8)
        .map(|i| {
            (
                Seed::from_bytes([10 + i; 32]).root(),
                Seed::from_bytes([20 + i; 32]).root(),
            )
        })
        .collect();
    let mut m = Material::new();
    let mut ids = Vec::new();
    for (k, next) in &keys {
        let (id, ev) = incept(
            Authority::single(k.root_key()),
            &Authority::single(next.root_key()),
            None,
            &[k],
            &mut rng,
        )
        .unwrap();
        m.add(Item::Event(ev));
        ids.push(id);
    }
    let now = 1_800_000_000;
    let mut say =
        |i: usize, subject: Subject, delegate: bool, expires: Option<Time>, m: &mut Material| {
            let log = m.log(&ids[i]).as_ref().clone().unwrap();
            let st = issue(
                Statement {
                    issuer: Issuer::Identity {
                        id: ids[i],
                        event: 0,
                    },
                    issued: now,
                    expires,
                    note: None,
                    claim: Claim::Grant {
                        subject,
                        tags: Tags::one(Tag::parse("(svc)").unwrap()),
                        delegate,
                    },
                },
                &log,
                &[&keys[i].0],
                &mut rng,
            )
            .unwrap();
            m.add(Item::Statement(st));
        };
    say(0, Subject::Id(ids[1]), true, None, &mut m);
    say(1, Subject::Id(ids[2]), true, None, &mut m);
    say(
        2,
        Subject::Leaf(leaf.leaf_key().clone()),
        false,
        Some(now + 3600),
        &mut m,
    );
    let roots = [ids[0]];
    let policy = Policy::default();
    let holder = Holder::Leaf(leaf.leaf_key().clone());
    let tag = Tag::parse("(svc x)").unwrap();
    let bytes: Vec<u8> = (0..3)
        .flat_map(|i| {
            m.log(&ids[i])
                .as_ref()
                .as_ref()
                .unwrap()
                .items()
                .collect::<Vec<_>>()
        })
        .chain(m.statements().map(|(_, s)| Item::Statement(s.clone())))
        .flat_map(|i| i.encode())
        .collect();
    row(
        "check, 3-grant chain, cold (decode bundle, verify 3 logs + 3 grants)",
        median(
            || {
                let mut fresh = Material::new();
                fresh.add_bundle(&bytes).unwrap();
                Verifier::new(&roots, &fresh, &policy)
                    .check(&holder, &tag, now + 10)
                    .unwrap();
            },
            21,
        ),
    );
    let v = Verifier::new(&roots, &m, &policy);
    v.check(&holder, &tag, now + 10).unwrap();
    row(
        "check, same chain, signatures cached",
        median(|| drop(v.check(&holder, &tag, now + 10).unwrap()), 1001),
    );
}
