//! End-to-end with real SLH-DSA and ML-DSA-65+Ed25519 signatures (the unit
//! tests use fake signers for speed).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use libwrit::*;

struct SeqRng(u8);

impl Rng for SeqRng {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *b = self.0;
        }
    }
}

fn seed(n: u8) -> Seed {
    Seed::from_bytes([n; 32])
}

#[test]
fn identity_leaf_and_rotation() {
    let mut rng = SeqRng(1);
    let warm = seed(1).root();
    let cold = seed(2).root();
    let cold2 = seed(3).root();
    let (id, inception) = incept(
        Authority::single(warm.root_key()),
        &Authority::single(cold.root_key()),
        None,
        &[&warm],
        &mut rng,
    )
    .unwrap();
    let mut material = Material::new();
    material.add(Item::Event(inception.clone()));
    let log = material.log(&id).as_ref().clone().unwrap();

    // A leaf key with a day-long grant, signing data.
    let leaf = seed(9).leaf();
    let tag = Tag::parse("(release)").unwrap();
    let now = 1_800_000_000;
    let grant = issue(
        Statement {
            issuer: Issuer::Identity { id, event: 0 },
            issued: now,
            expires: Some(now + 86_400),
            note: Some("build machine".into()),
            claim: Claim::Grant {
                subject: Subject::Leaf(leaf.leaf_key().clone()),
                tag: tag.clone(),
                delegate: false,
            },
        },
        &log,
        &[&warm],
        &mut rng,
    )
    .unwrap();
    let data = Hash::of_data(b"release tarball");
    let sig = sign_data_leaf(data, b"example/release/v1", now + 10, &leaf, &mut rng).unwrap();

    // Ship everything as armor and verify from the decoded bundle.
    let bundle: String = [
        Item::Event(inception.clone()),
        Item::Statement(grant.clone()),
    ]
    .iter()
    .map(Item::armor)
    .collect();
    let mut fresh = Material::new();
    assert_eq!(fresh.add_bundle(bundle.as_bytes()), Ok(2));
    let sig = match Item::decode_bundle(Item::Signature(sig).armor().as_bytes())
        .unwrap()
        .pop()
    {
        Some(Item::Signature(s)) => s,
        other => panic!("{other:?}"),
    };
    let roots = [id];
    let policy = Policy::default();
    let v = Verifier::new(&roots, &fresh, &policy);
    let proof = v
        .verify(&sig, &data, b"example/release/v1", &tag, now + 20)
        .unwrap();
    assert_eq!(proof.expires, Some(now + 86_400));
    assert_eq!(
        v.verify(&sig, &data, b"example/release/v1", &tag, now + 86_400),
        Err(Denial::NotFound {
            rejected: vec![Rejection {
                statement: grant.body.hash(),
                reason: Reason::Expired(now + 86_400)
            }]
        })
    );
    let mut forged = sig.clone();
    forged.sigs[0].bytes[3300] ^= 1; // inside the ML-DSA part
    assert_eq!(
        v.verify(&forged, &data, b"example/release/v1", &tag, now + 20),
        Err(Denial::Signature(Reason::BadSignature))
    );
    let mut forged = sig.clone();
    let last = forged.sigs[0].bytes.len() - 1;
    forged.sigs[0].bytes[last] ^= 1; // inside the Ed25519 part
    assert_eq!(
        v.verify(&forged, &data, b"example/release/v1", &tag, now + 20),
        Err(Denial::Signature(Reason::BadSignature))
    );

    // Rotate: reveal the cold key, keep nothing; the leaf grant dies.
    let rotation = rotate(
        &log,
        Authority::single(cold.root_key()),
        &Authority::single(cold2.root_key()),
        None,
        vec![],
        &[&cold],
        &mut rng,
    )
    .unwrap();
    // The warm key can't rotate.
    assert_eq!(
        rotate(
            &log,
            Authority::single(warm.root_key()),
            &Authority::single(cold2.root_key()),
            None,
            vec![],
            &[&warm],
            &mut rng,
        ),
        Err(IssueError::WrongNext)
    );
    fresh.add(Item::Event(rotation));
    let v = Verifier::new(&roots, &fresh, &policy);
    assert!(
        v.verify(&sig, &data, b"example/release/v1", &tag, now + 20)
            .is_err()
    );
    assert_eq!(fresh.log(&id).as_ref().as_ref().unwrap().head_n(), 1);
}

#[test]
fn two_of_two_inception() {
    let mut rng = SeqRng(2);
    let a = seed(11).root();
    let b = seed(12).root();
    let next = seed(13).root();
    let authority = Authority::new(2, vec![a.root_key(), b.root_key()]).unwrap();
    let (id, ev) = incept(
        authority.clone(),
        &Authority::single(next.root_key()),
        Some(3600),
        &[&a, &b],
        &mut rng,
    )
    .unwrap();
    let bytes = Item::Event(ev.clone()).encode();
    let Item::Event(decoded) = Item::decode(&bytes).unwrap() else {
        panic!()
    };
    assert!(decoded.verify_threshold(&authority));
    let mut one = decoded.clone();
    one.sigs.truncate(1);
    assert!(!one.verify_threshold(&authority));
    let m = Material::from_items([Item::Event(one)]);
    assert_eq!(
        m.log(&id).as_ref().as_ref().err(),
        Some(&LogError::BadSignature { n: 0 })
    );
}
