//! Property tests in the spirit of fuzzing: decoding is total on arbitrary
//! and mutated input, and anything accepted is canonical.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::scenarios::{Ident, grant, name, path};
use crate::testing::{FakeLeaf, TestRng};
use crate::*;
use proptest::prelude::*;

fn seeds() -> Vec<Vec<u8>> {
    let a = Ident::new(1);
    let b = Ident::new(2);
    let leaf = FakeLeaf::new(3);
    let mut items = vec![
        Item::Statement(a.say(grant(Subject::Id(b.id), "(x y)", true), 5, Some(9))),
        Item::Statement(a.say(name("n", path(b.id, &["m", "o"])), 5, None)),
        Item::Statement(a.say(
            Claim::Revoke {
                target: Hash([3; 32]),
            },
            5,
            None,
        )),
        Item::Signature(
            sign_data_leaf(Hash([4; 32]), b"ctx", 1, &leaf, &mut TestRng::new(0)).unwrap(),
        ),
        Item::PublicKey(PublicKey::Leaf(leaf.0.clone())),
        Item::Authority(Authority::single(a.keys[0].0)),
    ];
    items.extend(a.items());
    items.iter().map(Item::encode).collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = Item::decode(&bytes);
        let _ = Item::decode_bundle(&bytes);
    }

    #[test]
    fn mutated_items(
        which in any::<prop::sample::Index>(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0..3u8), 1..4),
    ) {
        let all = seeds();
        let mut bytes = all[which.index(all.len())].clone();
        for (at, b, op) in edits {
            let i = at.index(bytes.len().max(1));
            match op {
                0 if !bytes.is_empty() => {
                    let j = i.min(bytes.len() - 1);
                    bytes[j] = b;
                }
                1 => bytes.insert(i.min(bytes.len()), b),
                _ if !bytes.is_empty() => { bytes.remove(i.min(bytes.len() - 1)); }
                _ => {}
            }
        }
        if let Ok(item) = Item::decode(&bytes) {
            prop_assert_eq!(item.encode(), bytes.clone());
        }
        if let Ok(items) = Item::decode_bundle(&bytes) {
            let again: Vec<u8> = items.iter().flat_map(Item::encode).collect();
            prop_assert_eq!(again, bytes);
        }
    }

    /// Whatever decodes can be added to material and queried without panicking.
    #[test]
    fn mutated_material_is_safe(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<prop::sample::Index>(), any::<u8>()), 0..6),
        now in 0..20u64,
    ) {
        let mut all = seeds();
        for (which, at, b) in flips {
            let item = which.index(all.len());
            let i = at.index(all[item].len());
            all[item][i] = b;
        }
        let mut m = Material::new();
        for bytes in &all {
            if let Ok(item) = Item::decode(bytes) {
                m.add(item);
            }
        }
        let a = Ident::new(1);
        let b = Ident::new(2);
        let roots = [a.id];
        let policy = Policy::default();
        let v = Verifier::new(&roots, &m, &policy);
        let _ = v.check(&Holder::Id(b.id), &Tag::parse("(x)").unwrap(), now);
        let _ = v.resolve(&NamePath { base: a.id, names: vec![b"n".to_vec()] }, now);
        let _ = v.time_witness();
    }
}
