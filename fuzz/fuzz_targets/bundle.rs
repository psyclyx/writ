//! Bundles: every item that decodes re-encodes to itself, armored and
//! binary bundles agree, and verifying the material never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libwrit::{Holder, Item, Material, Policy, Tag, Verifier};

fuzz_target!(|data: &[u8]| {
    let Ok(items) = Item::decode_bundle(data) else {
        return;
    };
    for item in &items {
        assert_eq!(Item::decode(&item.encode()).as_ref(), Ok(item));
    }
    let armored: String = items.iter().map(Item::armor).collect();
    assert_eq!(Item::decode_bundle(armored.as_bytes()).as_ref(), Ok(&items));
    let binary: Vec<u8> = items.iter().flat_map(Item::encode).collect();
    assert_eq!(Item::decode_bundle(&binary).as_ref(), Ok(&items));

    let material = Material::from_items(items);
    let ids: Vec<_> = material.ids().copied().collect();
    let Some(root) = ids.first() else {
        return;
    };
    let roots = [*root];
    let policy = Policy::default();
    let v = Verifier::new(&roots, &material, &policy);
    let _ = v.time_witness();
    for id in &ids {
        let _ = v.check(&Holder::Id(*id), &Tag::everything(), 1_800_000_000);
    }
});
