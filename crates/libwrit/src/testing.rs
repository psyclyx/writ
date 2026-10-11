//! Test helpers: a deterministic RNG, fake signers, and vector parsing.
//!
//! Fake signatures exist only in this crate's unit tests (`cfg(test)`): a
//! fake signature is `SHAKE256("writ/test/fake-sig" ‖ 0x00 ‖ key ‖ msg)`
//! at the suite's signature length, and `RootKey::verify` /
//! `LeafKey::verify` accept it in addition to real signatures. This makes
//! chain-semantics property tests fast; real signatures are covered by the
//! integration tests, which link the crate without `cfg(test)`.
#![allow(clippy::indexing_slicing)]

use crate::keys::{
    LEAF_SIGNATURE_SIZE, LeafKey, MLDSA65_PUBLIC_KEY_SIZE, PublicKey, ROOT_SIGNATURE_SIZE, Rng,
    RootKey, SignError, Signer,
};

/// A deterministic RNG: SHAKE256 of a seed and a counter.
pub struct TestRng {
    seed: u64,
    counter: u64,
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        TestRng { seed, counter: 0 }
    }
}

impl Rng for TestRng {
    fn fill(&mut self, out: &mut [u8]) {
        let mut input = [0u8; 16];
        input[..8].copy_from_slice(&self.seed.to_le_bytes());
        input[8..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        crate::hash::shake256_labelled("writ/test/rng", &input, out);
    }
}

fn fake_sig(key: &[u8], msg: &[u8], len: usize) -> Vec<u8> {
    let mut input = key.to_vec();
    input.extend_from_slice(msg);
    let mut out = vec![0u8; len];
    crate::hash::shake256_labelled("writ/test/fake-sig", &input, &mut out);
    out
}

/// Whether `sig` is the fake signature by `key` over `msg`.
pub fn fake_verify(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    !sig.is_empty() && fake_sig(key, msg, sig.len()) == sig
}

/// A root key that makes fake signatures.
#[derive(Clone, Copy)]
pub struct FakeRoot(pub RootKey);

impl FakeRoot {
    pub fn new(n: u8) -> Self {
        let mut pk = [0u8; 32];
        crate::hash::shake256_labelled("writ/test/root", &[n], &mut pk);
        FakeRoot(RootKey(pk))
    }
}

impl Signer for FakeRoot {
    fn public_key(&self) -> PublicKey {
        PublicKey::Root(self.0)
    }

    fn sign(&self, msg: &[u8], _: &mut dyn Rng) -> Result<Vec<u8>, SignError> {
        Ok(fake_sig(&self.0.0, msg, ROOT_SIGNATURE_SIZE))
    }
}

/// A leaf key that makes fake signatures.
#[derive(Clone)]
pub struct FakeLeaf(pub LeafKey);

impl FakeLeaf {
    pub fn new(n: u8) -> Self {
        let mut ed = [0u8; 32];
        crate::hash::shake256_labelled("writ/test/leaf", &[n], &mut ed);
        FakeLeaf(LeafKey {
            mldsa: Box::new([n; MLDSA65_PUBLIC_KEY_SIZE]),
            ed25519: ed,
        })
    }
}

impl Signer for FakeLeaf {
    fn public_key(&self) -> PublicKey {
        PublicKey::Leaf(self.0.clone())
    }

    fn sign(&self, msg: &[u8], _: &mut dyn Rng) -> Result<Vec<u8>, SignError> {
        Ok(fake_sig(&self.0.ed25519, msg, LEAF_SIGNATURE_SIZE))
    }
}

/// `(message, pub_key, signature)` from ed25519-speccheck's cases.json.
pub fn speccheck_cases(json: &str) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let field = |obj: &str, name: &str| -> Vec<u8> {
        let key = format!("\"{name}\":\"");
        let start = obj.find(&key).map(|i| i + key.len()).unwrap_or(0);
        let end = obj[start..].find('"').map(|i| start + i).unwrap_or(start);
        crate::hash::unhex(&obj[start..end]).unwrap_or_default()
    };
    json.split('}')
        .filter(|o| o.contains("pub_key"))
        .map(|o| {
            (
                field(o, "message"),
                field(o, "pub_key"),
                field(o, "signature"),
            )
        })
        .collect()
}
