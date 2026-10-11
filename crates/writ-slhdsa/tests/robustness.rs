//! Negative and robustness tests for the public API.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

mod common;

use common::Rng;
use writ_slhdsa::{
    Error, N, SECRET_KEY_SIZE, SIGNATURE_SIZE, SigningKey, VerifyingKey, keygen_internal, sign,
    verify, verify_internal,
};

/// Signature layout in n-byte nodes (FIPS 205 Fig. 17).
const R_NODES: usize = 1;
const FORS_TREES: usize = 14;
const FORS_TREE_NODES: usize = 1 + 12;
const HT_LAYERS: usize = 7;
const HT_LAYER_NODES: usize = 35 + 9;

fn fixture() -> (SigningKey, Vec<u8>, Vec<u8>, [u8; SIGNATURE_SIZE]) {
    let mut rng = Rng::new(42);
    let sk = keygen_internal(&rng.array(), &rng.array(), &rng.array());
    let msg = rng.bytes(100);
    let ctx = rng.bytes(255);
    let sig = sign(&sk, &msg, &ctx, &rng.array()).unwrap();
    (sk, msg, ctx, sig)
}

#[test]
fn signature_layout_constants() {
    assert_eq!(
        (R_NODES + FORS_TREES * FORS_TREE_NODES + HT_LAYERS * HT_LAYER_NODES) * N,
        SIGNATURE_SIZE
    );
}

#[test]
fn sign_verify_and_rejections() {
    let (sk, msg, ctx, sig) = fixture();
    let vk = sk.verifying_key();
    assert!(verify(&vk, &msg, &ctx, &sig));

    // Domain separation: an external signature is not an internal one, and
    // context, message and key are all bound.
    assert!(!verify_internal(&vk, &msg, &sig));
    assert!(!verify(&vk, &msg, &ctx[1..], &sig));
    assert!(!verify(&vk, &msg, b"", &sig));
    assert!(!verify(&vk, &msg[1..], &ctx, &sig));
    let mut other_vk = vk.to_bytes();
    other_vk[31] ^= 1;
    assert!(!verify(
        &VerifyingKey::from_bytes(&other_vk),
        &msg,
        &ctx,
        &sig
    ));
    other_vk = vk.to_bytes();
    other_vk[0] ^= 1;
    assert!(!verify(
        &VerifyingKey::from_bytes(&other_vk),
        &msg,
        &ctx,
        &sig
    ));

    // Wrong lengths, including the valid signature truncated or extended.
    for len in [
        0,
        1,
        N,
        SIGNATURE_SIZE - 1,
        SIGNATURE_SIZE + 1,
        2 * SIGNATURE_SIZE,
    ] {
        let mut s = sig.to_vec();
        s.resize(len, 0);
        assert!(!verify(&vk, &msg, &ctx, &s), "len {len}");
        assert!(!verify_internal(&vk, &msg, &s), "len {len}");
    }

    // Context too long.
    let long = vec![0u8; 256];
    assert_eq!(sign(&sk, &msg, &long, &[0; N]), Err(Error::ContextTooLong));
    assert!(!verify(&vk, &msg, &long, &sig));
}

/// One bit flipped in every node of the signature — R, every FORS secret
/// and auth node, every WOTS+ chain and XMSS auth node of every layer — is
/// rejected.
#[test]
fn every_node_bit_flip_rejected() {
    let (sk, msg, ctx, sig) = fixture();
    let vk = sk.verifying_key();
    let mut rng = Rng::new(7);
    let mut regions = [0usize; 3];
    for node in 0..SIGNATURE_SIZE / N {
        let mut bad = sig;
        bad[node * N + rng.below(N)] ^= 1 << rng.below(8);
        assert!(!verify(&vk, &msg, &ctx, &bad), "node {node}");
        let region = if node < R_NODES {
            0
        } else if node < R_NODES + FORS_TREES * FORS_TREE_NODES {
            1
        } else {
            2
        };
        regions[region] += 1;
    }
    assert_eq!(
        regions,
        [
            R_NODES,
            FORS_TREES * FORS_TREE_NODES,
            HT_LAYERS * HT_LAYER_NODES
        ]
    );
}

#[test]
fn key_encodings() {
    let mut rng = Rng::new(9);
    let sk = keygen_internal(&rng.array(), &rng.array(), &rng.array());
    let bytes: [u8; SECRET_KEY_SIZE] = sk.to_bytes();
    let sk2 = SigningKey::from_bytes(&bytes);
    assert_eq!(sk2.to_bytes(), bytes);
    assert_eq!(sk2.verifying_key(), sk.verifying_key());
    assert_eq!(&bytes[32..], sk.verifying_key().as_bytes());
    let vk = VerifyingKey::from_bytes(sk.verifying_key().as_bytes());
    assert_eq!(vk.to_bytes(), *sk.verifying_key().as_bytes());
    assert_eq!(format!("{sk:?}"), "SigningKey(..)");
}
