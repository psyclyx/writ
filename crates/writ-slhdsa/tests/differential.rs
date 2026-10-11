//! Differential tests against RustCrypto `slh-dsa` (SLH-DSA-SHAKE-128s).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

mod common;

use common::Rng;
use slh_dsa::Shake128s;
use writ_slhdsa::{
    N, SIGNATURE_SIZE, SigningKey, VerifyingKey, keygen_internal, sign, sign_internal, verify,
    verify_internal,
};

type TheirSk = slh_dsa::SigningKey<Shake128s>;
type TheirVk = slh_dsa::VerifyingKey<Shake128s>;
type TheirSig = slh_dsa::Signature<Shake128s>;

/// A key pair made by both implementations from the same seeds, checked equal.
fn keypair(rng: &mut Rng) -> (SigningKey, TheirSk) {
    let (sk_seed, sk_prf, pk_seed) = (rng.array(), rng.array(), rng.array());
    let ours = keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let theirs = TheirSk::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    assert_eq!(ours.to_bytes().as_slice(), theirs.to_bytes().as_slice());
    let their_vk: &TheirVk = theirs.as_ref();
    assert_eq!(
        ours.verifying_key().as_bytes().as_slice(),
        their_vk.to_bytes().as_slice()
    );
    (ours, theirs)
}

fn their_sig(bytes: &[u8]) -> Option<TheirSig> {
    TheirSig::try_from(bytes).ok()
}

/// Flip one random bit in each of a few random positions; both must reject.
fn check_mutations(
    rng: &mut Rng,
    sig: &[u8; SIGNATURE_SIZE],
    ours: impl Fn(&[u8]) -> bool,
    theirs: impl Fn(&TheirSig) -> bool,
) {
    for _ in 0..8 {
        let mut bad = *sig;
        bad[rng.below(SIGNATURE_SIZE)] ^= 1 << rng.below(8);
        assert!(!ours(&bad));
        assert!(!theirs(&their_sig(&bad).unwrap()));
    }
}

#[test]
fn keygen_matches() {
    let mut rng = Rng::new(1);
    for _ in 0..6 {
        keypair(&mut rng);
    }
}

#[test]
fn sign_internal_matches() {
    let mut rng = Rng::new(2);
    for deterministic in [true, false] {
        let (sk, theirs) = keypair(&mut rng);
        let vk = sk.verifying_key();
        let their_vk: &TheirVk = theirs.as_ref();
        let msg = rng.bytes_below(300);
        let addrnd: [u8; N] = if deterministic {
            vk.as_bytes()[..N].try_into().unwrap()
        } else {
            rng.array()
        };

        let sig = sign_internal(&sk, &msg, &addrnd);
        let their = theirs.slh_sign_internal(&[&msg], Some(&addrnd));
        assert_eq!(sig.as_slice(), their.to_bytes().as_slice());
        if deterministic {
            // slh-dsa's own deterministic mode (opt_rand = None → PK.seed).
            let their_det = theirs.slh_sign_internal(&[&msg], None);
            assert_eq!(sig.as_slice(), their_det.to_bytes().as_slice());
        }

        // Cross-verification both ways.
        assert!(verify_internal(&vk, &msg, &their.to_bytes()));
        assert!(
            their_vk
                .slh_verify_internal(&[&msg], &their_sig(&sig).unwrap())
                .is_ok()
        );

        check_mutations(
            &mut rng,
            &sig,
            |s| verify_internal(&vk, &msg, s),
            |s| their_vk.slh_verify_internal(&[&msg], s).is_ok(),
        );
    }
}

#[test]
fn sign_with_context_matches() {
    let mut rng = Rng::new(3);
    for ctx_len in [0, 1 + rng.below(254), 255] {
        let (sk, theirs) = keypair(&mut rng);
        let vk = sk.verifying_key();
        let their_vk: &TheirVk = theirs.as_ref();
        let msg = rng.bytes_below(2000);
        let ctx = rng.bytes(ctx_len);
        let addrnd: [u8; N] = rng.array();

        let sig = sign(&sk, &msg, &ctx, &addrnd).unwrap();
        let their = theirs
            .try_sign_with_context(&msg, &ctx, Some(&addrnd))
            .unwrap();
        assert_eq!(sig.as_slice(), their.to_bytes().as_slice());

        assert!(verify(&vk, &msg, &ctx, &their.to_bytes()));
        assert!(
            their_vk
                .try_verify_with_context(&msg, &ctx, &their_sig(&sig).unwrap())
                .is_ok()
        );

        // A different context is a different message for both.
        let mut other_ctx = ctx.clone();
        other_ctx.push(0);
        assert!(!verify(&vk, &msg, &other_ctx, &sig));
        assert!(
            their_vk
                .try_verify_with_context(&msg, &other_ctx, &their)
                .is_err()
        );

        check_mutations(
            &mut rng,
            &sig,
            |s| verify(&vk, &msg, &ctx, s),
            |s| their_vk.try_verify_with_context(&msg, &ctx, s).is_ok(),
        );
    }
}

/// Verification agrees on random garbage under random keys (both reject).
#[test]
fn random_signatures_rejected_by_both() {
    let mut rng = Rng::new(4);
    for _ in 0..16 {
        let vk_bytes: [u8; 32] = rng.array();
        let vk = VerifyingKey::from_bytes(&vk_bytes);
        let their_vk = TheirVk::try_from(vk_bytes.as_slice()).unwrap();
        let msg = rng.bytes_below(64);
        let sig = rng.bytes(SIGNATURE_SIZE);
        assert!(!verify_internal(&vk, &msg, &sig));
        assert!(
            their_vk
                .slh_verify_internal(&[&msg], &their_sig(&sig).unwrap())
                .is_err()
        );
    }
}
