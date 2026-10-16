//! NIST ACVP vectors for ML-DSA-65 (vendored in vectors/acvp/), run against
//! the libcrux-ml-dsa entry points the leaf suite uses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

// The vector parser shared with writ-slhdsa's ACVP tests (same file format).
#[path = "../../writ-slhdsa/tests/common/mod.rs"]
mod common;

use common::{Case, parse};
use libcrux_ml_dsa::ml_dsa_65::{
    MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey, generate_key_pair, sign, verify,
};

const KEYGEN: &str = include_str!("../../../vectors/acvp/ml-dsa-65-keygen.txt");
const SIGGEN: &str = include_str!("../../../vectors/acvp/ml-dsa-65-siggen.txt");
const SIGVER: &str = include_str!("../../../vectors/acvp/ml-dsa-65-sigver.txt");

#[test]
fn keygen() {
    let cases = parse(KEYGEN);
    assert_eq!(cases.len(), 10);
    for c in &cases {
        let kp = generate_key_pair(c.arr("seed"));
        assert!(
            kp.verification_key.as_slice() == c.hex("pk").as_slice(),
            "pk mismatch: {}",
            c.id()
        );
        assert!(
            kp.signing_key.as_slice() == c.hex("sk").as_slice(),
            "sk mismatch: {}",
            c.id()
        );
    }
}

#[test]
fn siggen_count() {
    assert_eq!(parse(SIGGEN).len(), 8);
}

#[test]
fn siggen_deterministic() {
    siggen("true");
}

#[test]
fn siggen_hedged() {
    siggen("false");
}

/// Run the sigGen cases of one kind. Deterministic signing is hedged signing
/// with rnd = 0^32 (FIPS 204 Algorithm 2).
fn siggen(deterministic: &str) {
    let cases: Vec<Case> = parse(SIGGEN)
        .into_iter()
        .filter(|c| c.str("deterministic") == deterministic)
        .collect();
    assert_eq!(cases.len(), 4);
    for c in &cases {
        let sk = MLDSA65SigningKey::new(c.arr("sk"));
        let vk = MLDSA65VerificationKey::new(c.arr("pk"));
        let rnd: [u8; 32] = match deterministic {
            "true" => {
                assert!(c.get("rnd").is_none(), "{}", c.id());
                [0; 32]
            }
            _ => c.arr("rnd"),
        };
        let msg = c.hex("message");
        let ctx = c.hex("context");
        let sig = sign(&sk, &msg, &ctx, rnd).expect("sign");
        assert!(verify(&vk, &msg, &ctx, &sig).is_ok(), "{}", c.id());
        assert!(
            sig.as_slice() == c.hex("signature").as_slice(),
            "signature mismatch: {}",
            c.id()
        );
    }
}

#[test]
fn sigver() {
    let cases = parse(SIGVER);
    assert_eq!(cases.len(), 9);
    let mut passed = 0;
    for c in &cases {
        let vk = MLDSA65VerificationKey::new(c.arr("pk"));
        let sig = MLDSA65Signature::new(c.arr("signature"));
        let expected = match c.str("testPassed") {
            "true" => true,
            "false" => false,
            other => panic!("bad testPassed {other}"),
        };
        let got = verify(&vk, &c.hex("message"), &c.hex("context"), &sig).is_ok();
        assert_eq!(got, expected, "{} ({})", c.id(), c.str("reason"));
        passed += usize::from(got);
    }
    assert_eq!(passed, 3);
}
