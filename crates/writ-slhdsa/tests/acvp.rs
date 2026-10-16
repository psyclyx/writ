//! NIST ACVP vectors for SLH-DSA-SHAKE-128s (vendored in vectors/acvp/).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::{Case, parse};
use writ_slhdsa::{
    SigningKey, VerifyingKey, keygen_internal, sign, sign_internal, verify, verify_internal,
};

const KEYGEN: &str = include_str!("../../../vectors/acvp/slh-dsa-shake-128s-keygen.txt");
const SIGGEN: &str = include_str!("../../../vectors/acvp/slh-dsa-shake-128s-siggen.txt");
const SIGVER: &str = include_str!("../../../vectors/acvp/slh-dsa-shake-128s-sigver.txt");

#[test]
fn keygen() {
    let cases = parse(KEYGEN);
    assert_eq!(cases.len(), 10);
    for c in &cases {
        let sk = keygen_internal(&c.arr("skSeed"), &c.arr("skPrf"), &c.arr("pkSeed"));
        assert_eq!(sk.to_bytes().to_vec(), c.hex("sk"), "{}", c.id());
        assert_eq!(
            sk.verifying_key().to_bytes().to_vec(),
            c.hex("pk"),
            "{}",
            c.id()
        );
    }
}

/// opt_rand: the given additionalRandomness (hedged) or PK.seed (deterministic).
fn addrnd(c: &Case, sk: &SigningKey) -> [u8; 16] {
    match c.str("deterministic") {
        "true" => {
            assert!(c.get("additionalRandomness").is_none());
            sk.verifying_key().as_bytes()[..16].try_into().unwrap()
        }
        "false" => c.arr("additionalRandomness"),
        other => panic!("bad deterministic flag {other}"),
    }
}

#[test]
fn siggen_count() {
    assert_eq!(parse(SIGGEN).len(), 28);
}

#[test]
fn siggen_internal_deterministic() {
    siggen("internal", "true");
}

#[test]
fn siggen_internal_hedged() {
    siggen("internal", "false");
}

#[test]
fn siggen_external_pure_deterministic() {
    siggen("external", "true");
}

#[test]
fn siggen_external_pure_hedged() {
    siggen("external", "false");
}

/// Run the sigGen cases of one configuration (split so they run in parallel).
fn siggen(interface: &str, deterministic: &str) {
    let cases: Vec<Case> = parse(SIGGEN)
        .into_iter()
        .filter(|c| c.str("interface") == interface && c.str("deterministic") == deterministic)
        .collect();
    assert_eq!(cases.len(), 7);
    for c in &cases {
        let sk = SigningKey::from_bytes(&c.arr("sk"));
        let pk = VerifyingKey::from_bytes(&c.arr("pk"));
        assert_eq!(sk.verifying_key(), pk, "{}", c.id());
        let rnd = addrnd(c, &sk);
        let msg = c.hex("message");
        let expected = c.hex("signature");
        let sig = match c.str("interface") {
            "internal" => {
                let sig = sign_internal(&sk, &msg, &rnd).unwrap();
                assert!(verify_internal(&pk, &msg, &sig), "{}", c.id());
                sig
            }
            "external" => {
                let ctx = c.hex("context");
                let sig = sign(&sk, &msg, &ctx, &rnd).expect("sign");
                assert!(verify(&pk, &msg, &ctx, &sig), "{}", c.id());
                sig
            }
            other => panic!("bad interface {other}"),
        };
        assert!(
            sig.as_slice() == expected.as_slice(),
            "signature mismatch: {}",
            c.id()
        );
    }
}

#[test]
fn sigver() {
    let cases = parse(SIGVER);
    assert_eq!(cases.len(), 28);
    let mut passed = 0;
    for c in &cases {
        let pk = VerifyingKey::from_bytes(&c.arr("pk"));
        let msg = c.hex("message");
        let sig = c.hex("signature");
        let expected = match c.str("testPassed") {
            "true" => true,
            "false" => false,
            other => panic!("bad testPassed {other}"),
        };
        let got = match c.str("interface") {
            "internal" => verify_internal(&pk, &msg, &sig),
            "external" => verify(&pk, &msg, &c.hex("context"), &sig),
            other => panic!("bad interface {other}"),
        };
        assert_eq!(got, expected, "{} ({})", c.id(), c.str("reason"));
        passed += usize::from(got);
    }
    assert_eq!(passed, 4);
}
