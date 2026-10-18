//! Differential tests: the libcrux-ml-dsa calls the leaf suite makes,
//! against RustCrypto `ml-dsa`, an independent implementation of FIPS 204.
//!
//! Key generation and signing must agree byte for byte, each must accept
//! the other's signatures, and both must give the same answer on damaged
//! signatures, including in the hint and z encodings where libcrux has had
//! bugs (RUSTSEC-2026-0076, -0077, -0125).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use libcrux_ml_dsa::ml_dsa_65 as crux;
use ml_dsa::{B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey};

const SIG_LEN: usize = 3309;
/// The hint encoding is the last ω + k = 55 + 6 bytes of the signature.
const HINT: usize = SIG_LEN - 61;

/// A small deterministic generator (SplitMix64): reproducible inputs.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in &mut out {
            *b = self.next() as u8;
        }
        out
    }

    fn vec(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

struct Pair {
    crux: crux::MLDSA65KeyPair,
    theirs: SigningKey<MlDsa65>,
}

fn keys(xi: [u8; 32]) -> Pair {
    Pair {
        crux: crux::generate_key_pair(xi),
        theirs: SigningKey::<MlDsa65>::from_seed(&B32::from(xi)),
    }
}

fn crux_verify(p: &Pair, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; SIG_LEN]>::try_from(sig) else {
        return false;
    };
    crux::verify(
        &p.crux.verification_key,
        msg,
        ctx,
        &crux::MLDSA65Signature::new(sig),
    )
    .is_ok()
}

fn their_verify(p: &Pair, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&enc) else {
        return false;
    };
    p.theirs.verifying_key().verify_with_context(msg, ctx, &sig)
}

/// FIPS 204 Algorithm 2 with a given `rnd`: Sign_internal over
/// M' = 0 ‖ |ctx| ‖ ctx ‖ M.
fn their_sign(p: &Pair, msg: &[u8], ctx: &[u8], rnd: [u8; 32]) -> Vec<u8> {
    let prefix = [0u8, u8::try_from(ctx.len()).unwrap()];
    p.theirs
        .expanded_key()
        .sign_internal(&[&prefix, ctx, msg], &B32::from(rnd))
        .encode()
        .to_vec()
}

#[test]
fn key_generation_agrees() {
    let mut g = Gen(1);
    for _ in 0..32 {
        let p = keys(g.bytes());
        let theirs: EncodedVerifyingKey<MlDsa65> = p.theirs.verifying_key().encode();
        assert_eq!(p.crux.verification_key.as_slice(), theirs.as_slice());
    }
}

/// The leaf suite's own derivation (SPEC §4.2) gives the key RustCrypto
/// derives from the same ξ.
#[test]
fn leaf_keys_agree() {
    let mut g = Gen(2);
    for _ in 0..8 {
        let seed = g.bytes::<32>();
        let leaf = libwrit::Seed::from_bytes(seed).leaf();
        let mut okm = [0u8; 64];
        let msg = libwrit::labelled_message("writ/v1/keygen/mldsa65-ed25519", &seed);
        libcrux_sha3::shake256_ema(&mut okm, &msg);
        let xi: [u8; 32] = okm[..32].try_into().unwrap();
        let theirs = SigningKey::<MlDsa65>::from_seed(&B32::from(xi));
        assert_eq!(
            leaf.leaf_key().mldsa.as_slice(),
            theirs.verifying_key().encode().as_slice()
        );
    }
}

#[test]
fn signing_agrees_and_cross_verifies() {
    let mut g = Gen(3);
    for i in 0..48 {
        let p = keys(g.bytes());
        let msg = g.vec(300);
        let ctx = if i % 4 == 0 { Vec::new() } else { g.vec(255) };
        // Every fourth deterministic (rnd = 0), the rest hedged.
        let rnd = if i % 4 == 1 { [0; 32] } else { g.bytes() };
        let ours = crux::sign(&p.crux.signing_key, &msg, &ctx, rnd).unwrap();
        let theirs = their_sign(&p, &msg, &ctx, rnd);
        assert_eq!(ours.as_slice(), theirs.as_slice(), "case {i}");
        assert!(their_verify(&p, &msg, &ctx, ours.as_slice()), "case {i}");
        assert!(crux_verify(&p, &msg, &ctx, &theirs), "case {i}");
        // Wrong message or context: both refuse.
        let mut other = msg.clone();
        other.push(1);
        assert!(!crux_verify(&p, &other, &ctx, &theirs));
        assert!(!their_verify(&p, &other, &ctx, &theirs));
        if ctx.len() < 255 {
            let mut other_ctx = ctx.clone();
            other_ctx.push(0);
            assert!(!crux_verify(&p, &msg, &other_ctx, &theirs));
            assert!(!their_verify(&p, &msg, &other_ctx, &theirs));
        }
    }
}

/// Damaged signatures: both implementations give the same answer. Most
/// edits land in the hint (where an encoding can be invalid in several
/// ways) and in z (where the norm bound applies).
#[test]
fn damaged_signatures_agree() {
    let mut g = Gen(4);
    let p = keys(g.bytes());
    let msg = b"writ differential".to_vec();
    let ctx = b"writ/v1/leaf/mldsa65-ed25519".to_vec();
    let good = crux::sign(&p.crux.signing_key, &msg, &ctx, g.bytes()).unwrap();
    let good = good.as_slice().to_vec();
    let mut accepted = 0;
    for i in 0..3000 {
        let mut sig = good.clone();
        let edits = 1 + g.below(4);
        for _ in 0..edits {
            let at = match i % 3 {
                0 => HINT + g.below(61),
                1 => 48 + g.below(HINT - 48),
                _ => g.below(SIG_LEN),
            };
            sig[at] = match g.below(4) {
                0 => sig[at] ^ (1 << g.below(8)),
                1 => 0,
                2 => 0xff,
                _ => g.next() as u8,
            };
        }
        let ours = crux_verify(&p, &msg, &ctx, &sig);
        let theirs = their_verify(&p, &msg, &ctx, &sig);
        assert_eq!(
            ours, theirs,
            "edit {i}: libcrux {ours}, RustCrypto {theirs}"
        );
        accepted += usize::from(ours);
    }
    // Edits that change nothing (writing a byte's own value) still verify;
    // nearly every other edit must be rejected.
    assert!(
        accepted < 300,
        "{accepted} of 3000 damaged signatures verified"
    );
}
