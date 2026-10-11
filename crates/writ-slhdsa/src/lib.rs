//! SLH-DSA-SHAKE-128s (FIPS 205), and only that parameter set.
//!
//! See DESIGN.md §3. Built on `libcrux-sha3`.
//!
//! - [`keygen_internal`], `sign_internal`, [`verify_internal`] are
//!   FIPS 205 Algs. 18–20, exposed for test vectors and composition.
//! - [`sign`] and [`verify`] are the pure (non-prehash) external interface,
//!   Algs. 22 and 24, with a context string. [`sign`] is hedged (the caller
//!   supplies fresh randomness) and verifies its own output before returning
//!   it.
//!
//! Constant-time discipline: the secret seeds (SK.seed, SK.prf) only ever
//! enter hash inputs. Every branch and index depends only on public data —
//! the message digest, which selects the FORS leaves and the hypertree path.
//! Note that the digest is computed from R = PRF_msg(SK.prf, ...), which is
//! published as part of the signature.

#![cfg_attr(not(test), no_std)]

mod address;
mod fors;
mod hash;
mod signature;
mod tree;
mod wots;
mod xmss;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::address::{Adrs, AdrsType};
use crate::hash::{Hasher, Pieces};
use crate::signature::Signature;

/// Security parameter n: bytes per hash output, seed, and signature node.
pub const N: usize = 16;
/// Encoded public key size: PK.seed ‖ PK.root.
pub const PUBLIC_KEY_SIZE: usize = 2 * N;
/// Encoded secret key size: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root.
pub const SECRET_KEY_SIZE: usize = 4 * N;
/// Signature size: R ‖ SIG_FORS ‖ SIG_HT.
pub const SIGNATURE_SIZE: usize = 7856;

/// Hypertree layers d.
const D: usize = 7;
/// Height h' of each XMSS tree (total height h = d·h' = 63).
const HP: usize = 9;
/// FORS tree height a.
const A: usize = 12;
/// Number of FORS trees k.
const K: usize = 14;
/// Winternitz parameter w = 2^lg_w, lg_w = 4.
const W: u32 = 16;
/// WOTS+ chains: len1 = 32 message digits + len2 = 3 checksum digits.
const LEN: usize = 35;
/// Message digest length m.
const M: usize = 30;
/// Bytes of the digest that select FORS leaves: ceil(k·a / 8).
const MD_BYTES: usize = 21;

/// An n-byte value: a seed, hash output, or signature node.
type Node = [u8; N];

/// An SLH-DSA-SHAKE-128s signing key: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root.
///
/// The secret seeds are wiped when the key is dropped. `Debug` does not print
/// key material.
pub struct SigningKey {
    sk_seed: Node,
    sk_prf: Node,
    pk_seed: Node,
    pk_root: Node,
}

impl SigningKey {
    /// Decode a signing key. FIPS 205 defines no validation beyond the length
    /// (in particular, PK.root is not recomputed).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Self {
        // Copy straight into the fields, leaving no intermediate copies.
        let mut sk = Self {
            sk_seed: [0; N],
            sk_prf: [0; N],
            pk_seed: [0; N],
            pk_root: [0; N],
        };
        let fields = [
            &mut sk.sk_seed,
            &mut sk.sk_prf,
            &mut sk.pk_seed,
            &mut sk.pk_root,
        ];
        for (dst, src) in fields.into_iter().zip(bytes.as_chunks::<N>().0) {
            dst.copy_from_slice(src);
        }
        sk
    }

    /// Encode the signing key. The result is secret and is wiped when
    /// dropped.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        let mut out = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        let fields = [&self.sk_seed, &self.sk_prf, &self.pk_seed, &self.pk_root];
        for (dst, src) in out.as_chunks_mut::<N>().0.iter_mut().zip(fields) {
            dst.copy_from_slice(src);
        }
        out
    }

    /// The matching verifying key (PK.seed ‖ PK.root).
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_parts(&self.pk_seed, &self.pk_root)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}

impl ZeroizeOnDrop for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// An SLH-DSA-SHAKE-128s verifying (public) key: PK.seed ‖ PK.root.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerifyingKey([u8; PUBLIC_KEY_SIZE]);

impl VerifyingKey {
    /// Decode a verifying key. Any 32 bytes are a valid encoding.
    #[must_use]
    pub const fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Encode the verifying key.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }

    /// The encoded verifying key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    fn from_parts(pk_seed: &Node, pk_root: &Node) -> Self {
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out[..N].copy_from_slice(pk_seed);
        out[N..].copy_from_slice(pk_root);
        Self(out)
    }

    /// (PK.seed, PK.root).
    fn parts(&self) -> (Node, Node) {
        let mut parts = [[0u8; N]; 2];
        copy_nodes(&mut parts, &self.0);
        let [pk_seed, pk_root] = parts;
        (pk_seed, pk_root)
    }
}

/// Copy consecutive n-byte chunks of `src` into `dst`.
fn copy_nodes(dst: &mut [Node], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.as_chunks::<N>().0) {
        *d = *s;
    }
}

/// Errors from [`sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// The freshly made signature did not verify (a fault occurred while
    /// signing); it has been discarded.
    SelfVerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContextTooLong => "SLH-DSA context string longer than 255 bytes",
            Self::SelfVerificationFailed => "SLH-DSA signature failed self-verification",
        })
    }
}

impl core::error::Error for Error {}

/// Bytes of stack overwritten by [`scrub_stack`]. Measured with temporary
/// instrumentation (x86_64, debug and release profiles): the deepest
/// hash-function frame under [`sign`] lies about 18 KiB below the top of the
/// scrub frame, and libcrux's Keccak frames lie below that. 32 KiB covers
/// them with margin; the cost is negligible next to signing.
const SCRUB_BYTES: usize = 32 * 1024;

/// Best-effort wipe of the dead stack below the caller's frame.
///
/// libcrux's `Shake256Xof` buffers and the portable Keccak `load_last` block
/// copies leave SK.seed- and SK.prf-derived state in callee frames that we
/// cannot wipe directly (`unsafe` is forbidden). Instead this function claims
/// a frame at least as deep as those callees used and overwrites it.
/// `zeroize` uses volatile writes, so the wipe is not elided; `inline(never)`
/// puts the array in its own frame below the caller's; `black_box` keeps it
/// materialised. This is not a guarantee — copies spilled into the caller's
/// own frame or left in registers are not reached — but it clears the bulk of
/// the residue.
#[inline(never)]
fn scrub_stack() {
    let mut s = [0u8; SCRUB_BYTES];
    s.zeroize();
    core::hint::black_box(&s);
}

/// FIPS 205 Alg. 18 `slh_keygen_internal`.
#[must_use]
pub fn keygen_internal(sk_seed: &[u8; N], sk_prf: &[u8; N], pk_seed: &[u8; N]) -> SigningKey {
    let h = Hasher::new(pk_seed);
    let pk_root = xmss::top_root(&h, sk_seed);
    scrub_stack();
    SigningKey {
        sk_seed: *sk_seed,
        sk_prf: *sk_prf,
        pk_seed: *pk_seed,
        pk_root,
    }
}

/// Split `H_msg` output into (md, idx_tree, idx_leaf) (Alg. 19 lines 7–12).
fn split_digest(digest: [u8; M]) -> ([u8; MD_BYTES], u64, u32) {
    let [md @ .., t0, t1, t2, t3, t4, t5, t6, l0, l1] = digest;
    let idx_tree = u64::from_be_bytes([0, t0, t1, t2, t3, t4, t5, t6]) & ((1 << (D * HP - HP)) - 1);
    let idx_leaf = u32::from(u16::from_be_bytes([l0, l1])) & ((1 << HP) - 1);
    (md, idx_tree, idx_leaf)
}

/// The FORS address for the digest-selected key pair (Alg. 19 lines 13–15).
fn fors_adrs(idx_tree: u64, idx_leaf: u32) -> Adrs {
    let mut adrs = Adrs::zero();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(AdrsType::ForsTree);
    adrs.set_key_pair(idx_leaf);
    adrs
}

fn sign_pieces(sk: &SigningKey, msg: &Pieces<'_>, addrnd: &Node) -> Signature {
    let h = Hasher::new(&sk.pk_seed);
    let mut sig = Signature::zero();
    sig.r = hash::prf_msg(&sk.sk_prf, addrnd, msg);
    let digest = hash::h_msg(&sig.r, &sk.pk_seed, &sk.pk_root, msg);
    let (md, idx_tree, idx_leaf) = split_digest(digest);
    let adrs = fors_adrs(idx_tree, idx_leaf);
    let pk_fors = fors::sign(&h, &md, &sk.sk_seed, &adrs, &mut sig.fors);
    xmss::ht_sign(&h, &pk_fors, &sk.sk_seed, idx_tree, idx_leaf, &mut sig.ht);
    sig
}

fn verify_pieces(pk: &VerifyingKey, msg: &Pieces<'_>, sig: &[u8]) -> bool {
    let Ok(sig) = <&[u8; SIGNATURE_SIZE]>::try_from(sig) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    let (pk_seed, pk_root) = pk.parts();
    let h = Hasher::new(&pk_seed);
    let digest = hash::h_msg(&sig.r, &pk_seed, &pk_root, msg);
    let (md, idx_tree, idx_leaf) = split_digest(digest);
    let adrs = fors_adrs(idx_tree, idx_leaf);
    let pk_fors = fors::pk_from_sig(&h, &sig.fors, &md, &adrs);
    xmss::ht_verify(&h, &pk_fors, &sig.ht, idx_tree, idx_leaf, &pk_root)
}

/// FIPS 205 Alg. 19 `slh_sign_internal`. `addrnd` is `opt_rand`; pass
/// PK.seed for the deterministic variant.
///
/// **This skips self-verification.** It exists for test vectors and for
/// composition by callers that do their own checks; otherwise use [`sign`].
#[doc(hidden)]
#[must_use]
pub fn sign_internal(sk: &SigningKey, msg: &[u8], addrnd: &[u8; N]) -> [u8; SIGNATURE_SIZE] {
    let sig = sign_pieces(sk, &[msg], addrnd).to_bytes();
    scrub_stack();
    sig
}

/// FIPS 205 Alg. 20 `slh_verify_internal`. Total: a signature of the wrong
/// length is rejected.
#[must_use]
pub fn verify_internal(pk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    verify_pieces(pk, &[msg], sig)
}

/// The domain-separation prefix of M' = 0x00 ‖ |ctx| ‖ ctx ‖ M (Alg. 22/24).
fn pure_prefix(ctx: &[u8]) -> Option<[u8; 2]> {
    let len = u8::try_from(ctx.len()).ok()?;
    Some([0, len])
}

/// FIPS 205 Alg. 22 `slh_sign` (pure, hedged), with context string `ctx`
/// (at most 255 bytes). The caller supplies 16 bytes of fresh randomness.
///
/// The signature is verified before it is returned, so a fault during
/// signing cannot release a malformed signature.
///
/// # Errors
///
/// [`Error::ContextTooLong`] if `ctx` exceeds 255 bytes;
/// [`Error::SelfVerificationFailed`] if the signature does not verify.
pub fn sign(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    addrnd: &[u8; N],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let prefix = pure_prefix(ctx).ok_or(Error::ContextTooLong)?;
    let pieces: [&[u8]; 3] = [&prefix, ctx, msg];
    let sig = sign_pieces(sk, &pieces, addrnd).to_bytes();
    let ok = verify_pieces(&sk.verifying_key(), &pieces, &sig);
    scrub_stack();
    if ok {
        Ok(sig)
    } else {
        Err(Error::SelfVerificationFailed)
    }
}

/// FIPS 205 Alg. 24 `slh_verify` (pure), with context string `ctx`.
/// Returns false for a context longer than 255 bytes or a signature of the
/// wrong length.
#[must_use]
pub fn verify(pk: &VerifyingKey, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Some(prefix) = pure_prefix(ctx) else {
        return false;
    };
    verify_pieces(pk, &[&prefix, ctx, msg], sig)
}
