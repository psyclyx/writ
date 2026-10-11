//! The SHAKE instantiation of the tweakable hash functions (FIPS 205 §11.1).
//!
//! Every function is SHAKE256 of a concatenation; the fixed-size ones (F, H,
//! PRF) fit in one Keccak block and are computed one-shot from a stack buffer.

use libcrux_sha3::portable::incremental::{Shake256Xof, Xof};
use zeroize::Zeroize;

use crate::address::Adrs;
use crate::{M, N, Node};

/// The message pieces whose concatenation is the message M (or M').
pub(crate) type Pieces<'a> = [&'a [u8]];

/// Tweakable hashes keyed by PK.seed.
pub(crate) struct Hasher {
    pk_seed: Node,
}

impl Hasher {
    pub(crate) const fn new(pk_seed: &Node) -> Self {
        Self { pk_seed: *pk_seed }
    }

    /// `F(PK.seed, ADRS, M1) = SHAKE256(PK.seed ‖ ADRS ‖ M1, 8n)`.
    #[inline]
    pub(crate) fn f(&self, adrs: &Adrs, m: &Node) -> Node {
        let mut buf = [0u8; 2 * N + 32];
        buf[0..16].copy_from_slice(&self.pk_seed);
        buf[16..48].copy_from_slice(adrs.as_bytes());
        buf[48..64].copy_from_slice(m);
        let mut out = [0u8; N];
        libcrux_sha3::shake256_ema(&mut out, &buf);
        out
    }

    /// `PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ‖ ADRS ‖ SK.seed, 8n)`.
    /// Same shape as F, but the input buffer holds a secret and is wiped.
    #[inline]
    pub(crate) fn prf(&self, adrs: &Adrs, sk_seed: &Node) -> Node {
        let mut buf = [0u8; 2 * N + 32];
        buf[0..16].copy_from_slice(&self.pk_seed);
        buf[16..48].copy_from_slice(adrs.as_bytes());
        buf[48..64].copy_from_slice(sk_seed);
        let mut out = [0u8; N];
        libcrux_sha3::shake256_ema(&mut out, &buf);
        buf.zeroize();
        out
    }

    /// `H(PK.seed, ADRS, M2) = SHAKE256(PK.seed ‖ ADRS ‖ left ‖ right, 8n)`.
    #[inline]
    pub(crate) fn h(&self, adrs: &Adrs, left: &Node, right: &Node) -> Node {
        let mut buf = [0u8; 3 * N + 32];
        buf[0..16].copy_from_slice(&self.pk_seed);
        buf[16..48].copy_from_slice(adrs.as_bytes());
        buf[48..64].copy_from_slice(left);
        buf[64..80].copy_from_slice(right);
        let mut out = [0u8; N];
        libcrux_sha3::shake256_ema(&mut out, &buf);
        out
    }

    /// `T_l(PK.seed, ADRS, M_l) = SHAKE256(PK.seed ‖ ADRS ‖ M_l, 8n)`, with
    /// the l nodes of `M_l` streamed in.
    pub(crate) fn t(&self, adrs: &Adrs, nodes: impl IntoIterator<Item = Node>) -> Node {
        let mut xof = Shake256Xof::new();
        xof.absorb(&self.pk_seed);
        xof.absorb(adrs.as_bytes());
        for node in nodes {
            xof.absorb(&node);
        }
        xof.absorb_final(&[]);
        let mut out = [0u8; N];
        xof.squeeze(&mut out);
        out
    }
}

/// `PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf ‖ opt_rand ‖ M, 8n)`.
pub(crate) fn prf_msg(sk_prf: &Node, opt_rand: &Node, msg: &Pieces<'_>) -> Node {
    let mut xof = Shake256Xof::new();
    xof.absorb(sk_prf);
    xof.absorb(opt_rand);
    for piece in msg {
        xof.absorb(piece);
    }
    xof.absorb_final(&[]);
    let mut out = [0u8; N];
    xof.squeeze(&mut out);
    out
}

/// `H_msg(R, PK.seed, PK.root, M) = SHAKE256(R ‖ PK.seed ‖ PK.root ‖ M, 8m)`.
pub(crate) fn h_msg(r: &Node, pk_seed: &Node, pk_root: &Node, msg: &Pieces<'_>) -> [u8; M] {
    let mut xof = Shake256Xof::new();
    xof.absorb(r);
    xof.absorb(pk_seed);
    xof.absorb(pk_root);
    for piece in msg {
        xof.absorb(piece);
    }
    xof.absorb_final(&[]);
    let mut out = [0u8; M];
    xof.squeeze(&mut out);
    out
}
