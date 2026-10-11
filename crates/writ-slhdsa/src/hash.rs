//! The SHAKE instantiation of the tweakable hash functions (FIPS 205 §11.1).
//!
//! Every function is SHAKE256 of a concatenation; the fixed-size ones (F, H,
//! PRF) fit in one Keccak block and are computed one-shot from a stack buffer.

use libcrux_sha3::portable::incremental::{Shake256Xof, Xof};
use zeroize::Zeroize;

use crate::address::{ADRS_BYTES, Adrs};
use crate::{M, N, Node};

/// The message pieces whose concatenation is the message M (or M').
pub(crate) type Pieces<'a> = [&'a [u8]];

/// End of the PK.seed ‖ ADRS prefix shared by F, PRF and H; the n-byte
/// inputs follow it.
const PREFIX: usize = N + ADRS_BYTES;

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
        let mut buf = [0u8; PREFIX + N];
        buf[..N].copy_from_slice(&self.pk_seed);
        buf[N..PREFIX].copy_from_slice(adrs.as_bytes());
        buf[PREFIX..].copy_from_slice(m);
        let mut out = [0u8; N];
        libcrux_sha3::shake256_ema(&mut out, &buf);
        out
    }

    /// `PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ‖ ADRS ‖ SK.seed, 8n)`.
    ///
    /// Same shape as F. `buf` holds SK.seed, so we wipe it; that covers only
    /// our own copy. libcrux copies the input into its Keccak state and block
    /// buffers in frames we cannot reach, and the output is itself secret
    /// (a WOTS+ or FORS secret value). Those are left to the stack scrub at
    /// the end of the public signing and key-generation functions.
    #[inline]
    pub(crate) fn prf(&self, adrs: &Adrs, sk_seed: &Node) -> Node {
        let mut buf = [0u8; PREFIX + N];
        buf[..N].copy_from_slice(&self.pk_seed);
        buf[N..PREFIX].copy_from_slice(adrs.as_bytes());
        buf[PREFIX..].copy_from_slice(sk_seed);
        let mut out = [0u8; N];
        libcrux_sha3::shake256_ema(&mut out, &buf);
        buf.zeroize();
        out
    }

    /// `H(PK.seed, ADRS, M2) = SHAKE256(PK.seed ‖ ADRS ‖ left ‖ right, 8n)`.
    #[inline]
    pub(crate) fn h(&self, adrs: &Adrs, left: &Node, right: &Node) -> Node {
        let mut buf = [0u8; PREFIX + 2 * N];
        buf[..N].copy_from_slice(&self.pk_seed);
        buf[N..PREFIX].copy_from_slice(adrs.as_bytes());
        buf[PREFIX..PREFIX + N].copy_from_slice(left);
        buf[PREFIX + N..].copy_from_slice(right);
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

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// SHAKE256 rate in bytes: the Xof's internal block size.
    const RATE: usize = 136;

    fn shake(input: &[u8]) -> [u8; M] {
        let mut out = [0u8; M];
        libcrux_sha3::shake256_ema(&mut out, input);
        out
    }

    /// Splitting the message into pieces at any boundary — in particular
    /// around the 136-byte block — does not change `prf_msg` or `h_msg`,
    /// which also agree with one-shot SHAKE256 of the concatenation.
    #[test]
    fn piecewise_absorb_matches_one_shot() {
        let msg: Vec<u8> = (0..3 * RATE).map(|i| (i * 7 + 3) as u8).collect();
        let (a, b, c) = ([1u8; N], [2u8; N], [3u8; N]);
        let prf_ref = shake(&[&a[..], &b, &msg].concat());
        let hmsg_ref = shake(&[&a[..], &b, &c, &msg].concat());
        let check = |pieces: &Pieces<'_>, label: &str| {
            assert_eq!(prf_msg(&a, &b, pieces), prf_ref[..N], "prf_msg {label}");
            assert_eq!(h_msg(&a, &b, &c, pieces), hmsg_ref, "h_msg {label}");
        };

        check(&[&msg], "single");
        check(&[&msg, &[], &[]], "trailing empties");
        // Every two-way split.
        for i in 0..=msg.len() {
            let (x, y) = msg.split_at(i);
            check(&[x, y], &format!("split {i}"));
        }
        // Three-way splits at points straddling block boundaries.
        let points = [0, 1, RATE - 1, RATE, RATE + 1, 2 * RATE - 1, 2 * RATE];
        for &i in &points {
            for &j in points.iter().filter(|&&j| j >= i) {
                let pieces: [&[u8]; 3] = [&msg[..i], &msg[i..j], &msg[j..]];
                check(&pieces, &format!("split {i}, {j}"));
            }
        }
        // One byte per piece.
        let bytes: Vec<&[u8]> = msg.chunks(1).collect();
        check(&bytes, "bytewise");
    }
}
