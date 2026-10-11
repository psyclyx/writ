//! FORS few-time signatures (FIPS 205 §8), k = 14 trees of height a = 12.

use crate::address::{Adrs, AdrsType};
use crate::hash::Hasher;
use crate::signature::ForsTreeSig;
use crate::tree::{root_from_auth, subtree};
use crate::{A, K, MD_BYTES, Node};

/// `base_2b(md, a, k)`: fourteen 12-bit big-endian indices from 21 bytes.
fn indices(md: &[u8; MD_BYTES]) -> [u32; K] {
    let mut out = [0u32; K];
    for (pair, &[b0, b1, b2]) in out
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(md.as_chunks::<3>().0)
    {
        let (b0, b1, b2) = (u32::from(b0), u32::from(b1), u32::from(b2));
        *pair = [(b0 << 4) | (b1 >> 4), ((b1 & 0x0f) << 8) | b2];
    }
    out
}

/// Global leaf index of index `idx` in tree `t`.
const fn global(t: u32, idx: u32) -> u32 {
    (t << A) + idx
}

/// Alg. 14 `fors_skGen`. `adrs` has type FORS_TREE and the key pair set.
fn sk_gen(h: &Hasher, sk_seed: &Node, adrs: &Adrs, idx: u32) -> Node {
    let mut sk_adrs = adrs.with_type_keep_key_pair(AdrsType::ForsPrf);
    sk_adrs.set_tree_index(idx);
    h.prf(&sk_adrs, sk_seed)
}

/// FORS leaf: `F` of the secret value at tree height 0.
fn leaf(h: &Hasher, adrs: &Adrs, idx: u32, sk: &Node) -> Node {
    let mut leaf_adrs = *adrs;
    leaf_adrs.set_tree_height(0);
    leaf_adrs.set_tree_index(idx);
    h.f(&leaf_adrs, sk)
}

/// Alg. 16 `fors_sign`, also returning the FORS public key (what Alg. 17
/// `fors_pkFromSig` recomputes from the signature).
pub(crate) fn sign(
    h: &Hasher,
    md: &[u8; MD_BYTES],
    sk_seed: &Node,
    adrs: &Adrs,
    sigs: &mut [ForsTreeSig; K],
) -> Node {
    let mut roots = [[0u8; crate::N]; K];
    for ((t, (sig, root)), idx) in (0u32..)
        .zip(sigs.iter_mut().zip(roots.iter_mut()))
        .zip(indices(md))
    {
        let target = global(t, idx);
        sig.sk = sk_gen(h, sk_seed, adrs, target);
        let mut leaf_fn = |i: u32| leaf(h, adrs, i, &sk_gen(h, sk_seed, adrs, i));
        let mut node_adrs = *adrs;
        *root = subtree(
            h,
            &mut node_adrs,
            &mut leaf_fn,
            global(t, 0),
            A as u32,
            target,
            &mut sig.auth,
        );
    }
    h.t(&adrs.with_type_keep_key_pair(AdrsType::ForsRoots), roots)
}

/// Alg. 17 `fors_pkFromSig`.
pub(crate) fn pk_from_sig(
    h: &Hasher,
    sigs: &[ForsTreeSig; K],
    md: &[u8; MD_BYTES],
    adrs: &Adrs,
) -> Node {
    let roots = (0u32..).zip(sigs).zip(indices(md)).map(|((t, sig), idx)| {
        let index = global(t, idx);
        let node = leaf(h, adrs, index, &sig.sk);
        let mut node_adrs = *adrs;
        root_from_auth(h, &mut node_adrs, node, index, &sig.auth)
    });
    h.t(&adrs.with_type_keep_key_pair(AdrsType::ForsRoots), roots)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn base_2b_12() {
        let mut md = [0u8; MD_BYTES];
        md[0] = 0xab;
        md[1] = 0xcd;
        md[2] = 0xef;
        md[20] = 0xff;
        let ix = indices(&md);
        assert_eq!(ix[0], 0xabc);
        assert_eq!(ix[1], 0xdef);
        assert_eq!(ix[13], 0x0ff);
    }
}
