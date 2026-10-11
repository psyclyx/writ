//! XMSS (FIPS 205 §6) and the hypertree (§7).

use crate::address::{Adrs, AdrsType};
use crate::hash::Hasher;
use crate::signature::XmssSig;
use crate::tree::{root_from_auth, subtree};
use crate::{D, HP, Node, wots};

/// Alg. 9 `xmss_node(SK.seed, 0, h', ...)` with an optional auth path for
/// leaf `idx` (Alg. 10 line 1–4). `adrs` carries the layer and tree address.
fn root_and_auth(h: &Hasher, sk_seed: &Node, adrs: &Adrs, idx: u32, auth: &mut [Node]) -> Node {
    let mut leaf = |i: u32| {
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type_and_clear(AdrsType::WotsHash);
        leaf_adrs.set_key_pair(i);
        wots::pk_gen(h, sk_seed, &leaf_adrs)
    };
    let mut node_adrs = *adrs;
    node_adrs.set_type_and_clear(AdrsType::Tree);
    subtree(h, &mut node_adrs, &mut leaf, 0, HP as u32, idx, auth)
}

/// The root of the top-layer XMSS tree: PK.root (Alg. 18 lines 2–3).
pub(crate) fn top_root(h: &Hasher, sk_seed: &Node) -> Node {
    let mut adrs = Adrs::zero();
    adrs.set_layer(D as u32 - 1);
    root_and_auth(h, sk_seed, &adrs, 0, &mut [])
}

/// Alg. 10 `xmss_sign`, also returning the tree's root (which is what
/// `xmss_pkFromSig` would recompute from the signature).
fn sign(h: &Hasher, msg: &Node, sk_seed: &Node, idx: u32, adrs: &Adrs, sig: &mut XmssSig) -> Node {
    let root = root_and_auth(h, sk_seed, adrs, idx, &mut sig.auth);
    let mut wots_adrs = *adrs;
    wots_adrs.set_type_and_clear(AdrsType::WotsHash);
    wots_adrs.set_key_pair(idx);
    wots::sign(h, msg, sk_seed, &wots_adrs, &mut sig.wots);
    root
}

/// Alg. 11 `xmss_pkFromSig`.
fn pk_from_sig(h: &Hasher, idx: u32, sig: &XmssSig, msg: &Node, adrs: &Adrs) -> Node {
    let mut wots_adrs = *adrs;
    wots_adrs.set_type_and_clear(AdrsType::WotsHash);
    wots_adrs.set_key_pair(idx);
    let leaf = wots::pk_from_sig(h, &sig.wots, msg, &wots_adrs);
    let mut node_adrs = *adrs;
    node_adrs.set_type_and_clear(AdrsType::Tree);
    root_from_auth(h, &mut node_adrs, leaf, idx, &sig.auth)
}

/// Mask for the leaf index within one XMSS tree.
const LEAF_MASK: u64 = (1 << HP) - 1;

/// Alg. 12 `ht_sign`. `idx_tree`/`idx_leaf` come from the public message
/// digest.
pub(crate) fn ht_sign(
    h: &Hasher,
    msg: &Node,
    sk_seed: &Node,
    mut idx_tree: u64,
    mut idx_leaf: u32,
    sigs: &mut [XmssSig; D],
) {
    let mut root = *msg;
    for (layer, sig) in (0u32..).zip(sigs.iter_mut()) {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_tree(idx_tree);
        root = sign(h, &root, sk_seed, idx_leaf, &adrs, sig);
        idx_leaf = (idx_tree & LEAF_MASK) as u32;
        idx_tree >>= HP;
    }
}

/// Alg. 13 `ht_verify`.
pub(crate) fn ht_verify(
    h: &Hasher,
    msg: &Node,
    sigs: &[XmssSig; D],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    pk_root: &Node,
) -> bool {
    let mut node = *msg;
    for (layer, sig) in (0u32..).zip(sigs) {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_tree(idx_tree);
        node = pk_from_sig(h, idx_leaf, sig, &node, &adrs);
        idx_leaf = (idx_tree & LEAF_MASK) as u32;
        idx_tree >>= HP;
    }
    node == *pk_root
}
