//! Merkle tree helpers shared by XMSS and FORS.
//!
//! Both trees hash node pairs with `H` under an address whose tree height and
//! tree index identify the node; tree indices are global (FORS trees are laid
//! side by side, so tree `t`'s leaves are `t·2^a ..`). Leaf indices and auth
//! path positions come only from public data (the message digest).

use crate::Node;
use crate::address::Adrs;
use crate::hash::Hasher;

/// Root of the subtree of height `z` whose leftmost leaf has global index
/// `start` (FIPS 205 Alg. 9 / Alg. 14), recording into `auth` the
/// authentication path for global leaf `target` as a side effect, so that one
/// pass yields both the root and the path (Alg. 10 / Alg. 16).
///
/// `node_adrs` carries the type (TREE or FORS_TREE) and other fixed fields;
/// only tree height and tree index are changed. Pass an empty `auth` to skip
/// path recording.
pub(crate) fn subtree<L: FnMut(u32) -> Node>(
    h: &Hasher,
    node_adrs: &mut Adrs,
    leaf: &mut L,
    start: u32,
    z: u32,
    target: u32,
    auth: &mut [Node],
) -> Node {
    let node = if z == 0 {
        leaf(start)
    } else {
        let left = subtree(h, node_adrs, leaf, start, z - 1, target, auth);
        let right = subtree(
            h,
            node_adrs,
            leaf,
            start + (1 << (z - 1)),
            z - 1,
            target,
            auth,
        );
        node_adrs.set_tree_height(z);
        node_adrs.set_tree_index(start >> z);
        h.h(node_adrs, &left, &right)
    };
    if start >> z == (target >> z) ^ 1
        && let Some(slot) = auth.get_mut(z as usize)
    {
        *slot = node;
    }
    node
}

/// Climb from a leaf to the root using an authentication path
/// (FIPS 205 Alg. 11 lines 6–17 / Alg. 17 lines 6–19).
pub(crate) fn root_from_auth(
    h: &Hasher,
    node_adrs: &mut Adrs,
    mut node: Node,
    mut index: u32,
    auth: &[Node],
) -> Node {
    for (height, sibling) in (1u32..).zip(auth) {
        let is_left = index & 1 == 0;
        index >>= 1;
        node_adrs.set_tree_height(height);
        node_adrs.set_tree_index(index);
        node = if is_left {
            h.h(node_adrs, &node, sibling)
        } else {
            h.h(node_adrs, sibling, &node)
        };
    }
    node
}
