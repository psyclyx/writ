//! The signature layout (FIPS 205 Fig. 17): R ‖ SIG_FORS ‖ SIG_HT, held as
//! typed arrays so that the algorithms never index into raw bytes.

use core::iter;

use crate::{A, D, HP, K, LEN, N, Node, SIGNATURE_SIZE};

/// One FORS tree's part of SIG_FORS: the revealed secret and its auth path.
#[derive(Clone, Copy)]
pub(crate) struct ForsTreeSig {
    pub(crate) sk: Node,
    pub(crate) auth: [Node; A],
}

/// One hypertree layer: a WOTS+ signature and the XMSS auth path.
#[derive(Clone, Copy)]
pub(crate) struct XmssSig {
    pub(crate) wots: [Node; LEN],
    pub(crate) auth: [Node; HP],
}

pub(crate) struct Signature {
    pub(crate) r: Node,
    pub(crate) fors: [ForsTreeSig; K],
    pub(crate) ht: [XmssSig; D],
}

/// Number of n-byte nodes in a signature.
const NODES: usize = 1 + K * (1 + A) + D * (LEN + HP);
const _: () = assert!(NODES * N == SIGNATURE_SIZE);

impl Signature {
    pub(crate) const fn zero() -> Self {
        Self {
            r: [0; N],
            fors: [ForsTreeSig {
                sk: [0; N],
                auth: [[0; N]; A],
            }; K],
            ht: [XmssSig {
                wots: [[0; N]; LEN],
                auth: [[0; N]; HP],
            }; D],
        }
    }

    /// All nodes in wire order.
    fn nodes(&self) -> impl Iterator<Item = &Node> {
        iter::once(&self.r)
            .chain(
                self.fors
                    .iter()
                    .flat_map(|t| iter::once(&t.sk).chain(t.auth.iter())),
            )
            .chain(
                self.ht
                    .iter()
                    .flat_map(|x| x.wots.iter().chain(x.auth.iter())),
            )
    }

    /// All nodes in wire order, mutably.
    fn nodes_mut(&mut self) -> impl Iterator<Item = &mut Node> {
        iter::once(&mut self.r)
            .chain(
                self.fors
                    .iter_mut()
                    .flat_map(|t| iter::once(&mut t.sk).chain(t.auth.iter_mut())),
            )
            .chain(
                self.ht
                    .iter_mut()
                    .flat_map(|x| x.wots.iter_mut().chain(x.auth.iter_mut())),
            )
    }

    pub(crate) fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        for (dst, src) in out.as_chunks_mut::<N>().0.iter_mut().zip(self.nodes()) {
            *dst = *src;
        }
        out
    }

    pub(crate) fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        let mut sig = Self::zero();
        for (dst, src) in sig.nodes_mut().zip(bytes.as_chunks::<N>().0) {
            *dst = *src;
        }
        sig
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn layout_round_trip_and_order() {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        for (k, node) in bytes.as_chunks_mut::<N>().0.iter_mut().enumerate() {
            node[..2].copy_from_slice(&(k as u16).to_be_bytes());
        }
        let sig = Signature::from_bytes(&bytes);
        assert_eq!(sig.to_bytes(), bytes);
        assert_eq!(sig.nodes().count(), NODES);
        // Spot-check field positions against FIPS 205 Fig. 17.
        let node = |i: usize| {
            let mut n = [0u8; N];
            n.copy_from_slice(&bytes[i * N..(i + 1) * N]);
            n
        };
        assert_eq!(sig.r, node(0));
        assert_eq!(sig.fors[0].sk, node(1));
        assert_eq!(sig.fors[0].auth[11], node(13));
        assert_eq!(sig.fors[13].auth[11], node(K * (1 + A)));
        let ht0 = 1 + K * (1 + A);
        assert_eq!(sig.ht[0].wots[0], node(ht0));
        assert_eq!(sig.ht[0].auth[0], node(ht0 + LEN));
        assert_eq!(sig.ht[6].auth[8], node(NODES - 1));
    }
}
