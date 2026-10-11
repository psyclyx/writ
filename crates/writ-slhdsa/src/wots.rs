//! WOTS+ one-time signatures (FIPS 205 §5), lg_w = 4, len = 35.

use crate::address::{Adrs, AdrsType};
use crate::hash::Hasher;
use crate::{LEN, Node, W};

/// Base-16 digits of the message followed by the 3-digit checksum
/// (FIPS 205 Alg. 7 lines 1–8 / Alg. 8 lines 1–8).
///
/// Only ever applied to public values (roots being signed), so branching
/// and indexing on the digits is fine.
fn digits(msg: &Node) -> [u8; LEN] {
    let mut d = [0u8; LEN];
    for (pair, byte) in d.as_chunks_mut::<2>().0.iter_mut().zip(msg) {
        *pair = [byte >> 4, byte & 0x0f];
    }
    let csum: u32 = msg
        .iter()
        .map(|b| (W - 1 - u32::from(b >> 4)) + (W - 1 - u32::from(b & 0x0f)))
        .sum();
    // len1 = 32 digits, then csum << 4 as two bytes → its three high nibbles.
    d[32] = ((csum >> 8) & 0x0f) as u8;
    d[33] = ((csum >> 4) & 0x0f) as u8;
    d[34] = (csum & 0x0f) as u8;
    d
}

/// Alg. 5 `chain`: apply F `steps` times starting at position `start`.
#[inline]
fn chain(h: &Hasher, adrs: &mut Adrs, mut x: Node, start: u32, steps: u32) -> Node {
    for j in start..start + steps {
        adrs.set_hash(j);
        x = h.f(adrs, &x);
    }
    x
}

/// Alg. 6 `wots_pkGen`. `adrs` has type WOTS_HASH and the key pair address set.
pub(crate) fn pk_gen(h: &Hasher, sk_seed: &Node, adrs: &Adrs) -> Node {
    let sk_adrs = adrs.with_type_keep_key_pair(AdrsType::WotsPrf);
    let pk_adrs = adrs.with_type_keep_key_pair(AdrsType::WotsPk);
    let mut adrs = *adrs;
    let tops = (0..LEN as u32).map(|i| {
        let mut sk_adrs = sk_adrs;
        sk_adrs.set_chain(i);
        let sk = h.prf(&sk_adrs, sk_seed);
        adrs.set_chain(i);
        chain(h, &mut adrs, sk, 0, W - 1)
    });
    h.t(&pk_adrs, tops)
}

/// Alg. 7 `wots_sign`. `adrs` has type WOTS_HASH and the key pair address set.
pub(crate) fn sign(h: &Hasher, msg: &Node, sk_seed: &Node, adrs: &Adrs, sig: &mut [Node; LEN]) {
    let mut sk_adrs = adrs.with_type_keep_key_pair(AdrsType::WotsPrf);
    let mut adrs = *adrs;
    for ((i, out), digit) in (0u32..).zip(sig.iter_mut()).zip(digits(msg)) {
        sk_adrs.set_chain(i);
        let sk = h.prf(&sk_adrs, sk_seed);
        adrs.set_chain(i);
        *out = chain(h, &mut adrs, sk, 0, u32::from(digit));
    }
}

/// Alg. 8 `wots_pkFromSig`. `adrs` has type WOTS_HASH and the key pair
/// address set.
pub(crate) fn pk_from_sig(h: &Hasher, sig: &[Node; LEN], msg: &Node, adrs: &Adrs) -> Node {
    let pk_adrs = adrs.with_type_keep_key_pair(AdrsType::WotsPk);
    let mut adrs = *adrs;
    let tops = (0u32..).zip(sig).zip(digits(msg)).map(|((i, s), digit)| {
        let digit = u32::from(digit);
        adrs.set_chain(i);
        chain(h, &mut adrs, *s, digit, W - 1 - digit)
    });
    h.t(&pk_adrs, tops)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn checksum_digits() {
        // All-zero message: every digit 0, csum = 32 * 15 = 480 = 0x1e0.
        let d = digits(&[0; 16]);
        assert_eq!(d[32..], [0x1, 0xe, 0x0]);
        // All-0xff message: every digit 15, csum = 0.
        let d = digits(&[0xff; 16]);
        assert!(d[..32].iter().all(|&x| x == 15));
        assert_eq!(d[32..], [0, 0, 0]);
        let d = digits(&[0x12; 16]);
        assert_eq!(d[0..2], [1, 2]);
    }
}
