//! Labelled hashing. Every hash and signature input is
//! `label ‖ 0x00 ‖ data`, where `label` is `writ/v1/<purpose>` (SPEC.md §2).

use crate::bech32;
use core::fmt;
use libcrux_sha3::portable::incremental::{Shake256Xof, Xof};

/// Domain-separation labels. No label is a prefix of another, and the `0x00`
/// terminator makes `label ‖ 0x00 ‖ data` unambiguous regardless.
pub mod label {
    /// Identity id: hash of the inception body.
    pub const ID: &str = "writ/v1/id";
    /// Log events: hashed for `prev`, signed by the event's authority.
    pub const EVENT: &str = "writ/v1/event";
    /// Authorities: hashed for the `next` commitment.
    pub const AUTHORITY: &str = "writ/v1/authority";
    /// Statements: hashed for identity, signed by the issuer.
    pub const STATEMENT: &str = "writ/v1/stmt";
    /// Data signatures: the signed body, hashed for `keep` and `revoke`.
    pub const SIGNATURE: &str = "writ/v1/sig";
    /// Revocation records (DESIGN.md §18.4): hash and signed message.
    pub const RECORD: &str = "writ/v1/record";
    /// Hash of signed data (SHAKE256, so it can be computed incrementally).
    pub const DATA: &str = "writ/v1/data";
    /// Leaf key ids: how leaf-issued items name their issuer.
    pub const LEAF_ID: &str = "writ/v1/leaf-id";
    /// Root-suite signing: SLH-DSA context string.
    pub const ROOT_SUITE: &str = "writ/v1/root/slh-dsa-shake-128s";
    /// Leaf-suite signing: prefix of the composite message and ML-DSA context.
    pub const LEAF_SUITE: &str = "writ/v1/leaf/mldsa65-ed25519";
    /// Root key derivation from a seed.
    pub const KEYGEN_ROOT: &str = "writ/v1/keygen/slh-dsa-shake-128s";
    /// Leaf key derivation from a seed.
    pub const KEYGEN_LEAF: &str = "writ/v1/keygen/mldsa65-ed25519";
}

/// A 32-byte digest: SHA3-256, except for data hashes (see [`DataHasher`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// `SHA3-256(label ‖ 0x00 ‖ data)`.
    pub fn labelled(label: &str, data: &[u8]) -> Hash {
        Hash(libcrux_sha3::sha256(&labelled_message(label, data)))
    }

    /// The hash of `data` as referenced by data signatures.
    pub fn of_data(data: &[u8]) -> Hash {
        let mut h = DataHasher::new();
        h.update(data);
        h.finish()
    }

    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 64 hex digits.
    pub fn from_hex(text: &str) -> Option<Hash> {
        let bytes = unhex(text)?;
        Some(Hash(bytes.try_into().ok()?))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

/// An identity id: `SHA3-256("writ/v1/id" ‖ 0x00 ‖ canonical(inception))`.
/// Displayed as bech32m with prefix `writ`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(pub [u8; 32]);

/// The bech32m human-readable prefix of ids.
pub const ID_HRP: &str = "writ";

impl Id {
    /// Parses the bech32m form (`writ1…`).
    pub fn parse(text: &str) -> Option<Id> {
        let (hrp, data) = bech32::decode(text)?;
        if hrp != ID_HRP {
            return None;
        }
        Some(Id(data.try_into().ok()?))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bech32::encode(ID_HRP, &self.0))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

/// The hash of signed data, fed in pieces:
/// `SHAKE256("writ/v1/data" ‖ 0x00 ‖ data, 32)`. SHAKE256 rather than
/// SHA3-256 because libcrux absorbs it incrementally, so files of any size
/// hash in constant memory.
pub struct DataHasher(Shake256Xof);

impl DataHasher {
    /// A hasher with the label absorbed.
    pub fn new() -> DataHasher {
        let mut xof = Shake256Xof::new();
        xof.absorb(label::DATA.as_bytes());
        xof.absorb(&[0]);
        DataHasher(xof)
    }

    /// Absorbs the next piece of data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    /// The hash of everything absorbed.
    pub fn finish(mut self) -> Hash {
        let mut out = [0u8; 32];
        self.0.absorb_final(&[]);
        self.0.squeeze(&mut out);
        Hash(out)
    }
}

impl Default for DataHasher {
    fn default() -> Self {
        DataHasher::new()
    }
}

/// A leaf key's id: `SHA3-256("writ/v1/leaf-id" ‖ 0x00 ‖ canonical(key))`.
/// Leaf-issued items name their issuer by it; the key itself travels in the
/// grant to the leaf.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeafId(pub [u8; 32]);

impl LeafId {
    /// A short fingerprint for display: the first 8 bytes, in hex.
    pub fn fingerprint(&self) -> String {
        hex(self.0.get(..8).unwrap_or_default())
    }
}

impl fmt::Display for LeafId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for LeafId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeafId({})", self.fingerprint())
    }
}

/// `label ‖ 0x00 ‖ data`.
pub fn labelled_message(label: &str, data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(label.len() + 1 + data.len());
    msg.extend_from_slice(label.as_bytes());
    msg.push(0);
    msg.extend_from_slice(data);
    msg
}

/// `SHAKE256(label ‖ 0x00 ‖ data)`, squeezed into `out`.
pub(crate) fn shake256_labelled(label: &str, data: &[u8], out: &mut [u8]) {
    let mut xof = Shake256Xof::new();
    xof.absorb(label.as_bytes());
    xof.absorb(&[0]);
    xof.absorb_final(data);
    xof.squeeze(out);
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 15] {
            s.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    s
}

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[hi, lo]| {
            let hi = char::from(*hi).to_digit(16)?;
            let lo = char::from(*lo).to_digit(16)?;
            Some((hi << 4 | lo) as u8)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_prefix_free() {
        let all = [
            label::ID,
            label::EVENT,
            label::AUTHORITY,
            label::STATEMENT,
            label::SIGNATURE,
            label::RECORD,
            label::DATA,
            label::LEAF_ID,
            label::ROOT_SUITE,
            label::LEAF_SUITE,
            label::KEYGEN_ROOT,
            label::KEYGEN_LEAF,
        ];
        for a in all {
            assert!(a.starts_with("writ/v1/"));
            for b in all {
                assert!(a == b || !b.starts_with(a), "{a} is a prefix of {b}");
            }
        }
    }

    #[test]
    fn sha3_known_answer() {
        // SHA3-256("") from FIPS 202.
        assert_eq!(
            hex(&libcrux_sha3::sha256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            Hash::labelled("writ/v1/data", b"abc"),
            Hash(libcrux_sha3::sha256(b"writ/v1/data\0abc"))
        );
    }

    #[test]
    fn data_hash_is_labelled_shake256() {
        // SHAKE256("", 256) from FIPS 202.
        let mut xof = Shake256Xof::new();
        xof.absorb_final(b"");
        let mut out = [0u8; 32];
        xof.squeeze(&mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        let mut expect = [0u8; 32];
        shake256_labelled(label::DATA, b"abc", &mut expect);
        assert_eq!(Hash::of_data(b"abc"), Hash(expect));
    }

    #[test]
    fn data_hash_ignores_how_data_is_split() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let whole = Hash::of_data(&data);
        for size in [1, 5, 135, 136, 137, 999] {
            let mut h = DataHasher::new();
            for chunk in data.chunks(size) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), whole, "chunks of {size}");
        }
    }

    #[test]
    fn hex_round_trip() {
        let h = Hash([0xa5; 32]);
        assert_eq!(Hash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(Hash::from_hex("abc"), None);
        assert_eq!(Hash::from_hex(&"zz".repeat(32)), None);
    }

    #[test]
    fn id_round_trip() {
        let id = Id([7; 32]);
        let text = id.to_string();
        assert!(text.starts_with("writ1"));
        assert_eq!(Id::parse(&text), Some(id));
        assert_eq!(Id::parse(&text.to_uppercase()), Some(id));
        let mut typo = text.into_bytes();
        typo[10] = if typo[10] == b'q' { b'p' } else { b'q' };
        assert_eq!(
            Id::parse(&String::from_utf8(typo).unwrap_or_default()),
            None
        );
    }
}
