//! ADRS, the 32-byte hash address (FIPS 205 §4.2). The SHAKE parameter sets
//! use the full, uncompressed layout:
//!
//! | bytes  | field                                        |
//! | ------ | -------------------------------------------- |
//! | 0..4   | layer address                                |
//! | 4..16  | tree address (we use the low 8 bytes)        |
//! | 16..20 | type                                         |
//! | 20..24 | key pair address                             |
//! | 24..28 | chain address / tree height                  |
//! | 28..32 | hash address / tree index                    |

/// Address types (FIPS 205 §4.2).
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

/// Encoded ADRS size in bytes.
pub(crate) const ADRS_BYTES: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct Adrs([u8; ADRS_BYTES]);

impl Adrs {
    /// `toByte(0, 32)`.
    pub(crate) const fn zero() -> Self {
        Self([0; ADRS_BYTES])
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; ADRS_BYTES] {
        &self.0
    }

    pub(crate) fn set_layer(&mut self, layer: u32) {
        self.0[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// The tree address is 12 bytes; for SHAKE-128s it is < 2^54, so the top
    /// 4 bytes are always zero.
    pub(crate) fn set_tree(&mut self, tree: u64) {
        self.0[4..8].copy_from_slice(&[0; 4]);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// `setTypeAndClear`: set the type and zero the last 12 bytes.
    pub(crate) fn set_type_and_clear(&mut self, ty: AdrsType) {
        self.0[16..20].copy_from_slice(&(ty as u32).to_be_bytes());
        self.0[20..32].copy_from_slice(&[0; 12]);
    }

    /// `setTypeAndClear` followed by restoring the key pair address, which is
    /// the pattern FIPS 205 uses when deriving PRF and public-key addresses.
    pub(crate) fn with_type_keep_key_pair(&self, ty: AdrsType) -> Self {
        let mut out = *self;
        out.set_type_and_clear(ty);
        out.0[20..24].copy_from_slice(&self.0[20..24]);
        out
    }

    pub(crate) fn set_key_pair(&mut self, kp: u32) {
        self.0[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    pub(crate) fn set_chain(&mut self, chain: u32) {
        self.0[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.0[24..28].copy_from_slice(&height.to_be_bytes());
    }

    pub(crate) fn set_hash(&mut self, hash: u32) {
        self.0[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    pub(crate) fn set_tree_index(&mut self, index: u32) {
        self.0[28..32].copy_from_slice(&index.to_be_bytes());
    }
}
