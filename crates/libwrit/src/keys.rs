//! The two v1 suites (DESIGN.md §3, SPEC.md §4), secret seeds, and signing.
//!
//! - Root: `slh-dsa-shake-128s`, FIPS 205 pure signing, hedged, context
//!   `writ/v1/root/slh-dsa-shake-128s`.
//! - Leaf: `mldsa65-ed25519`, both components over
//!   `M' = "writ/v1/leaf/mldsa65-ed25519" ‖ 0x00 ‖ msg`; ML-DSA-65 also gets
//!   the label as its FIPS 204 context. Both must verify.

use crate::bech32;
use crate::hash::{LeafId, label, labelled_message, shake256_labelled};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

/// ML-DSA-65 verification key size.
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 signature size.
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;
/// Root-suite signature size.
pub const ROOT_SIGNATURE_SIZE: usize = writ_slhdsa::SIGNATURE_SIZE;
/// Leaf-suite (composite) signature size: ML-DSA-65 ‖ Ed25519.
pub const LEAF_SIGNATURE_SIZE: usize = MLDSA65_SIGNATURE_SIZE + 64;

/// A signature suite. One per role in v1; carried in every key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Suite {
    /// SLH-DSA-SHAKE-128s, for identity authorities.
    SlhDsaShake128s,
    /// ML-DSA-65 + Ed25519 composite, for leaf keys.
    MlDsa65Ed25519,
}

impl Suite {
    /// The suite identifier as it appears in encodings.
    pub fn name(self) -> &'static str {
        match self {
            Suite::SlhDsaShake128s => "slh-dsa-shake-128s",
            Suite::MlDsa65Ed25519 => "mldsa65-ed25519",
        }
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A root-suite public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RootKey(pub [u8; writ_slhdsa::PUBLIC_KEY_SIZE]);

impl RootKey {
    /// Verifies a root-suite signature over `msg` (an already-labelled item message).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        #[cfg(test)]
        if crate::testing::fake_verify(&self.0, msg, sig) {
            return true;
        }
        let pk = writ_slhdsa::VerifyingKey::from_bytes(&self.0);
        writ_slhdsa::verify(&pk, msg, label::ROOT_SUITE.as_bytes(), sig)
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootKey({})", crate::hash::hex(&self.0))
    }
}

/// A leaf-suite public key: ML-DSA-65 verification key and Ed25519 key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeafKey {
    /// ML-DSA-65 verification key.
    pub mldsa: Box<[u8; MLDSA65_PUBLIC_KEY_SIZE]>,
    /// Ed25519 public key.
    pub ed25519: [u8; 32],
}

impl LeafKey {
    /// Verifies a composite signature over `msg`. Both components must verify;
    /// Ed25519 verification is strict (see [`ed25519_verify_strict`]).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        #[cfg(test)]
        if crate::testing::fake_verify(&self.ed25519, msg, sig) {
            return true;
        }
        let Some((ml, ed)) = sig.split_at_checked(MLDSA65_SIGNATURE_SIZE) else {
            return false;
        };
        let (Ok(ml), Ok(ed)) = (
            <[u8; MLDSA65_SIGNATURE_SIZE]>::try_from(ml),
            <[u8; 64]>::try_from(ed),
        ) else {
            return false;
        };
        let m = labelled_message(label::LEAF_SUITE, msg);
        let vk = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey::new(*self.mldsa);
        let ml_ok = libcrux_ml_dsa::ml_dsa_65::verify(
            &vk,
            &m,
            label::LEAF_SUITE.as_bytes(),
            &libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(ml),
        )
        .is_ok();
        let ed_ok = ed25519_verify_strict(&self.ed25519, &m, &ed);
        ml_ok & ed_ok
    }

    /// The key's id: `SHA3-256("writ/v1/leaf-id" ‖ 0x00 ‖ canonical(key))`.
    pub fn id(&self) -> LeafId {
        LeafId(crate::Hash::labelled(label::LEAF_ID, &self.to_sexp().encode()).0)
    }

    /// A short fingerprint for display: the start of [`LeafKey::id`].
    pub fn fingerprint(&self) -> String {
        self.id().fingerprint()
    }
}

impl fmt::Debug for LeafKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeafKey({})", self.fingerprint())
    }
}

/// A public key of either suite.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PublicKey {
    /// Root suite.
    Root(RootKey),
    /// Leaf suite.
    Leaf(LeafKey),
}

impl PublicKey {
    /// The key's suite.
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Root(_) => Suite::SlhDsaShake128s,
            PublicKey::Leaf(_) => Suite::MlDsa65Ed25519,
        }
    }

    /// Verifies a signature over an item message.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Root(k) => k.verify(msg, sig),
            PublicKey::Leaf(k) => k.verify(msg, sig),
        }
    }
}

/// Encodings of the small-order points' y-coordinates (sign bit cleared):
/// y = 0, 1, −1 and the two order-8 values. Together with the canonical-y
/// check in libcrux, this rejects every small-order A or R.
const SMALL_ORDER_Y: [[u8; 32]; 5] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
];

fn has_small_order(point: &[u8; 32]) -> bool {
    let mut y = *point;
    if let Some(last) = y.last_mut() {
        *last &= 0x7f;
    }
    SMALL_ORDER_Y.contains(&y)
}

/// Strict Ed25519 verification (DESIGN.md §3.2): cofactorless RFC 8032
/// equation, canonical A, R and S, small-order A and R rejected.
///
/// libcrux-ed25519 (HACL\*) already rejects non-canonical y (≥ p) and
/// x = 0 with the sign bit set for A and R, rejects S ≥ L, and checks the
/// cofactorless equation; this wrapper adds the small-order rejection.
pub fn ed25519_verify_strict(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let r: [u8; 32] = sig.first_chunk::<32>().copied().unwrap_or([0; 32]);
    if has_small_order(public) || has_small_order(&r) {
        return false;
    }
    libcrux_ed25519::verify(msg, public, sig).is_ok()
}

/// A source of randomness. Signing takes one explicitly; libwrit never
/// reads ambient randomness.
pub trait Rng {
    /// Fills `out` with uniformly random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// Signing failed. Practically unreachable; reported rather than panicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// SLH-DSA's own signature did not verify (fault detected).
    SelfCheckFailed,
    /// ML-DSA rejection sampling gave up.
    MlDsa,
    /// Ed25519 refused the message.
    Ed25519,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::SelfCheckFailed => write!(f, "signature failed its own verification"),
            SignError::MlDsa => write!(f, "ML-DSA signing failed"),
            SignError::Ed25519 => write!(f, "Ed25519 signing failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// Something that can sign item messages: an in-memory key today, an agent
/// or hardware token later.
pub trait Signer {
    /// The public key the signatures verify under.
    fn public_key(&self) -> PublicKey;
    /// Signs an already-labelled item message.
    fn sign(&self, msg: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, SignError>;
}

/// A 32-byte secret seed: the whole content of a secret key file.
#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; 32]>);

/// Human-readable prefix of secret key files (upper-cased in the file).
pub const SECRET_KEY_HRP: &str = "writ-secret-key-";

impl Seed {
    /// A seed from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Seed {
        Seed(Zeroizing::new(bytes))
    }

    /// A fresh seed.
    pub fn generate(rng: &mut dyn Rng) -> Seed {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill(bytes.as_mut());
        Seed(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key-file form: `WRIT-SECRET-KEY-1…`, upper case, no newline.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = bech32::encode(SECRET_KEY_HRP, self.0.as_ref());
        let upper = Zeroizing::new(s.to_ascii_uppercase());
        s.zeroize();
        upper
    }

    /// Parses the key-file form (either case).
    pub fn parse(text: &str) -> Option<Seed> {
        let (hrp, mut data) = bech32::decode(text.trim())?;
        let seed = if hrp == SECRET_KEY_HRP {
            <[u8; 32]>::try_from(data.as_slice())
                .ok()
                .map(Seed::from_bytes)
        } else {
            None
        };
        data.zeroize();
        seed
    }

    /// The root-suite signer derived from this seed.
    pub fn root(&self) -> RootSigner {
        let mut okm = Zeroizing::new([[0u8; 16]; 3]);
        shake256_labelled(label::KEYGEN_ROOT, self.0.as_ref(), okm.as_flattened_mut());
        // Fixed-size destructuring: there is no fallback that could derive a
        // key from the wrong bytes.
        let [sk_seed, sk_prf, pk_seed] = &*okm;
        let sk = writ_slhdsa::keygen_internal(sk_seed, sk_prf, pk_seed);
        let public = RootKey(sk.verifying_key().to_bytes());
        RootSigner { sk, public }
    }

    /// The leaf-suite signer derived from this seed.
    pub fn leaf(&self) -> LeafSigner {
        let keys = LeafKeys::derive(&self.0);
        let public = LeafKey {
            mldsa: Box::new(*keys.mldsa.verification_key.as_ref()),
            ed25519: keys.ed25519_public(),
        };
        LeafSigner {
            seed: self.0.clone(),
            public,
        }
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// Signs with a root-suite key.
pub struct RootSigner {
    sk: writ_slhdsa::SigningKey,
    public: RootKey,
}

impl RootSigner {
    /// The public key.
    pub fn root_key(&self) -> RootKey {
        self.public
    }
}

impl Signer for RootSigner {
    fn public_key(&self) -> PublicKey {
        PublicKey::Root(self.public)
    }

    fn sign(&self, msg: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, SignError> {
        let mut addrnd = Zeroizing::new([0u8; writ_slhdsa::N]);
        rng.fill(addrnd.as_mut());
        writ_slhdsa::sign(&self.sk, msg, label::ROOT_SUITE.as_bytes(), &addrnd)
            .map(|sig| sig.to_vec())
            .map_err(|_| SignError::SelfCheckFailed)
    }
}

/// Signs with a leaf-suite key. Holds only the seed; the expanded keys are
/// derived per signature and wiped afterwards.
pub struct LeafSigner {
    seed: Zeroizing<[u8; 32]>,
    public: LeafKey,
}

impl LeafSigner {
    /// The public key.
    pub fn leaf_key(&self) -> &LeafKey {
        &self.public
    }
}

struct LeafKeys {
    mldsa: libcrux_ml_dsa::ml_dsa_65::MLDSA65KeyPair,
    ed25519: Zeroizing<[u8; 32]>,
}

impl LeafKeys {
    fn derive(seed: &[u8; 32]) -> LeafKeys {
        let mut okm = Zeroizing::new([[0u8; 32]; 2]);
        shake256_labelled(label::KEYGEN_LEAF, seed, okm.as_flattened_mut());
        let [xi, ed] = &*okm;
        LeafKeys {
            mldsa: libcrux_ml_dsa::ml_dsa_65::generate_key_pair(*xi),
            ed25519: Zeroizing::new(*ed),
        }
    }

    fn ed25519_public(&self) -> [u8; 32] {
        let mut pk = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut pk, &self.ed25519);
        pk
    }
}

impl Drop for LeafKeys {
    fn drop(&mut self) {
        self.mldsa.signing_key.as_mut_slice().zeroize();
    }
}

impl Signer for LeafSigner {
    fn public_key(&self) -> PublicKey {
        PublicKey::Leaf(self.public.clone())
    }

    fn sign(&self, msg: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, SignError> {
        let keys = LeafKeys::derive(&self.seed);
        let m = labelled_message(label::LEAF_SUITE, msg);
        let mut rnd = Zeroizing::new([0u8; 32]);
        rng.fill(rnd.as_mut());
        let ml = libcrux_ml_dsa::ml_dsa_65::sign(
            &keys.mldsa.signing_key,
            &m,
            label::LEAF_SUITE.as_bytes(),
            *rnd,
        )
        .map_err(|_| SignError::MlDsa)?;
        let ed = libcrux_ed25519::sign(&m, &keys.ed25519).map_err(|_| SignError::Ed25519)?;
        let mut sig = Vec::with_capacity(LEAF_SIGNATURE_SIZE);
        sig.extend_from_slice(ml.as_slice());
        sig.extend_from_slice(&ed);
        // Verify before release, as for the root suite: catches faults in
        // deterministic Ed25519 signing, which would otherwise leak the key.
        if !self.public.verify(msg, &sig) {
            return Err(SignError::SelfCheckFailed);
        }
        Ok(sig)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testing::TestRng;

    #[test]
    fn seed_text_round_trip() {
        let seed = Seed::from_bytes([42; 32]);
        let text = seed.to_text();
        assert!(text.starts_with("WRIT-SECRET-KEY-1"));
        assert_eq!(text.len(), 16 + 1 + 52 + 6);
        let back = Seed::parse(&text).map(|s| *s.as_bytes());
        assert_eq!(back, Some([42; 32]));
        assert!(Seed::parse(&text.to_lowercase()).is_some());
        assert!(Seed::parse(&crate::bech32::encode("writ", &[42; 32])).is_none());
        assert!(Seed::parse(&crate::bech32::encode(SECRET_KEY_HRP, &[42; 31])).is_none());
    }

    #[test]
    fn leaf_sign_verify() {
        let mut rng = TestRng::new(1);
        let signer = Seed::generate(&mut rng).leaf();
        let msg = b"writ/v1/stmt\0(grant)";
        let sig = signer.sign(msg, &mut rng).unwrap_or_default();
        assert_eq!(sig.len(), LEAF_SIGNATURE_SIZE);
        let key = signer.leaf_key();
        assert!(key.verify(msg, &sig));
        assert!(!key.verify(b"other", &sig));
        // Either component alone is not enough.
        for i in [
            0,
            MLDSA65_SIGNATURE_SIZE - 1,
            MLDSA65_SIGNATURE_SIZE,
            LEAF_SIGNATURE_SIZE - 1,
        ] {
            let mut bad = sig.clone();
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert!(!key.verify(msg, &bad), "flip at {i}");
        }
        assert!(!key.verify(msg, sig.get(..sig.len() - 1).unwrap_or_default()));
        // Deterministic derivation.
        let again = Seed::from_bytes(*Seed::generate(&mut TestRng::new(1)).as_bytes()).leaf();
        assert_eq!(again.leaf_key(), key);
    }

    #[test]
    fn root_derivation_is_deterministic() {
        let seed = Seed::from_bytes([3; 32]);
        assert_eq!(seed.root().root_key(), seed.root().root_key());
        assert_ne!(
            seed.root().root_key(),
            Seed::from_bytes([4; 32]).root().root_key()
        );
    }

    /// novifinancial/ed25519-speccheck: strict verification accepts only
    /// case 3 (mixed-order A and R that pass the cofactorless equation).
    #[test]
    fn ed25519_speccheck() {
        let json = include_str!("../../../vectors/ed25519-speccheck/cases.json");
        let cases = crate::testing::speccheck_cases(json);
        assert_eq!(cases.len(), 12);
        for (i, (msg, pk, sig)) in cases.iter().enumerate() {
            let pk: [u8; 32] = pk.as_slice().try_into().unwrap_or([0; 32]);
            let sig: [u8; 64] = sig.as_slice().try_into().unwrap_or([0; 64]);
            assert_eq!(ed25519_verify_strict(&pk, msg, &sig), i == 3, "case {i}");
        }
    }

    /// RFC 8032 §7.1 test 1 and 2: plain Ed25519 still works.
    #[test]
    fn ed25519_rfc8032() {
        let unhex = |s: &str| crate::hash::unhex(s).unwrap_or_default();
        let sk: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap_or([0; 32]);
        let mut pk = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut pk, &sk);
        assert_eq!(
            crate::hash::hex(&pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = libcrux_ed25519::sign(b"", &sk).unwrap_or([0; 64]);
        assert_eq!(
            crate::hash::hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(ed25519_verify_strict(&pk, b"", &sig));
    }
}
