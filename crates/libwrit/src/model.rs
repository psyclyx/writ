//! Every item writ signs, hashes, or ships, with its canonical csexp form
//! (SPEC.md §5–§7). Decoding is syntactic and total; semantic rules live in
//! [`Statement::check_wellformed`] and the verifier.

use crate::hash::{Hash, Id, LeafId, label, labelled_message};
use crate::keys::{
    LEAF_SIGNATURE_SIZE, LeafKey, MLDSA65_PUBLIC_KEY_SIZE, PublicKey, ROOT_SIGNATURE_SIZE, RootKey,
    Suite,
};
use crate::tag::{Tag, Tags};
use crate::time::Time;
use core::fmt;
use writ_sexp::Sexp;

/// The head atom of every encoded item.
pub const VERSION: &str = "writ/v1";
/// Largest bundle accepted, in bytes (each item is limited separately, to
/// 4 MiB of canonical encoding).
pub const MAX_BUNDLE: usize = 256 << 20;
/// Most keys in one authority.
pub const MAX_AUTHORITY_KEYS: usize = 16;
/// Most names in a name path.
pub const MAX_NAME_PATH: usize = 16;
/// Longest name, tag atom, or context, in bytes.
pub const MAX_ATOM: usize = 255;
/// Longest note, in bytes.
pub const MAX_NOTE: usize = 1024;
/// Longest opaque key type name, in bytes.
pub const MAX_OPAQUE_TYPE: usize = 64;
/// Longest opaque key, in bytes.
pub const MAX_OPAQUE_KEY: usize = 16 * 1024;

/// Why bytes are not a valid item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not canonical csexp.
    Sexp(writ_sexp::DecodeError),
    /// Bad armor.
    Armor(writ_sexp::armor::ArmorError),
    /// Not a `writ/v1` item.
    Version,
    /// Well-formed csexp that doesn't match the item grammar.
    Malformed(&'static str),
    /// Parses, but is not the unique canonical encoding of what it parses to.
    NonCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Sexp(e) => write!(f, "{e}"),
            DecodeError::Armor(e) => write!(f, "{e}"),
            DecodeError::Version => write!(f, "not a writ/v1 item"),
            DecodeError::Malformed(what) => write!(f, "malformed item: {what}"),
            DecodeError::NonCanonical => write!(f, "item is not in canonical form"),
        }
    }
}

impl std::error::Error for DecodeError {}

type Result<T> = core::result::Result<T, DecodeError>;

fn bad<T>(what: &'static str) -> Result<T> {
    Err(DecodeError::Malformed(what))
}

// ---------------------------------------------------------------------------
// Parsing helpers

/// A cursor over the fields of a list.
struct Fields<'a> {
    items: &'a [Sexp],
}

impl<'a> Fields<'a> {
    /// The fields of `(head …)`.
    fn of(sexp: &'a Sexp, head: &str, what: &'static str) -> Result<Fields<'a>> {
        match sexp.as_list() {
            Some([Sexp::Atom(h), rest @ ..]) if h == head.as_bytes() => Ok(Fields { items: rest }),
            _ => bad(what),
        }
    }

    fn next(&mut self, what: &'static str) -> Result<&'a Sexp> {
        let (first, rest) = self
            .items
            .split_first()
            .ok_or(DecodeError::Malformed(what))?;
        self.items = rest;
        Ok(first)
    }

    fn atom(&mut self, what: &'static str) -> Result<&'a [u8]> {
        self.next(what)?
            .as_atom()
            .ok_or(DecodeError::Malformed(what))
    }

    fn peek_head(&self) -> Option<&'a [u8]> {
        Fields::head_of(self.items.first()?)
    }

    /// The head atom of `(head …)`.
    fn head_of(s: &'a Sexp) -> Option<&'a [u8]> {
        match s.as_list()? {
            [Sexp::Atom(h), ..] => Some(h),
            _ => None,
        }
    }

    /// `(name …)` → the fields after `name`.
    fn field(&mut self, name: &str, what: &'static str) -> Result<Fields<'a>> {
        Fields::of(self.next(what)?, name, what)
    }

    /// Like [`Fields::field`], but absent is fine.
    fn optional(&mut self, name: &str, what: &'static str) -> Result<Option<Fields<'a>>> {
        if self.peek_head() == Some(name.as_bytes()) {
            self.field(name, what).map(Some)
        } else {
            Ok(None)
        }
    }

    /// `(name atom)` → atom.
    fn single(&mut self, name: &str, what: &'static str) -> Result<&'a [u8]> {
        let mut f = self.field(name, what)?;
        let a = f.atom(what)?;
        f.end(what)?;
        Ok(a)
    }

    fn optional_single(&mut self, name: &str, what: &'static str) -> Result<Option<&'a [u8]>> {
        if self.peek_head() == Some(name.as_bytes()) {
            self.single(name, what).map(Some)
        } else {
            Ok(None)
        }
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn end(&self, what: &'static str) -> Result<()> {
        if self.items.is_empty() {
            Ok(())
        } else {
            bad(what)
        }
    }
}

fn atom32(bytes: &[u8], what: &'static str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| DecodeError::Malformed(what))
}

/// Canonical unsigned decimal: `0` or `[1-9][0-9]*`, at most `u64::MAX`.
fn decimal(bytes: &[u8], what: &'static str) -> Result<u64> {
    let ok = match bytes {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if !ok {
        return bad(what);
    }
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(DecodeError::Malformed(what))
}

fn num(n: u64) -> Sexp {
    Sexp::atom(n.to_string())
}

fn tagged(name: &str, items: impl IntoIterator<Item = Sexp>) -> Sexp {
    let mut v = vec![Sexp::atom(name)];
    v.extend(items);
    Sexp::List(v)
}

fn bounded_atom(bytes: &[u8], min: usize, max: usize, what: &'static str) -> Result<Vec<u8>> {
    if (min..=max).contains(&bytes.len()) {
        Ok(bytes.to_vec())
    } else {
        bad(what)
    }
}

// ---------------------------------------------------------------------------
// Keys

impl RootKey {
    /// `(slh-dsa-shake-128s PK)`.
    pub fn to_sexp(&self) -> Sexp {
        tagged(Suite::SlhDsaShake128s.name(), [Sexp::atom(self.0)])
    }

    fn from_fields(mut f: Fields<'_>) -> Result<RootKey> {
        let pk = atom32(f.atom("root key")?, "root key length")?;
        f.end("root key")?;
        Ok(RootKey(pk))
    }
}

impl LeafKey {
    /// `(mldsa65-ed25519 MLDSA-PK ED25519-PK)`.
    pub fn to_sexp(&self) -> Sexp {
        tagged(
            Suite::MlDsa65Ed25519.name(),
            [Sexp::atom(self.mldsa.as_slice()), Sexp::atom(self.ed25519)],
        )
    }

    fn from_fields(mut f: Fields<'_>) -> Result<LeafKey> {
        let ml: [u8; MLDSA65_PUBLIC_KEY_SIZE] = f
            .atom("leaf key")?
            .try_into()
            .map_err(|_| DecodeError::Malformed("ML-DSA-65 key length"))?;
        let ed = atom32(f.atom("leaf key")?, "Ed25519 key length")?;
        f.end("leaf key")?;
        Ok(LeafKey {
            mldsa: Box::new(ml),
            ed25519: ed,
        })
    }

    fn from_sexp(s: &Sexp) -> Result<LeafKey> {
        LeafKey::from_fields(Fields::of(s, Suite::MlDsa65Ed25519.name(), "leaf key")?)
    }
}

impl PublicKey {
    /// The key's canonical form.
    pub fn to_sexp(&self) -> Sexp {
        match self {
            PublicKey::Root(k) => k.to_sexp(),
            PublicKey::Leaf(k) => k.to_sexp(),
        }
    }

    fn from_sexp(s: &Sexp) -> Result<PublicKey> {
        if let Ok(f) = Fields::of(s, Suite::SlhDsaShake128s.name(), "key") {
            RootKey::from_fields(f).map(PublicKey::Root)
        } else {
            LeafKey::from_sexp(s).map(PublicKey::Leaf)
        }
    }
}

// ---------------------------------------------------------------------------
// Authority

/// `k` of `keys` must sign (DESIGN.md §4.1). Keys are distinct and sorted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Authority {
    k: u8,
    keys: Vec<RootKey>,
}

/// Why an authority can't be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    /// No keys, or more than [`MAX_AUTHORITY_KEYS`].
    KeyCount,
    /// `k` is 0 or more than the number of keys.
    Threshold,
    /// The same key twice.
    Duplicate,
    /// `k` is at most half the keys, so two disjoint groups could each act.
    Quorum,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityError::KeyCount => {
                write!(f, "an authority has 1 to {MAX_AUTHORITY_KEYS} keys")
            }
            AuthorityError::Threshold => write!(f, "threshold must be between 1 and the key count"),
            AuthorityError::Duplicate => write!(f, "an authority may not list a key twice"),
            AuthorityError::Quorum => {
                write!(f, "the threshold must be more than half of the keys")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

impl Authority {
    /// `k` of `keys`. Sorts the keys; rejects duplicates, and thresholds of
    /// half the keys or fewer: any two groups of `k` holders must share a
    /// holder, so two different signed events at one position always mean
    /// some holder signed both.
    pub fn new(
        k: usize,
        mut keys: Vec<RootKey>,
    ) -> core::result::Result<Authority, AuthorityError> {
        if keys.is_empty() || keys.len() > MAX_AUTHORITY_KEYS {
            return Err(AuthorityError::KeyCount);
        }
        if k == 0 || k > keys.len() {
            return Err(AuthorityError::Threshold);
        }
        keys.sort();
        if keys.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(AuthorityError::Duplicate);
        }
        if 2 * k <= keys.len() {
            return Err(AuthorityError::Quorum);
        }
        Ok(Authority { k: k as u8, keys })
    }

    /// 1-of-1.
    pub fn single(key: RootKey) -> Authority {
        Authority {
            k: 1,
            keys: vec![key],
        }
    }

    /// The threshold.
    pub fn k(&self) -> usize {
        usize::from(self.k)
    }

    /// The keys, sorted. Signature indices refer to this order.
    pub fn keys(&self) -> &[RootKey] {
        &self.keys
    }

    /// Position of `key` in [`Authority::keys`].
    pub fn index_of(&self, key: &RootKey) -> Option<u8> {
        self.keys.iter().position(|k| k == key).map(|i| i as u8)
    }

    /// `(authority K KEY…)`.
    pub fn to_sexp(&self) -> Sexp {
        tagged(
            "authority",
            core::iter::once(num(u64::from(self.k))).chain(self.keys.iter().map(RootKey::to_sexp)),
        )
    }

    /// `SHA3-256("writ/v1/authority" ‖ 0x00 ‖ canonical)`: what `next` commits to.
    pub fn hash(&self) -> Hash {
        Hash::labelled(label::AUTHORITY, &self.to_sexp().encode())
    }

    fn from_sexp(s: &Sexp) -> Result<Authority> {
        let mut f = Fields::of(s, "authority", "authority")?;
        let k = decimal(f.atom("authority threshold")?, "authority threshold")?;
        let mut keys = Vec::new();
        while !f.is_empty() {
            keys.push(RootKey::from_fields(Fields::of(
                f.next("authority key")?,
                Suite::SlhDsaShake128s.name(),
                "authority key",
            )?)?);
        }
        let k = usize::try_from(k).map_err(|_| DecodeError::Malformed("authority threshold"))?;
        let sorted = keys.windows(2).all(|w| w.first() < w.get(1));
        let a = Authority::new(k, keys).map_err(|_| DecodeError::Malformed("authority"))?;
        if !sorted {
            return Err(DecodeError::NonCanonical);
        }
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Events

/// The first event of an identity log (DESIGN.md §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inception {
    /// Who signs for the identity at event 0.
    pub authority: Authority,
    /// Hash of the authority allowed to perform the first rotation.
    pub next: Hash,
    /// Longest permitted statement lifetime, if any (DESIGN.md §4.5).
    pub max_validity: Option<u64>,
    /// Where the identity publishes revocation records, if it does
    /// (DESIGN.md §18.5).
    pub publish: Option<Publish>,
}

/// Shortest `max-age` an identity may publish with.
pub const MIN_MAX_AGE: u64 = 3600;
/// Most URLs in a `publish` field.
pub const MAX_PUBLISH_URLS: usize = 4;

/// An identity's promise to sign a revocation record at least every
/// `max_age` seconds, and where to find it (DESIGN.md §18.5). Verifiers
/// then need a record no older than `max_age` before they accept a
/// long-lived statement by the identity (§18.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publish {
    max_age: u64,
    urls: Vec<String>,
}

impl Publish {
    /// `None` if `max_age` is below [`MIN_MAX_AGE`], there are more than
    /// [`MAX_PUBLISH_URLS`] URLs, or a URL is empty, over 255 bytes, or not
    /// printable ASCII without spaces.
    pub fn new(max_age: u64, urls: Vec<String>) -> Option<Publish> {
        let ok = max_age >= MIN_MAX_AGE
            && urls.len() <= MAX_PUBLISH_URLS
            && urls.iter().all(|u| valid_url(u.as_bytes()));
        ok.then_some(Publish { max_age, urls })
    }

    /// D: verifiers refuse a record older than this many seconds.
    pub fn max_age(&self) -> u64 {
        self.max_age
    }

    /// Where the records are published.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    fn to_sexp(&self) -> Sexp {
        tagged(
            "publish",
            core::iter::once(tagged("max-age", [num(self.max_age)]))
                .chain(self.urls.iter().map(Sexp::atom)),
        )
    }

    fn from_fields(mut f: Fields<'_>) -> Result<Publish> {
        let max_age = decimal(f.single("max-age", "max-age")?, "max-age")?;
        let mut urls = Vec::new();
        while !f.is_empty() {
            let u = f.atom("publish url")?;
            urls.push(String::from_utf8(u.to_vec()).map_err(|_| DecodeError::Malformed("url"))?);
        }
        Publish::new(max_age, urls).ok_or(DecodeError::Malformed("publish"))
    }
}

/// 1–255 bytes of printable ASCII, no spaces.
fn valid_url(u: &[u8]) -> bool {
    !u.is_empty() && u.len() <= MAX_ATOM && u.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// A later event (DESIGN.md §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The identity.
    pub id: Id,
    /// Event number, ≥ 1.
    pub n: u64,
    /// Hash of event `n − 1`.
    pub prev: Hash,
    /// The next authority committed to by event `n − 1` (it must hash to
    /// that event's `next`). It signs this rotation, and nothing else.
    pub revealed: Authority,
    /// The current authority from this event on: it signs statements.
    pub authority: Authority,
    /// Commitment to the next authority.
    pub next: Hash,
    /// Statement lifetime limit from now on.
    pub max_validity: Option<u64>,
    /// Where the identity publishes revocation records from now on.
    pub publish: Option<Publish>,
    /// Hashes of earlier statements and signatures that stay valid. Sorted, distinct.
    pub keep: Vec<Hash>,
}

/// An identity log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Event 0.
    Inception(Inception),
    /// Event n ≥ 1.
    Rotation(Rotation),
}

impl Event {
    /// The event number.
    pub fn n(&self) -> u64 {
        match self {
            Event::Inception(_) => 0,
            Event::Rotation(r) => r.n,
        }
    }

    /// The authority that signs this event: the inception's own authority,
    /// or a rotation's revealed next authority.
    pub fn signers(&self) -> &Authority {
        match self {
            Event::Inception(i) => &i.authority,
            Event::Rotation(r) => &r.revealed,
        }
    }

    /// The current authority under this event: it signs statements.
    pub fn authority(&self) -> &Authority {
        match self {
            Event::Inception(i) => &i.authority,
            Event::Rotation(r) => &r.authority,
        }
    }

    /// The commitment to the next authority.
    pub fn next(&self) -> &Hash {
        match self {
            Event::Inception(i) => &i.next,
            Event::Rotation(r) => &r.next,
        }
    }

    /// The statement lifetime limit in force under this event.
    pub fn max_validity(&self) -> Option<u64> {
        match self {
            Event::Inception(i) => i.max_validity,
            Event::Rotation(r) => r.max_validity,
        }
    }

    /// Where the identity publishes revocation records under this event.
    pub fn publish(&self) -> Option<&Publish> {
        match self {
            Event::Inception(i) => i.publish.as_ref(),
            Event::Rotation(r) => r.publish.as_ref(),
        }
    }

    /// The identity this event belongs to.
    pub fn id(&self) -> Id {
        match self {
            Event::Inception(_) => Id(Hash::labelled(label::ID, &self.encode()).0),
            Event::Rotation(r) => r.id,
        }
    }

    /// The `keep` list (empty for inception).
    pub fn keep(&self) -> &[Hash] {
        match self {
            Event::Inception(_) => &[],
            Event::Rotation(r) => &r.keep,
        }
    }

    fn fields_tail(
        authority: &Authority,
        next: &Hash,
        max_validity: Option<u64>,
        publish: Option<&Publish>,
    ) -> impl Iterator<Item = Sexp> {
        [
            Some(authority.to_sexp()),
            Some(tagged("next", [Sexp::atom(next.0)])),
            max_validity.map(|mv| tagged("max-validity", [num(mv)])),
            publish.map(Publish::to_sexp),
        ]
        .into_iter()
        .flatten()
    }
}

/// A signed or hashed body: an event, statement, data signature or record.
pub trait Body: Sized + Clone {
    /// The label for hashing and signing.
    const LABEL: &'static str;
    /// The canonical tree.
    fn to_sexp(&self) -> Sexp;
    /// Parses a tree (syntax only).
    fn from_sexp(s: &Sexp) -> Result<Self>;
    /// The signed body as a bundle item.
    fn item(signed: &Signed<Self>) -> Item;

    /// A rule an identity's signature on this body must respect, beyond
    /// well-formedness: issuing refuses to sign otherwise.
    fn check_signable(&self) -> core::result::Result<(), &'static str> {
        Ok(())
    }

    /// The canonical bytes.
    fn encode(&self) -> Vec<u8> {
        self.to_sexp().encode()
    }

    /// `SHA3-256(LABEL ‖ 0x00 ‖ canonical)`.
    fn hash(&self) -> Hash {
        Hash::labelled(Self::LABEL, &self.encode())
    }

    /// What signers sign: `LABEL ‖ 0x00 ‖ canonical`.
    fn message(&self) -> Vec<u8> {
        labelled_message(Self::LABEL, &self.encode())
    }
}

impl Body for Event {
    const LABEL: &'static str = label::EVENT;

    fn item(signed: &Signed<Self>) -> Item {
        Item::Event(signed.clone())
    }

    fn to_sexp(&self) -> Sexp {
        match self {
            Event::Inception(i) => tagged(
                "inception",
                Event::fields_tail(&i.authority, &i.next, i.max_validity, i.publish.as_ref()),
            ),
            Event::Rotation(r) => tagged(
                "rotation",
                [
                    tagged("id", [Sexp::atom(r.id.0)]),
                    tagged("n", [num(r.n)]),
                    tagged("prev", [Sexp::atom(r.prev.0)]),
                    tagged("revealed", [r.revealed.to_sexp()]),
                ]
                .into_iter()
                .chain(Event::fields_tail(
                    &r.authority,
                    &r.next,
                    r.max_validity,
                    r.publish.as_ref(),
                ))
                .chain([tagged("keep", r.keep.iter().map(|h| Sexp::atom(h.0)))]),
            ),
        }
    }

    fn from_sexp(s: &Sexp) -> Result<Event> {
        type Tail = (Authority, Hash, Option<u64>, Option<Publish>);
        fn tail(f: &mut Fields<'_>) -> Result<Tail> {
            let authority = Authority::from_sexp(f.next("authority")?)?;
            let next = Hash(atom32(f.single("next", "next")?, "next")?);
            let mv = f
                .optional_single("max-validity", "max-validity")?
                .map(|a| decimal(a, "max-validity"))
                .transpose()?;
            if mv == Some(0) {
                return bad("max-validity must be positive");
            }
            let publish = f
                .optional("publish", "publish")?
                .map(Publish::from_fields)
                .transpose()?;
            Ok((authority, next, mv, publish))
        }
        if let Ok(mut f) = Fields::of(s, "inception", "event") {
            let (authority, next, max_validity, publish) = tail(&mut f)?;
            f.end("inception")?;
            return Ok(Event::Inception(Inception {
                authority,
                next,
                max_validity,
                publish,
            }));
        }
        let mut f = Fields::of(s, "rotation", "event")?;
        let id = Id(atom32(f.single("id", "id")?, "id")?);
        let n = decimal(f.single("n", "event number")?, "event number")?;
        if n == 0 {
            return bad("rotation number must be positive");
        }
        let prev = Hash(atom32(f.single("prev", "prev")?, "prev")?);
        let mut rf = f.field("revealed", "revealed")?;
        let revealed = Authority::from_sexp(rf.next("revealed authority")?)?;
        rf.end("revealed")?;
        let (authority, next, max_validity, publish) = tail(&mut f)?;
        let mut kf = f.field("keep", "keep")?;
        let mut keep = Vec::new();
        while !kf.is_empty() {
            keep.push(Hash(atom32(kf.atom("keep")?, "keep hash")?));
        }
        f.end("rotation")?;
        if !keep.windows(2).all(|w| w.first() < w.get(1)) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Event::Rotation(Rotation {
            id,
            n,
            prev,
            revealed,
            authority,
            next,
            max_validity,
            publish,
            keep,
        }))
    }
}

// ---------------------------------------------------------------------------
// Statements

/// Who issued a statement or signature (DESIGN.md §5.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Issuer {
    /// An identity, under event `event` of its log.
    Identity {
        /// The identity.
        id: Id,
        /// The event whose authority signed.
        event: u64,
    },
    /// A leaf key, by id. The key itself travels in the grant to it.
    Leaf(LeafId),
}

impl Issuer {
    fn to_sexp(&self) -> Sexp {
        match self {
            Issuer::Identity { id, event } => tagged("issuer", [Sexp::atom(id.0), num(*event)]),
            Issuer::Leaf(k) => tagged("issuer", [tagged("leaf", [Sexp::atom(k.0)])]),
        }
    }

    fn from_sexp(s: &Sexp) -> Result<Issuer> {
        let mut f = Fields::of(s, "issuer", "issuer")?;
        let first = f.next("issuer")?;
        let issuer = match first {
            Sexp::Atom(id) => Issuer::Identity {
                id: Id(atom32(id, "issuer id")?),
                event: decimal(f.atom("issuer event")?, "issuer event")?,
            },
            Sexp::List(_) => {
                let mut leaf = Fields::of(first, "leaf", "leaf issuer")?;
                let id = LeafId(atom32(leaf.atom("leaf id")?, "leaf id")?);
                leaf.end("leaf issuer")?;
                Issuer::Leaf(id)
            }
        };
        f.end("issuer")?;
        Ok(issuer)
    }

    /// The identity, if any.
    pub fn id(&self) -> Option<Id> {
        match self {
            Issuer::Identity { id, .. } => Some(*id),
            Issuer::Leaf(_) => None,
        }
    }
}

/// An SDSI compound name: `base`'s `names[0]`'s `names[1]`… (DESIGN.md §5.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamePath {
    /// The identity whose namespace the path starts in.
    pub base: Id,
    /// One or more names.
    pub names: Vec<Vec<u8>>,
}

/// An application key writ doesn't interpret (`xwing`, `ssh-ed25519`, …).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpaqueKey {
    /// The application's type name.
    pub kind: Vec<u8>,
    /// The key bytes.
    pub bytes: Vec<u8>,
}

/// What a name or grant is about (DESIGN.md §5.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    /// An identity.
    Id(Id),
    /// A writ leaf key.
    Leaf(LeafKey),
    /// An application key.
    Opaque(OpaqueKey),
    /// Whoever a name path refers to.
    Name(NamePath),
}

impl Subject {
    /// The canonical tree.
    pub fn to_sexp(&self) -> Sexp {
        match self {
            Subject::Id(id) => tagged("id", [Sexp::atom(id.0)]),
            Subject::Leaf(k) => k.to_sexp(),
            Subject::Opaque(k) => tagged("key", [Sexp::atom(&k.kind), Sexp::atom(&k.bytes)]),
            Subject::Name(p) => tagged(
                "name",
                core::iter::once(Sexp::atom(p.base.0)).chain(p.names.iter().map(Sexp::atom)),
            ),
        }
    }

    /// Parses a subject tree.
    pub fn from_sexp(s: &Sexp) -> Result<Subject> {
        let head = match s.as_list() {
            Some([Sexp::Atom(h), ..]) => h.as_slice(),
            _ => return bad("subject"),
        };
        match head {
            b"id" => {
                let mut f = Fields::of(s, "id", "subject")?;
                let id = Id(atom32(f.atom("subject id")?, "subject id")?);
                f.end("subject id")?;
                Ok(Subject::Id(id))
            }
            b"key" => {
                let mut f = Fields::of(s, "key", "subject")?;
                let kind = bounded_atom(f.atom("key type")?, 1, MAX_OPAQUE_TYPE, "key type")?;
                if !kind.iter().all(|&b| writ_sexp::readable::is_token_byte(b)) {
                    return bad("key type must be a token");
                }
                let bytes = bounded_atom(f.atom("key")?, 1, MAX_OPAQUE_KEY, "key length")?;
                f.end("key")?;
                Ok(Subject::Opaque(OpaqueKey { kind, bytes }))
            }
            b"name" => {
                let mut f = Fields::of(s, "name", "subject")?;
                let base = Id(atom32(f.atom("name base")?, "name base")?);
                let mut names = Vec::new();
                while !f.is_empty() {
                    names.push(bounded_atom(f.atom("name")?, 1, MAX_ATOM, "name length")?);
                }
                if names.is_empty() || names.len() > MAX_NAME_PATH {
                    return bad("name path length");
                }
                Ok(Subject::Name(NamePath { base, names }))
            }
            _ => LeafKey::from_sexp(s).map(Subject::Leaf),
        }
    }
}

/// The kind-specific part of a statement (DESIGN.md §5.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Claim {
    /// "In my namespace, `name` refers to `subject`."
    Name {
        /// The local name.
        name: Vec<u8>,
        /// What it refers to.
        subject: Subject,
    },
    /// "`subject` holds each of `tags`." (DESIGN.md §18.2)
    Grant {
        /// The grantee.
        subject: Subject,
        /// What is granted: as many grants as there are tags.
        tags: Tags,
        /// Whether the subject may grant onward.
        delegate: bool,
    },
    /// "My statement or signature with hash `target` is revoked."
    Revoke {
        /// The revoked item's hash.
        target: Hash,
    },
}

impl Claim {
    /// The subject of a name or grant.
    pub fn subject(&self) -> Option<&Subject> {
        match self {
            Claim::Name { subject, .. } | Claim::Grant { subject, .. } => Some(subject),
            Claim::Revoke { .. } => None,
        }
    }

    /// Whether the subject is a leaf key.
    pub fn is_about_leaf(&self) -> bool {
        matches!(self.subject(), Some(Subject::Leaf(_)))
    }
}

/// A statement body (DESIGN.md §5.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Statement {
    /// Who says so.
    pub issuer: Issuer,
    /// When, per the issuer.
    pub issued: Time,
    /// Validity end, exclusive. Absent: indefinite.
    pub expires: Option<Time>,
    /// Display-only text.
    pub note: Option<String>,
    /// What is said.
    pub claim: Claim,
}

/// The leaf ceiling (DESIGN.md §7): a name or grant whose subject is a leaf
/// key lives at most this long.
pub const LEAF_CEILING: u64 = 24 * 3600;

impl Statement {
    /// The statement kind as a word: `name`, `grant`, or `revoke`.
    pub fn kind(&self) -> &'static str {
        match self.claim {
            Claim::Name { .. } => "name",
            Claim::Grant { .. } => "grant",
            Claim::Revoke { .. } => "revoke",
        }
    }

    /// Whether the leaf ceiling applies: the subject is a leaf key, or a
    /// leaf key issued it (DESIGN.md §7). Everything a leaf touches lives at
    /// most a day, so what a stolen or forged leaf key says dies with it.
    pub fn touches_leaf(&self) -> bool {
        self.claim.is_about_leaf() || matches!(self.issuer, Issuer::Leaf(_))
    }

    /// The rules every statement must satisfy regardless of who checks it or
    /// when: issuers and verifiers both apply them.
    pub fn check_wellformed(&self) -> core::result::Result<(), &'static str> {
        if let Some(expires) = self.expires
            && expires <= self.issued
        {
            return Err("expires must be after issued");
        }
        match (&self.issuer, &self.claim) {
            (
                Issuer::Leaf(_),
                Claim::Grant {
                    delegate: false, ..
                },
            ) => {}
            (Issuer::Leaf(_), Claim::Grant { delegate: true, .. }) => {
                return Err("a leaf key may only issue non-delegable grants");
            }
            (Issuer::Leaf(_), _) => return Err("a leaf key may only issue grants"),
            (Issuer::Identity { .. }, _) => {}
        }
        if self.touches_leaf() {
            match self.expires {
                None => return Err("a statement for or by a leaf key must expire"),
                Some(e) if e - self.issued > LEAF_CEILING => {
                    return Err("a statement for or by a leaf key may last at most 24 hours");
                }
                Some(_) => {}
            }
        }
        match &self.claim {
            Claim::Grant {
                subject: Subject::Opaque(_),
                delegate: true,
                ..
            } => return Err("an opaque key cannot delegate"),
            Claim::Revoke { .. } if self.expires.is_some() => {
                return Err("revocations do not expire");
            }
            _ => {}
        }
        Ok(())
    }
}

impl Body for Statement {
    const LABEL: &'static str = label::STATEMENT;

    fn item(signed: &Signed<Self>) -> Item {
        Item::Statement(signed.clone())
    }

    fn to_sexp(&self) -> Sexp {
        let mut items = vec![
            Sexp::atom(self.kind()),
            self.issuer.to_sexp(),
            tagged("issued", [num(self.issued)]),
        ];
        if let Some(e) = self.expires {
            items.push(tagged("expires", [num(e)]));
        }
        if let Some(n) = &self.note {
            items.push(tagged("note", [Sexp::atom(n)]));
        }
        match &self.claim {
            Claim::Name { name, subject } => {
                items.push(Sexp::atom(name));
                items.push(subject.to_sexp());
            }
            Claim::Grant {
                subject,
                tags,
                delegate,
            } => {
                items.push(subject.to_sexp());
                items.extend(tags.iter().map(Tag::to_sexp));
                if *delegate {
                    items.push(tagged("delegate", []));
                }
            }
            Claim::Revoke { target } => items.push(tagged("target", [Sexp::atom(target.0)])),
        }
        Sexp::List(items)
    }

    fn from_sexp(s: &Sexp) -> Result<Statement> {
        let kind = match s.as_list() {
            Some([Sexp::Atom(k), ..]) => k.as_slice(),
            _ => return bad("statement"),
        };
        let kind_str = match kind {
            b"name" => "name",
            b"grant" => "grant",
            b"revoke" => "revoke",
            _ => return bad("unknown statement kind"),
        };
        let mut f = Fields::of(s, kind_str, "statement")?;
        let issuer = Issuer::from_sexp(f.next("issuer")?)?;
        let issued = decimal(f.single("issued", "issued")?, "issued")?;
        let expires = f
            .optional_single("expires", "expires")?
            .map(|a| decimal(a, "expires"))
            .transpose()?;
        let note = f
            .optional_single("note", "note")?
            .map(|a| {
                if a.len() > MAX_NOTE {
                    return bad("note too long");
                }
                String::from_utf8(a.to_vec()).map_err(|_| DecodeError::Malformed("note not UTF-8"))
            })
            .transpose()?;
        let claim = match kind {
            b"name" => {
                let name = bounded_atom(f.atom("name")?, 1, MAX_ATOM, "name length")?;
                let subject = Subject::from_sexp(f.next("subject")?)?;
                Claim::Name { name, subject }
            }
            b"grant" => {
                let subject = Subject::from_sexp(f.next("subject")?)?;
                let n = f
                    .items
                    .iter()
                    .take_while(|s| Fields::head_of(s) == Some(b"tag"))
                    .count();
                let (tag_items, rest) = f.items.split_at(n);
                f.items = rest;
                let tags = Tags::from_sexps(tag_items)?;
                let delegate = match f.optional("delegate", "delegate")? {
                    Some(d) => {
                        d.end("delegate")?;
                        true
                    }
                    None => false,
                };
                Claim::Grant {
                    subject,
                    tags,
                    delegate,
                }
            }
            _ => Claim::Revoke {
                target: Hash(atom32(f.single("target", "target")?, "target")?),
            },
        };
        f.end("statement")?;
        Ok(Statement {
            issuer,
            issued,
            expires,
            note,
            claim,
        })
    }
}

// ---------------------------------------------------------------------------
// Data signatures

/// A signature over application data (DESIGN.md §8). The signed body.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DataSig {
    /// Who signed.
    pub signer: Issuer,
    /// When, per the signer.
    pub issued: Time,
    /// Application-chosen domain separation, e.g. `zuko/locator/v1`.
    pub context: Vec<u8>,
    /// [`Hash::of_data`] of the signed data.
    pub data: Hash,
}

impl Body for DataSig {
    const LABEL: &'static str = label::SIGNATURE;

    fn item(signed: &Signed<Self>) -> Item {
        Item::Signature(signed.clone())
    }

    /// An identity never signs under writ's own contexts (SPEC §5.5): those
    /// are for leaf keys, through [`crate::channel`].
    fn check_signable(&self) -> core::result::Result<(), &'static str> {
        if self.context.starts_with(crate::issue::RESERVED_CONTEXT) {
            return Err("contexts starting with writ/ are reserved for writ");
        }
        Ok(())
    }

    fn to_sexp(&self) -> Sexp {
        tagged(
            "signature",
            [
                self.signer.to_sexp(),
                tagged("issued", [num(self.issued)]),
                tagged("context", [Sexp::atom(&self.context)]),
                tagged("data", [Sexp::atom(self.data.0)]),
            ],
        )
    }

    fn from_sexp(s: &Sexp) -> Result<DataSig> {
        let mut f = Fields::of(s, "signature", "signature")?;
        let signer = Issuer::from_sexp(f.next("signer")?)?;
        let issued = decimal(f.single("issued", "issued")?, "issued")?;
        let context = bounded_atom(f.single("context", "context")?, 1, MAX_ATOM, "context")?;
        let data = Hash(atom32(f.single("data", "data")?, "data hash")?);
        f.end("signature")?;
        Ok(DataSig {
            signer,
            issued,
            context,
            data,
        })
    }
}

// ---------------------------------------------------------------------------
// Records

/// A revocation record (DESIGN.md §18.4): "as of `issued`, my log's head is
/// `head`, and these are all the statements and data signatures I have
/// revoked." Signed by the current authority of event `event`, which must
/// be the head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    /// The identity.
    pub id: Id,
    /// The event the record is made under: the log's head.
    pub event: u64,
    /// When it was signed.
    pub issued: Time,
    /// Hash of the head event.
    pub head: Hash,
    /// Every statement and data signature revoked, sorted and distinct.
    pub revoked: Vec<Hash>,
}

impl Record {
    /// Whether `hash` is in the revoked list.
    pub fn revokes(&self, hash: &Hash) -> bool {
        self.revoked.binary_search(hash).is_ok()
    }
}

impl Body for Record {
    const LABEL: &'static str = label::RECORD;

    fn item(signed: &Signed<Self>) -> Item {
        Item::Record(signed.clone())
    }

    fn to_sexp(&self) -> Sexp {
        tagged(
            "record",
            [
                Issuer::Identity {
                    id: self.id,
                    event: self.event,
                }
                .to_sexp(),
                tagged("issued", [num(self.issued)]),
                tagged("head", [Sexp::atom(self.head.0)]),
                tagged("revoked", self.revoked.iter().map(|h| Sexp::atom(h.0))),
            ],
        )
    }

    fn from_sexp(s: &Sexp) -> Result<Record> {
        let mut f = Fields::of(s, "record", "record")?;
        let Issuer::Identity { id, event } = Issuer::from_sexp(f.next("issuer")?)? else {
            return bad("records are made by identities");
        };
        let issued = decimal(f.single("issued", "issued")?, "issued")?;
        let head = Hash(atom32(f.single("head", "head")?, "head hash")?);
        let mut rf = f.field("revoked", "revoked")?;
        let mut revoked = Vec::new();
        while !rf.is_empty() {
            revoked.push(Hash(atom32(rf.atom("revoked")?, "revoked hash")?));
        }
        f.end("record")?;
        if !revoked.windows(2).all(|w| w.first() < w.get(1)) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Record {
            id,
            event,
            issued,
            head,
            revoked,
        })
    }
}

// ---------------------------------------------------------------------------
// Signed items

/// One signature attached to a body: `index` is the signing key's position
/// in the signer's authority (always 0 for leaf keys).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sig {
    /// Key index.
    pub index: u8,
    /// Signature bytes.
    pub bytes: Vec<u8>,
}

/// A body with signatures attached. Signatures are not part of the hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T> {
    /// What was signed.
    pub body: T,
    /// Signatures: strictly increasing by index when decoded; in any order,
    /// possibly several per index, once [`Material`](crate::Material) has
    /// merged copies.
    pub sigs: Vec<Sig>,
}

impl<T: Body> Signed<T> {
    /// Whether at least `authority.k()` distinct keys of `authority` signed.
    pub fn verify_threshold(&self, authority: &Authority) -> bool {
        self.valid_indices(authority).count_ones() as usize >= authority.k()
    }

    /// Bitmask of authority key indices with at least one valid signature.
    /// Stops early once `k` are found; duplicates of an index count once.
    pub fn valid_indices(&self, authority: &Authority) -> u32 {
        let msg = self.body.message();
        let mut seen = 0u32;
        for sig in &self.sigs {
            if seen.count_ones() as usize >= authority.k() {
                break;
            }
            let bit = 1u32 << sig.index.min(31);
            if seen & bit != 0 {
                continue;
            }
            if let Some(key) = authority.keys().get(usize::from(sig.index))
                && key.verify(&msg, &sig.bytes)
            {
                seen |= bit;
            }
        }
        seen
    }

    /// Whether a signature at index 0 verifies under a leaf key.
    pub fn verify_leaf(&self, key: &LeafKey) -> bool {
        let msg = self.body.message();
        self.sigs
            .iter()
            .any(|s| s.index == 0 && key.verify(&msg, &s.bytes))
    }

    /// The first valid signature for each index of `authority`, in index
    /// order: what to ship, so junk merged alongside never travels.
    pub fn valid_sigs(&self, authority: &Authority) -> Vec<Sig> {
        let msg = self.body.message();
        let mut out: Vec<Sig> = Vec::new();
        for sig in &self.sigs {
            if out.iter().any(|s| s.index == sig.index) {
                continue;
            }
            if let Some(key) = authority.keys().get(usize::from(sig.index))
                && key.verify(&msg, &sig.bytes)
            {
                out.push(sig.clone());
            }
        }
        out.sort_by_key(|s| s.index);
        out
    }

    /// The first valid leaf signature, if any.
    pub fn valid_leaf_sigs(&self, key: &LeafKey) -> Vec<Sig> {
        let msg = self.body.message();
        self.sigs
            .iter()
            .find(|s| s.index == 0 && key.verify(&msg, &s.bytes))
            .cloned()
            .into_iter()
            .collect()
    }
}

/// Anything that can appear in a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// An identity log event.
    Event(Signed<Event>),
    /// A name, grant, or revocation.
    Statement(Signed<Statement>),
    /// A data signature.
    Signature(Signed<DataSig>),
    /// A revocation record (DESIGN.md §18.4).
    Record(Signed<Record>),
    /// A bare public key (for naming leaf or root keys in files).
    PublicKey(PublicKey),
    /// A bare authority (an identity's pending next authority).
    Authority(Authority),
}

impl Item {
    /// `(writ/v1 BODY SIG…)`.
    pub fn to_sexp(&self) -> Sexp {
        fn signed<T: Body>(s: &Signed<T>) -> Vec<Sexp> {
            core::iter::once(s.body.to_sexp())
                .chain(
                    s.sigs.iter().map(|sig| {
                        tagged("sig", [num(u64::from(sig.index)), Sexp::atom(&sig.bytes)])
                    }),
                )
                .collect()
        }
        let rest = match self {
            Item::Event(s) => signed(s),
            Item::Statement(s) => signed(s),
            Item::Signature(s) => signed(s),
            Item::Record(s) => signed(s),
            Item::PublicKey(k) => vec![k.to_sexp()],
            Item::Authority(a) => vec![a.to_sexp()],
        };
        tagged(VERSION, rest)
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.to_sexp().encode()
    }

    /// The armored text.
    pub fn armor(&self) -> String {
        writ_sexp::armor::encode(&self.encode())
    }

    /// Decodes one canonical item.
    pub fn decode(bytes: &[u8]) -> Result<Item> {
        let sexp =
            writ_sexp::decode(bytes, &writ_sexp::Limits::default()).map_err(DecodeError::Sexp)?;
        let item = Item::from_sexp(&sexp)?;
        if item.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(item)
    }

    /// Decodes a bundle: armored blocks, or concatenated canonical items.
    pub fn decode_bundle(bytes: &[u8]) -> Result<Vec<Item>> {
        if bytes.len() > MAX_BUNDLE {
            return Err(DecodeError::Sexp(writ_sexp::DecodeError::TooLarge));
        }
        if writ_sexp::armor::is_armored(bytes) {
            // Each block is bounded before it is base64-decoded, so an
            // oversized block costs no more than in the binary form.
            writ_sexp::armor::decode_bounded(bytes, writ_sexp::Limits::default().max_len)
                .map_err(DecodeError::Armor)?
                .iter()
                .map(|b| Item::decode(b))
                .collect()
        } else if bytes
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            Ok(Vec::new())
        } else {
            // One item at a time, each under the per-item limits, so the
            // decoded trees in memory never exceed one item's.
            let mut items = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let (sexp, n) = writ_sexp::decode_prefix(rest, &writ_sexp::Limits::default())
                    .map_err(DecodeError::Sexp)?;
                let item = Item::from_sexp(&sexp)?;
                if item.to_sexp() != sexp {
                    return Err(DecodeError::NonCanonical);
                }
                items.push(item);
                rest = rest.get(n..).unwrap_or_default();
            }
            Ok(items)
        }
    }

    fn from_sexp(s: &Sexp) -> Result<Item> {
        let mut f = match s.as_list() {
            Some([Sexp::Atom(v), ..]) if v == VERSION.as_bytes() => Fields::of(s, VERSION, "item")?,
            _ => return Err(DecodeError::Version),
        };
        let body = f.next("item body")?;
        let head = match body.as_list() {
            Some([Sexp::Atom(h), ..]) => h.as_slice(),
            _ => return bad("item body"),
        };
        fn sigs(f: &mut Fields<'_>, size: Option<usize>) -> Result<Vec<Sig>> {
            let mut out: Vec<Sig> = Vec::new();
            while !f.is_empty() {
                let mut sf = f.field("sig", "signature")?;
                let index = decimal(sf.atom("signature index")?, "signature index")?;
                let index = u8::try_from(index)
                    .ok()
                    .filter(|i| usize::from(*i) < MAX_AUTHORITY_KEYS)
                    .ok_or(DecodeError::Malformed("signature index"))?;
                let bytes = sf.atom("signature")?;
                sf.end("signature")?;
                if size.is_some_and(|n| bytes.len() != n) {
                    return bad("signature length");
                }
                if out.last().is_some_and(|last| last.index >= index) {
                    return Err(DecodeError::NonCanonical);
                }
                out.push(Sig {
                    index,
                    bytes: bytes.to_vec(),
                });
            }
            if out.is_empty() {
                return bad("unsigned item");
            }
            Ok(out)
        }
        fn leaf_index_zero(issuer: &Issuer, sigs: &[Sig]) -> Result<()> {
            if matches!(issuer, Issuer::Leaf(_)) && sigs.iter().any(|s| s.index != 0) {
                return bad("leaf signatures use index 0");
            }
            Ok(())
        }
        fn sig_size(issuer: &Issuer) -> usize {
            match issuer {
                Issuer::Identity { .. } => ROOT_SIGNATURE_SIZE,
                Issuer::Leaf(_) => LEAF_SIGNATURE_SIZE,
            }
        }
        let item = match head {
            b"inception" | b"rotation" => {
                let body = Event::from_sexp(body)?;
                let sigs = sigs(&mut f, Some(ROOT_SIGNATURE_SIZE))?;
                if sigs
                    .iter()
                    .any(|s| usize::from(s.index) >= body.signers().keys().len())
                {
                    return bad("signature index outside authority");
                }
                Item::Event(Signed { body, sigs })
            }
            b"name" | b"grant" | b"revoke" => {
                let body = Statement::from_sexp(body)?;
                let sigs = sigs(&mut f, Some(sig_size(&body.issuer)))?;
                leaf_index_zero(&body.issuer, &sigs)?;
                Item::Statement(Signed { body, sigs })
            }
            b"signature" => {
                let body = DataSig::from_sexp(body)?;
                let sigs = sigs(&mut f, Some(sig_size(&body.signer)))?;
                leaf_index_zero(&body.signer, &sigs)?;
                Item::Signature(Signed { body, sigs })
            }
            b"record" => {
                let body = Record::from_sexp(body)?;
                let sigs = sigs(&mut f, Some(ROOT_SIGNATURE_SIZE))?;
                Item::Record(Signed { body, sigs })
            }
            b"authority" => {
                let a = Authority::from_sexp(body)?;
                f.end("authority item")?;
                Item::Authority(a)
            }
            b"slh-dsa-shake-128s" | b"mldsa65-ed25519" => {
                let k = PublicKey::from_sexp(body)?;
                f.end("key item")?;
                Item::PublicKey(k)
            }
            _ => return bad("unknown item kind"),
        };
        Ok(item)
    }

    /// A short word for the item's kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Item::Event(e) => match e.body {
                Event::Inception(_) => "inception",
                Event::Rotation(_) => "rotation",
            },
            Item::Statement(s) => s.body.kind(),
            Item::Signature(_) => "signature",
            Item::Record(_) => "record",
            Item::PublicKey(_) => "key",
            Item::Authority(_) => "authority",
        }
    }
}
