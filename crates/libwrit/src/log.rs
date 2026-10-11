//! Identity logs (DESIGN.md §4): validation, the chain rule, equivocation.

use crate::hash::{Hash, Id};
use crate::model::{Body, Event, Item, Signed};
use core::fmt;

/// A validated identity log: events `0..=head`, each signed by `k` of its own
/// authority, each rotation revealing the authority its predecessor
/// committed to and naming its predecessor's hash.
#[derive(Clone, Debug)]
pub struct Log {
    id: Id,
    inception: Signed<Event>,
    rotations: Vec<Signed<Event>>,
    hashes: Vec<Hash>,
}

impl Log {
    /// Builds a log from candidate events: `inception` and, per event number
    /// `n ≥ 1`, every rotation claiming `(id, n)`.
    ///
    /// Rotations not signed by the authority the previous event committed to
    /// are ignored (anyone can make them). Two different rotations at the
    /// same `n` that *are* signed by it are equivocation; one that is signed
    /// by it but names the wrong predecessor breaks the log. Both fail closed.
    pub fn build<'a>(
        inception: &Signed<Event>,
        mut rotations_at: impl FnMut(u64) -> Vec<&'a Signed<Event>>,
    ) -> Result<Log, LogError> {
        let Event::Inception(_) = inception.body else {
            return Err(LogError::NoInception);
        };
        // Keep only verified signatures (one per index): a log, and anything
        // derived from it, never carries junk merged in from other copies.
        let Some(inception) = verified(inception, inception.body.authority()) else {
            return Err(LogError::BadSignature { n: 0 });
        };
        let id = inception.body.id();
        let mut log = Log {
            id,
            hashes: vec![inception.body.hash()],
            inception,
            rotations: Vec::new(),
        };
        loop {
            let n = log.head_n() + 1;
            let committed = *log.head().next();
            let mut candidates: Vec<(Signed<Event>, Hash)> = Vec::new();
            for ev in rotations_at(n) {
                let Event::Rotation(r) = &ev.body else {
                    continue;
                };
                if r.id != id || r.n != n || r.authority.hash() != committed {
                    continue;
                }
                let h = ev.body.hash();
                if candidates.iter().any(|(_, c)| *c == h) {
                    continue;
                }
                if let Some(ev) = verified(ev, &r.authority) {
                    candidates.push((ev, h));
                }
            }
            match candidates.as_slice() {
                [] => return Ok(log),
                [(a, _), (b, _), ..] => {
                    return Err(LogError::Equivocation(Box::new(Evidence {
                        prefix: log.events().cloned().collect(),
                        a: a.clone(),
                        b: b.clone(),
                    })));
                }
                [(ev, h)] => {
                    let Event::Rotation(r) = &ev.body else {
                        return Ok(log);
                    };
                    if Some(&r.prev) != log.hashes.last() {
                        return Err(LogError::Broken { n });
                    }
                    log.rotations.push(ev.clone());
                    log.hashes.push(*h);
                }
            }
        }
    }

    /// The identity.
    pub fn id(&self) -> Id {
        self.id
    }

    /// The latest event.
    pub fn head(&self) -> &Event {
        &self.head_signed().body
    }

    /// The latest event with its signatures.
    pub fn head_signed(&self) -> &Signed<Event> {
        self.rotations.last().unwrap_or(&self.inception)
    }

    /// The latest event number.
    pub fn head_n(&self) -> u64 {
        self.rotations.len() as u64
    }

    /// Event `n`, if the log reaches it.
    pub fn event(&self, n: u64) -> Option<&Event> {
        match usize::try_from(n).ok()? {
            0 => Some(&self.inception.body),
            i => self.rotations.get(i - 1).map(|e| &e.body),
        }
    }

    /// Hash of event `n`.
    pub fn event_hash(&self, n: u64) -> Option<Hash> {
        self.hashes.get(usize::try_from(n).ok()?).copied()
    }

    /// All events, oldest first.
    pub fn events(&self) -> impl Iterator<Item = &Signed<Event>> {
        core::iter::once(&self.inception).chain(&self.rotations)
    }

    /// Whether the latest rotation keeps `hash`.
    pub fn keeps(&self, hash: &Hash) -> bool {
        self.head().keep().binary_search(hash).is_ok()
    }

    /// The log as bundle items.
    pub fn items(&self) -> impl Iterator<Item = Item> + '_ {
        self.events().cloned().map(Item::Event)
    }
}

/// Why an identity's log is unusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    /// No inception for this id in the material.
    NoInception,
    /// Event `n` lacks `k` valid signatures.
    BadSignature {
        /// Event number.
        n: u64,
    },
    /// Rotation `n` is signed by the committed authority but does not chain
    /// to event `n − 1`.
    Broken {
        /// Event number.
        n: u64,
    },
    /// Two validly signed events at the same position.
    Equivocation(Box<Evidence>),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::NoInception => write!(f, "no identity log"),
            LogError::BadSignature { n } => write!(f, "event {n} is not validly signed"),
            LogError::Broken { n } => {
                write!(
                    f,
                    "rotation {n} is signed but does not chain to event {}",
                    n - 1
                )
            }
            LogError::Equivocation(e) => write!(
                f,
                "equivocation: two different events numbered {} — the identity is compromised",
                e.n()
            ),
        }
    }
}

/// Proof that an identity's next authority signed two different events at
/// the same position (DESIGN.md §4.4). Self-contained: [`Evidence::items`]
/// can be shipped to anyone, and [`Evidence::verify`] checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The valid log up to event `n − 1`.
    pub prefix: Vec<Signed<Event>>,
    /// One event at `n`.
    pub a: Signed<Event>,
    /// Another.
    pub b: Signed<Event>,
}

impl Evidence {
    /// The identity.
    pub fn id(&self) -> Id {
        self.a.body.id()
    }

    /// The contested event number.
    pub fn n(&self) -> u64 {
        self.a.body.n()
    }

    /// Re-checks the evidence from scratch.
    pub fn verify(&self) -> bool {
        let Some((inception, rest)) = self.prefix.split_first() else {
            return false;
        };
        let rest: Vec<&Signed<Event>> = rest.iter().collect();
        let prefix = Log::build(inception, |n| {
            rest.iter().copied().filter(|e| e.body.n() == n).collect()
        });
        let Ok(prefix) = prefix else {
            return false;
        };
        if prefix.head_n() + 1 != self.n() {
            return false;
        }
        let both = [&self.a, &self.b];
        let result = Log::build(inception, |n| {
            if n == self.n() {
                both.to_vec()
            } else {
                rest.iter().copied().filter(|e| e.body.n() == n).collect()
            }
        });
        matches!(result, Err(LogError::Equivocation(_)))
    }

    /// The evidence as bundle items.
    pub fn items(&self) -> Vec<Item> {
        self.prefix
            .iter()
            .chain([&self.a, &self.b])
            .cloned()
            .map(Item::Event)
            .collect()
    }
}

/// Whether two events claim the same `(id, n)` with different contents.
/// Signatures are not checked here; see [`Log::build`] for the full rule.
pub fn equivocation(a: &Signed<Event>, b: &Signed<Event>) -> bool {
    a.body.id() == b.body.id() && a.body.n() == b.body.n() && a.body.hash() != b.body.hash()
}

/// `event` with only its valid signatures, if they reach the threshold.
fn verified(event: &Signed<Event>, authority: &crate::model::Authority) -> Option<Signed<Event>> {
    let sigs = event.valid_sigs(authority);
    (sigs.len() >= authority.k()).then(|| Signed {
        body: event.body.clone(),
        sigs,
    })
}
