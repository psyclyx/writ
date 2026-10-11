//! Shared test helpers: the vendored-vector parser, hex, and a tiny PRNG.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// One test case: the `key = value` lines of a blank-line-separated block
/// (format documented in vectors/acvp/README.md).
pub struct Case {
    fields: Vec<(String, String)>,
}

impl Case {
    /// The value of `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The value of `key`; panics if absent.
    pub fn str(&self, key: &str) -> &str {
        self.get(key)
            .unwrap_or_else(|| panic!("missing field {key} in case {}", self.id()))
    }

    /// The hex-decoded value of `key`; panics if absent or malformed.
    pub fn hex(&self, key: &str) -> Vec<u8> {
        hex(self.str(key))
    }

    /// The hex-decoded value of `key` as an array; panics on wrong length.
    pub fn arr<const L: usize>(&self, key: &str) -> [u8; L] {
        self.hex(key).try_into().expect("field length")
    }

    /// A label for failure messages.
    pub fn id(&self) -> String {
        format!(
            "tgId {} tcId {}",
            self.get("tgId").unwrap_or("?"),
            self.get("tcId").unwrap_or("?")
        )
    }
}

/// Parse a vector file: `#` lines are comments, blank lines separate cases,
/// every other line is `key = value` (value may be empty).
pub fn parse(text: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut fields = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                cases.push(Case {
                    fields: std::mem::take(&mut fields),
                });
            }
            continue;
        }
        let (k, v) = line.split_once('=').expect("key = value line");
        fields.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    cases
}

/// Decode hex (either case).
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("hex digit"))
        .collect()
}

/// SplitMix64: a small deterministic PRNG for reproducible random tests.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.next_u64() as u8;
        }
    }

    pub fn array<const L: usize>(&mut self) -> [u8; L] {
        let mut a = [0; L];
        self.fill(&mut a);
        a
    }

    /// Random bytes of random length below `max`.
    pub fn bytes_below(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        self.bytes(len)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        self.fill(&mut v);
        v
    }
}
