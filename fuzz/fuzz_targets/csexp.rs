//! Canonical csexp: whatever decodes re-encodes to exactly the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use writ_sexp::{Limits, decode, decode_prefix};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    if let Ok(s) = decode(data, &limits) {
        assert_eq!(s.encode(), data);
    }
    if let Ok((s, n)) = decode_prefix(data, &limits) {
        assert_eq!(Some(s.encode().as_slice()), data.get(..n));
    }
});
