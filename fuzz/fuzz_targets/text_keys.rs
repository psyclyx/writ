//! bech32m ids and secret key lines: whatever parses prints back to a form
//! that parses to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libwrit::{Id, Seed};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some((hrp, payload)) = libwrit::bech32::decode(text) {
        let again = libwrit::bech32::encode(&hrp, &payload);
        assert_eq!(libwrit::bech32::decode(&again), Some((hrp, payload)));
    }
    if let Some(id) = Id::parse(text) {
        assert_eq!(Id::parse(&id.to_string()), Some(id));
    }
    if let Some(seed) = Seed::parse(text) {
        let again = Seed::parse(&seed.to_text()).map(|s| *s.as_bytes());
        assert_eq!(again, Some(*seed.as_bytes()));
    }
});
