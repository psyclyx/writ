//! Strict armor: whatever decodes is canonical base64 that armors back to
//! blocks decoding to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use writ_sexp::armor;

fuzz_target!(|data: &[u8]| {
    if let Ok(blocks) = armor::decode(data) {
        let again: String = blocks.iter().map(|b| armor::encode(b)).collect();
        assert_eq!(armor::decode(again.as_bytes()), Ok(blocks));
    }
});
