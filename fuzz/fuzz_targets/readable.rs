//! The readable form: printing what parsed and parsing it again gives the
//! same tree.
#![no_main]

use libfuzzer_sys::fuzz_target;
use writ_sexp::readable;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(s) = readable::parse(text) {
        assert_eq!(readable::parse(&readable::print(&s)), Ok(s));
    }
    if let Ok(many) = readable::parse_many(text) {
        for s in many {
            assert_eq!(readable::parse(&readable::print(&s)), Ok(s));
        }
    }
});
