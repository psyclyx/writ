//! Strict armor: whatever decodes is canonical base64 that armors back to
//! blocks decoding to the same bytes, and the input was that canonical text
//! itself (CRLF for LF allowed), with only whitespace around the blocks. The
//! second check is what catches a lax decoder: re-armoring would normalise
//! a 65-column line or non-canonical base64 away.
#![no_main]

use libfuzzer_sys::fuzz_target;
use writ_sexp::armor;

fuzz_target!(|data: &[u8]| {
    let Ok(blocks) = armor::decode(data) else {
        return;
    };
    let again: String = blocks.iter().map(|b| armor::encode(b)).collect();
    assert_eq!(armor::decode(again.as_bytes()), Ok(blocks.clone()));
    // The input is the canonical blocks, in order, with whitespace between.
    let text = String::from_utf8(data.to_vec()).expect("armor is ASCII");
    let mut rest: &str = &text.replace("\r\n", "\n");
    for block in &blocks {
        rest = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        let canonical = armor::encode(block);
        match rest.strip_prefix(&canonical) {
            Some(r) => rest = r,
            // The final newline may be missing at the end of the input.
            None => match canonical
                .strip_suffix('\n')
                .and_then(|c| rest.strip_prefix(c))
            {
                Some(r) => rest = r,
                None => panic!("block accepted that is not its canonical text"),
            },
        }
    }
    assert!(
        rest.trim_matches([' ', '\t', '\r', '\n']).is_empty(),
        "trailing input"
    );
});
