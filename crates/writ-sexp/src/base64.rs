//! Standard padded base64 (RFC 4648 §4), strict: decoding rejects missing or
//! excess padding, non-zero trailing bits, and any byte outside the alphabet.

use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` as padded base64.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = (n >> (18 - 6 * i)) & 63;
                out.push(char::from(
                    ALPHABET.get(idx as usize).copied().unwrap_or(b'='),
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

/// Decodes strict padded base64. Returns `None` on any deviation from the
/// unique canonical encoding.
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let (chunks, rest) = text.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let quads = chunks.len();
    for (i, quad) in chunks.iter().enumerate() {
        let last = i + 1 == quads;
        let pad = match quad {
            [_, _, b'=', b'='] if last => 2,
            [_, _, _, b'='] if last => 1,
            _ => 0,
        };
        let mut n = 0u32;
        for (j, &c) in quad.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(c)? };
            n = n << 6 | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        match pad {
            // The bits under the padding must be zero for the encoding to be canonical.
            2 if n & 0xffff != 0 => return None,
            1 if n & 0xff != 0 => return None,
            _ => {}
        }
        out.extend_from_slice(bytes.get(..3 - pad)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), enc);
            assert_eq!(decode(enc.as_bytes()).as_deref(), Some(raw));
        }
    }

    #[test]
    fn rejects_non_canonical() {
        for bad in [
            "Zg", "Zg=", "Zh==", "Zm9=", "Zm9v=", "Zg==Zg==", "Zm9v\n", "Zm-v", "Z===", "====",
        ] {
            assert_eq!(decode(bad.as_bytes()), None, "{bad}");
        }
    }
}
