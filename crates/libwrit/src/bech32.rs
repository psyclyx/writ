//! Bech32m (BIP-350) for byte payloads, with BIP-173's length and case rules.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const MAX_LEN: usize = 90;

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> impl Iterator<Item = u8> + '_ {
    hrp.iter()
        .map(|c| c >> 5)
        .chain(core::iter::once(0))
        .chain(hrp.iter().map(|c| c & 31))
}

/// Regroups bits. With `pad`, emits a final partial group; without, rejects
/// more than 4 bits of padding or non-zero padding.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &v in data {
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || acc != 0 {
        return None;
    }
    Some(out)
}

/// Encodes `data` under `hrp` (which must be lower-case ASCII). Lower-case output.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let hrp_bytes = hrp.as_bytes();
    let five = convert_bits(data, 8, 5, true).unwrap_or_default();
    let chk = polymod(
        hrp_expand(hrp_bytes)
            .chain(five.iter().copied())
            .chain([0u8; 6]),
    ) ^ BECH32M_CONST;
    let mut s = String::with_capacity(hrp.len() + 1 + five.len() + 6);
    s.push_str(hrp);
    s.push('1');
    let checksum = (0..6).map(|i| ((chk >> (5 * (5 - i))) & 31) as u8);
    for v in five.iter().copied().chain(checksum) {
        s.push(char::from(
            CHARSET.get(usize::from(v)).copied().unwrap_or(b'q'),
        ));
    }
    s
}

/// Decodes a bech32m string into its lower-case hrp and payload bytes.
/// Rejects mixed case, bad characters, bad checksums, non-zero padding, and
/// strings over 90 characters.
pub fn decode(text: &str) -> Option<(String, Vec<u8>)> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_LEN || bytes.iter().any(|&b| !(33..=126).contains(&b)) {
        return None;
    }
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    if has_lower && has_upper {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let sep = lower.rfind('1')?;
    let (hrp, rest) = lower.split_at(sep);
    let data_part = rest.get(1..)?;
    if hrp.is_empty() || data_part.len() < 6 {
        return None;
    }
    let values: Vec<u8> = data_part
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()?;
    if polymod(hrp_expand(hrp.as_bytes()).chain(values.iter().copied())) != BECH32M_CONST {
        return None;
    }
    let payload = values.get(..values.len() - 6)?;
    let data = convert_bits(payload, 5, 8, false)?;
    Some((hrp.to_owned(), data))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// BIP-350 "valid Bech32m" vectors: checksum and structure.
    #[test]
    fn bip350_valid_checksums() {
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            assert!(checksum_ok(s), "{s}");
        }
    }

    /// BIP-350 "invalid Bech32m" vectors.
    #[test]
    fn bip350_invalid() {
        for s in [
            "\u{20}1xj0phk",
            "\u{7f}1g6xzxy",
            "\u{80}1vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m",
            "1qyrz8wqd2c9m",
            "y1b0jsk6g",
            "lt1igcx5c0",
            "in1muywd",
            "mm1crxm3i",
            "au1s5cgom",
            "M1VUXWEZ",
            "16plkw9",
            "1p2gdwpf",
        ] {
            assert!(!checksum_ok(s), "{s:?}");
            assert_eq!(decode(s), None, "{s:?}");
        }
    }

    /// Checksum/structure validity without the 8-bit payload conversion, which
    /// BIP-350's generic vectors don't promise.
    fn checksum_ok(s: &str) -> bool {
        let bytes = s.as_bytes();
        if bytes.len() > MAX_LEN || bytes.iter().any(|&b| !(33..=126).contains(&b)) {
            return false;
        }
        if bytes.iter().any(u8::is_ascii_lowercase) && bytes.iter().any(u8::is_ascii_uppercase) {
            return false;
        }
        let lower = s.to_ascii_lowercase();
        let Some(sep) = lower.rfind('1') else {
            return false;
        };
        let (hrp, rest) = lower.split_at(sep);
        let data = &rest[1..];
        if hrp.is_empty() || data.len() < 6 {
            return false;
        }
        let Some(values) = data
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
            .collect::<Option<Vec<u8>>>()
        else {
            return false;
        };
        polymod(hrp_expand(hrp.as_bytes()).chain(values)) == BECH32M_CONST
    }

    /// The BIP-350 segwit vectors exercise the 8↔5 conversion: the witness
    /// program (after the version character) must decode with strict padding.
    #[test]
    fn padding_rules() {
        // "Non-zero padding in 8-to-5 conversion" and "zero padding of more
        // than 4 bits" from BIP-350; checksums are valid, payload isn't.
        for s in [
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        ] {
            assert!(checksum_ok(s));
            let lower = s.to_ascii_lowercase();
            let sep = lower.rfind('1').unwrap_or(0);
            let values: Vec<u8> = lower[sep + 1..]
                .bytes()
                .map(|c| CHARSET.iter().position(|&x| x == c).unwrap_or(0) as u8)
                .collect();
            let program = &values[1..values.len() - 6];
            assert_eq!(convert_bits(program, 5, 8, false), None, "{s}");
        }
        // And a valid one: v1 program 79be667e….
        let s = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        let values: Vec<u8> = s[3..]
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).unwrap_or(0) as u8)
            .collect();
        let program = convert_bits(&values[1..values.len() - 6], 5, 8, false);
        assert_eq!(
            program.map(|p| crate::hash::hex(&p)),
            Some("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into())
        );
    }

    #[test]
    fn round_trip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let s = encode("writ", &data);
            assert_eq!(decode(&s), Some(("writ".into(), data.clone())));
            assert_eq!(decode(&s.to_ascii_uppercase()), Some(("writ".into(), data)));
        }
    }
}
