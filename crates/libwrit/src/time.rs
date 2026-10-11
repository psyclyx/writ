//! Time: seconds since the Unix epoch, the clock floor (DESIGN.md §9.4), and
//! RFC 3339 / duration text for humans. Nothing here reads a clock.

use core::fmt;

/// Seconds since 1970-01-01T00:00:00Z.
pub type Time = u64;

/// The build-time floor: no verifier believes it is earlier than this.
/// Bumped at each release (2026-10-11T00:00:00Z).
pub const BUILD_FLOOR: Time = 1_791_676_800;

/// A clock floor: the latest time the verifier has evidence for.
///
/// The floor is the newest `issued` seen on a valid statement from the
/// verifier's own roots, capped at wall clock + skew, and never below
/// [`BUILD_FLOOR`]. Callers persist [`Floor::value`] and supply the wall clock
/// and monotonic time elapsed since they last set the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    value: Time,
}

impl Floor {
    /// A floor from a persisted value (or none), raised to [`BUILD_FLOOR`].
    pub fn new(persisted: Option<Time>) -> Floor {
        Floor {
            value: persisted.unwrap_or(0).max(BUILD_FLOOR),
        }
    }

    /// The floor itself.
    pub fn value(&self) -> Time {
        self.value
    }

    /// `max(wall, floor + elapsed)`: rolling the clock back can't go below
    /// the floor, and freezing it can't stop monotonic time.
    pub fn now(&self, wall: Time, elapsed_since_set: u64) -> Time {
        wall.max(self.value.saturating_add(elapsed_since_set))
    }

    /// Raises the floor to `witness` (an own-root statement's `issued`),
    /// capped at `wall + skew`. Returns whether the floor moved.
    pub fn observe(&mut self, witness: Time, wall: Time, skew: u64) -> bool {
        let candidate = witness.min(wall.saturating_add(skew));
        if candidate > self.value {
            self.value = candidate;
            true
        } else {
            false
        }
    }
}

/// Days since the epoch → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Displays a [`Time`] as RFC 3339 UTC, e.g. `2026-10-11T14:03:00Z`.
pub struct Rfc3339(pub Time);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = (self.0 / 86_400) as i64;
        let secs = self.0 % 86_400;
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

/// Parses `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS]Z` (UTC only), or a plain
/// decimal Unix time `@SECONDS`.
pub fn parse_time(text: &str) -> Option<Time> {
    if let Some(secs) = text.strip_prefix('@') {
        return parse_decimal(secs);
    }
    let (date, clock) = match text.split_once(['T', 't', ' ']) {
        Some((d, c)) => (d, Some(c)),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let y: i64 = parse_fixed(parts.next()?, 4)?.try_into().ok()?;
    let m = u32::try_from(parse_fixed(parts.next()?, 2)?).ok()?;
    let d = u32::try_from(parse_fixed(parts.next()?, 2)?).ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    let mut secs = 0u64;
    if let Some(clock) = clock {
        let clock = clock.strip_suffix(['Z', 'z'])?;
        let mut parts = clock.split(':');
        let h = parse_fixed(parts.next()?, 2)?;
        let min = parse_fixed(parts.next()?, 2)?;
        let s = match parts.next() {
            Some(s) => parse_fixed(s, 2)?,
            None => 0,
        };
        if parts.next().is_some() || h > 23 || min > 59 || s > 59 {
            return None;
        }
        secs = h * 3600 + min * 60 + s;
    }
    let days = u64::try_from(days_from_civil(y, m, d)).ok()?;
    days.checked_mul(86_400)?.checked_add(secs)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn parse_fixed(text: &str, len: usize) -> Option<u64> {
    if text.len() != len {
        return None;
    }
    parse_decimal(text)
}

fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parses a duration such as `90s`, `15m`, `24h`, `30d`, `2w`, `1y`, or a
/// concatenation like `1d12h`. A year is 365 days.
pub fn parse_duration(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let (num, tail) = rest.split_at(digits);
        let n = parse_decimal(num)?;
        let mut chars = tail.chars();
        let unit = match chars.next()? {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 7 * 86_400,
            'y' => 365 * 86_400,
            _ => return None,
        };
        total = total.checked_add(n.checked_mul(unit)?)?;
        rest = chars.as_str();
    }
    Some(total)
}

/// Displays a duration in the largest exact units, e.g. `1d12h`, `24h`→`1d`.
pub struct Duration(pub u64);

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("0s");
        }
        let mut rest = self.0;
        for (unit, secs) in [
            ("y", 365 * 86_400),
            ("w", 7 * 86_400),
            ("d", 86_400),
            ("h", 3600),
            ("m", 60),
            ("s", 1),
        ] {
            if rest >= secs {
                write!(f, "{}{unit}", rest / secs)?;
                rest %= secs;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(Rfc3339(0).to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(Rfc3339(BUILD_FLOOR).to_string(), "2026-10-11T00:00:00Z");
        assert_eq!(Rfc3339(951_782_400).to_string(), "2000-02-29T00:00:00Z");
        assert_eq!(Rfc3339(4_102_444_799).to_string(), "2099-12-31T23:59:59Z");
        for t in [
            0,
            1,
            59,
            86_399,
            951_782_400,
            BUILD_FLOOR + 12_345,
            4_102_444_799,
        ] {
            assert_eq!(parse_time(&Rfc3339(t).to_string()), Some(t));
        }
        assert_eq!(parse_time("2026-10-11"), Some(BUILD_FLOOR));
        assert_eq!(parse_time("2026-10-11T00:01Z"), Some(BUILD_FLOOR + 60));
        assert_eq!(parse_time("@123"), Some(123));
        for bad in [
            "2026-13-01",
            "2026-02-29",
            "2026-1-01",
            "2026-10-11T00:00:00",
            "2026-10-11T24:00Z",
            "2026-10-11T00:00:00+01:00",
            "@",
            "@-1",
            "",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
        assert_eq!(parse_time("2024-02-29"), Some(1_709_164_800));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("24h"), Some(86_400));
        assert_eq!(parse_duration("1d12h"), Some(129_600));
        assert_eq!(parse_duration("2w"), Some(1_209_600));
        assert_eq!(parse_duration("1y"), Some(31_536_000));
        for bad in ["", "h", "1", "1x", "-1h", "1h-", "99999999999999999999y"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert_eq!(Duration(129_600).to_string(), "1d12h");
        assert_eq!(Duration(86_400).to_string(), "1d");
        assert_eq!(Duration(0).to_string(), "0s");
    }

    #[test]
    fn floor() {
        let mut f = Floor::new(None);
        assert_eq!(f.value(), BUILD_FLOOR);
        assert_eq!(f.now(0, 0), BUILD_FLOOR);
        assert_eq!(f.now(0, 10), BUILD_FLOOR + 10);
        assert_eq!(f.now(BUILD_FLOOR + 100, 10), BUILD_FLOOR + 100);
        // Capped at wall + skew.
        assert!(f.observe(BUILD_FLOOR + 1000, BUILD_FLOOR + 100, 60));
        assert_eq!(f.value(), BUILD_FLOOR + 160);
        assert!(!f.observe(BUILD_FLOOR + 50, BUILD_FLOOR + 1000, 60));
        assert_eq!(Floor::new(Some(BUILD_FLOOR + 5)).value(), BUILD_FLOOR + 5);
    }
}
