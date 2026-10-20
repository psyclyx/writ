//! Revocation records, the owner's side (DESIGN.md §18.4–§18.7): the
//! publish settings, signing a record, and DIR/record.writ, the file to
//! publish (the log and the newest record).

use crate::args::Parsed;
use crate::error::{Error, Result, err};
use crate::ident::{ISSUED, RECORD};
use crate::{OsRng, fs, wall_clock, warn};
use libwrit::keys::RootSigner;
use libwrit::time::{Duration, parse_duration};
use libwrit::{
    Body, Claim, Item, Log, MAX_PUBLISH_URLS, MIN_MAX_AGE, Material, Policy, Publish, Record,
    Signed, Signer, Verifier,
};
use std::path::Path;

/// `--max-age` when publishing starts without one.
pub const DEFAULT_MAX_AGE: u64 = 7 * 24 * 3600;

/// The publish settings `--publish`, `--max-age` and `--no-publish` ask
/// for. Without any of them, `current` stays (what the log says now).
pub fn setting(parsed: &Parsed, current: Option<&Publish>) -> Result<Option<Publish>> {
    let urls = parsed.values("publish");
    let max_age = parsed
        .value("max-age")
        .map(|v| {
            parse_duration(v).ok_or_else(|| {
                Error::Msg(format!(
                    "--max-age: expected a duration like 7d or 12h, got {v:?}"
                ))
            })
        })
        .transpose()?;
    if parsed.flag("no-publish") {
        if !urls.is_empty() || max_age.is_some() {
            return err("--no-publish does not go with --publish or --max-age");
        }
        return Ok(None);
    }
    if urls.is_empty() && max_age.is_none() {
        return Ok(current.cloned());
    }
    let urls: Vec<String> = if urls.is_empty() {
        current.map(|p| p.urls().to_vec()).unwrap_or_default()
    } else {
        urls.to_vec()
    };
    let max_age = max_age
        .or(current.map(Publish::max_age))
        .unwrap_or(DEFAULT_MAX_AGE);
    if max_age < MIN_MAX_AGE {
        return err(format!(
            "--max-age must be at least {}",
            Duration(MIN_MAX_AGE)
        ));
    }
    if urls.len() > MAX_PUBLISH_URLS {
        return err(format!("give at most {MAX_PUBLISH_URLS} --publish URLs"));
    }
    for u in &urls {
        let lower = u.to_ascii_lowercase();
        if !lower.starts_with("https://") && !lower.starts_with("http://") {
            return err(format!("--publish {u:?}: give an http:// or https:// URL"));
        }
        if host(u).is_empty() {
            return err(format!("--publish {u:?}: the URL has no host"));
        }
        if authority(u).contains('@') {
            return err(format!(
                "--publish {u:?}: a URL with a user name is not fetched; records are public"
            ));
        }
    }
    let publish = Publish::new(max_age, urls).ok_or_else(|| {
        Error::Msg(
            "--publish: a URL must be 1 to 255 characters of printable ASCII, without spaces"
                .into(),
        )
    })?;
    if let [first, rest @ ..] = publish.urls()
        && !rest.is_empty()
        && rest.iter().all(|u| host(u) == host(first))
    {
        warn(format!(
            "every --publish URL is on {}. If it is unreachable for longer than {}, \
             verifiers stop accepting this identity's long-lived statements; add a URL \
             on another host",
            host(first),
            Duration(max_age)
        ));
    }
    Ok(Some(publish))
}

/// The authority part of an http(s) URL: what lies between the scheme and
/// the path.
pub fn authority(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// The host of an http(s) URL, lower-cased, without user or port.
fn host(url: &str) -> String {
    let authority = authority(url);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host.starts_with('[') {
        host.find(']').and_then(|i| host.get(..=i)).unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// A new record for the identity of `log`, signed now by `signers`:
/// everything in `issued` that it has validly revoked under its head.
///
/// Only revocations by the identity itself count. issued.writ is not
/// trusted: a revocation by anyone else planted there would otherwise be
/// endorsed by the record, which revokes by hash whoever first said so.
pub fn sign(log: &Log, issued: &[Item], signers: &[RootSigner]) -> Result<Signed<Record>> {
    let roots = [log.id()];
    let material = Material::from_items(log.items().chain(issued.iter().cloned()));
    let policy = Policy::default();
    let verifier = Verifier::new(&roots, &material, &policy).with_local(&roots);
    let now = wall_clock();
    let revoked = issued
        .iter()
        .filter_map(|item| match item {
            Item::Statement(s) if s.body.issuer.id() == Some(log.id()) => match &s.body.claim {
                Claim::Revoke { target }
                    if verifier.statement_status(&s.body.hash(), now).is_ok() =>
                {
                    Some(*target)
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    libwrit::sign_record(log, revoked, now, &refs, &mut OsRng)
        .map_err(|e| Error::Msg(format!("signing the record: {e}")))
}

/// Signs a new record for the identity in `dir` (whose log is `log`) and
/// writes DIR/record.writ, returning its text. It holds the lock that
/// guards issued.writ and reads that file afresh, so a revocation recorded
/// meanwhile by another writ is not left out, and two writers can't
/// interleave.
pub fn renew(dir: &Path, log: &Log, signers: &[RootSigner]) -> Result<String> {
    let _recording = fs::lock_file(&dir.join(".issued.lock"), true)?;
    let issued = fs::read_bundle_file(&dir.join(ISSUED))?;
    let record = sign(log, &issued, signers)?;
    write(dir, log, record)
}

/// Writes DIR/record.writ, the log and `record`, and returns its text.
pub fn write(dir: &Path, log: &Log, record: Signed<Record>) -> Result<String> {
    let text: String = log
        .items()
        .chain([Item::Record(record)])
        .map(|i| i.armor())
        .collect();
    fs::replace(&dir.join(RECORD), text.as_bytes())?;
    Ok(text)
}

/// The line to show after writing DIR/record.writ.
pub fn reminder(dir: &Path, log: &Log) -> String {
    let path = dir.join(RECORD);
    match log.head().publish() {
        Some(p) if !p.urls().is_empty() => format!(
            "publish {} at {} (verifiers need a record younger than {})",
            path.display(),
            p.urls().join(", "),
            Duration(p.max_age())
        ),
        Some(p) => format!(
            "give {} to verifiers (they need a record younger than {})",
            path.display(),
            Duration(p.max_age())
        ),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host("https://Example.org/a"), "example.org");
        assert_eq!(host("http://u:p@example.org:8080/a?b"), "example.org");
        assert_eq!(host("https://[::1]:443/r"), "[::1]");
        assert_eq!(host("https://example.org"), "example.org");
        assert_eq!(host("https://example.org./x"), "example.org");
        assert_eq!(host("http://"), "");
    }
}
