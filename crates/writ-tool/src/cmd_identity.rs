//! `init`, `id`, `rotate`, `export`, `keygen`, `pubkey`.

use crate::args::Parsed;
use crate::error::{Context, Error, Result, err};
use crate::ident::{self, CURRENT_KEY, ISSUED, IdentityDir, LOG, NEXT};
use crate::specs::{EXPORT, ID, INIT, KEYGEN, PUBKEY, ROTATE};
use crate::{OsRng, fs, say, wall_clock};
use libwrit::keys::RootSigner;
use libwrit::time::{Duration, parse_duration};
use libwrit::{Authority, Body, Claim, Item, Policy, PublicKey, RootKey, Seed, Signer, Verifier};
use std::collections::BTreeSet;

fn count(parsed: &Parsed, name: &str, default: usize) -> Result<usize> {
    match parsed.value(name) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| Error::Msg(format!("--{name}: expected a number, got {v:?}"))),
    }
}

pub fn duration_arg(parsed: &Parsed, name: &str) -> Result<Option<u64>> {
    parsed
        .value(name)
        .map(|v| {
            parse_duration(v).filter(|d| *d > 0).ok_or_else(|| {
                Error::Msg(format!(
                    "--{name}: expected a duration like 30d or 12h, got {v:?}"
                ))
            })
        })
        .transpose()
}

fn read_root_pubs(paths: &[String]) -> Result<Vec<RootKey>> {
    let mut keys = Vec::new();
    for path in paths {
        let bytes = fs::read_input(path, "a public key")?;
        let items = Item::decode_bundle(&bytes).context(|| path.clone())?;
        let before = keys.len();
        for item in items {
            match item {
                Item::PublicKey(PublicKey::Root(k)) => keys.push(k),
                other => {
                    return err(format!(
                        "{path}: expected a root public key, found a {}",
                        other.kind()
                    ));
                }
            }
        }
        if keys.len() == before {
            return err(format!(
                "{path}: no public key (make one with `writ pubkey`)"
            ));
        }
    }
    Ok(keys)
}

/// Fresh next seeds plus the next authority.
fn new_next(parsed: &Parsed) -> Result<(Vec<Seed>, Authority)> {
    let pubs = read_root_pubs(parsed.values("next-pub"))?;
    let n = count(parsed, "next-n", usize::from(pubs.is_empty()))?;
    let seeds: Vec<Seed> = (0..n).map(|_| Seed::generate(&mut OsRng)).collect();
    let mut keys: Vec<RootKey> = seeds.iter().map(|s| s.root().root_key()).collect();
    keys.extend(pubs);
    let total = keys.len();
    if total == 0 {
        return err("there must be at least one next key: give --next-n or --next-pub");
    }
    let k = threshold(parsed, "next-k", total)?;
    let authority = Authority::new(k, keys).map_err(|e| Error::Msg(format!("next keys: {e}")))?;
    Ok((seeds, authority))
}

pub fn init(parsed: &Parsed) -> Result<()> {
    let [dir] = parsed.exact(&INIT, ["DIR"])?;
    let next_out = parsed.value("next-out").ok_or_else(|| {
        INIT.usage_error("--next-out PATH is required: where should the next (cold) key go?".into())
    })?;
    let key_out_default = format!("{}/{CURRENT_KEY}", dir.trim_end_matches('/'));
    let key_out = parsed.value("key-out").unwrap_or(&key_out_default);
    if next_out == "-" && key_out == "-" {
        return err("--next-out and --key-out can't both be stdout");
    }
    let max_validity = duration_arg(parsed, "max-validity")?;
    for p in [next_out, key_out] {
        fs::check_secret_target(p)?;
    }
    let (next_seeds, next) = new_next(parsed)?;
    let current_seed = Seed::generate(&mut OsRng);
    let current = current_seed.root();
    let (id, inception) = libwrit::incept(
        Authority::single(current.root_key()),
        &next,
        max_validity,
        &[&current],
        &mut OsRng,
    )
    .map_err(|e| Error::Msg(e.to_string()))?;

    let path = ident::create_dir(dir)?;
    let result = (|| {
        if !next_seeds.is_empty() {
            fs::write_secret(next_out, &fs::seeds_text(&next_seeds))?;
        }
        fs::write_secret(
            key_out,
            &fs::seeds_text(std::slice::from_ref(&current_seed)),
        )?;
        fs::replace(
            &path.join(NEXT),
            Item::Authority(next.clone()).armor().as_bytes(),
        )?;
        fs::replace(&path.join(ISSUED), b"")?;
        fs::replace(&path.join(LOG), Item::Event(inception).armor().as_bytes())
    })();
    if let Err(e) = result {
        // Leave nothing half-made behind (the key files we created stay:
        // never delete a key).
        for f in [LOG, ISSUED, NEXT] {
            let _ = std::fs::remove_file(path.join(f));
        }
        let _ = std::fs::remove_dir(&path);
        return Err(e);
    }

    let stdout_taken = next_out == "-" || key_out == "-";
    if !stdout_taken {
        fs::print(&format!("{id}\n"))?;
    }
    let mut lines = vec![format!("created identity {id} in {dir}")];
    lines.push(format!(
        "  current key  {key_out:<24} signs statements; keep it safe"
    ));
    if !next_seeds.is_empty() {
        lines.push(format!(
            "  next key     {next_out:<24} rotates the identity; keep it offline"
        ));
    }
    if next.keys().len() > 1 {
        lines.push(format!(
            "  next keys    any {} of these {} can rotate",
            next.k(),
            next.keys().len()
        ));
    }
    if let Some(mv) = max_validity {
        lines.push(format!(
            "  every statement must expire within {}",
            Duration(mv)
        ));
    }
    if !parsed.flag("quiet") || stdout_taken {
        eprintln!("{}", lines.join("\n"));
    }
    Ok(())
}

pub fn id(parsed: &Parsed) -> Result<()> {
    let [dir] = parsed.exact(&ID, ["DIR"])?;
    let ident = IdentityDir::open(dir)?;
    fs::print(&format!("{}\n", ident.id()))
}

/// What a rotation keeps: everything this identity issued that is still
/// live. The cold keys endorse kept items by hash, so each one must verify
/// here: DIR/issued.writ is not trusted.
fn compute_keep(ident: &IdentityDir, now: libwrit::Time) -> (Vec<libwrit::Hash>, KeepStats) {
    let roots = [ident.id()];
    let material = ident.material();
    let policy = Policy::default();
    let verifier = Verifier::new(&roots, &material, &policy);
    let mut stats = KeepStats::default();
    let mut keep = BTreeSet::new();
    for item in &ident.issued {
        let (h, status) = match item {
            Item::Statement(s) if s.body.issuer.id() == Some(ident.id()) => {
                if matches!(s.body.claim, Claim::Revoke { .. }) {
                    continue;
                }
                if s.body.claim.is_about_leaf() {
                    stats.leaf += 1;
                    continue;
                }
                let h = s.body.hash();
                (h, verifier.statement_status(&h, now))
            }
            Item::Signature(s) if s.body.signer.id() == Some(ident.id()) => {
                let h = s.body.hash();
                (h, verifier.signature_status(&h, now))
            }
            _ => continue,
        };
        match status {
            // Issued for the future: keep it, it isn't dead.
            Ok(()) | Err(libwrit::Reason::NotYetValid(_)) => {
                keep.insert(h);
            }
            Err(libwrit::Reason::Expired(_)) => stats.expired += 1,
            Err(libwrit::Reason::Revoked(_)) => stats.revoked += 1,
            Err(_) => stats.dead += 1,
        }
    }
    (keep.into_iter().collect(), stats)
}

#[derive(Default)]
struct KeepStats {
    expired: usize,
    revoked: usize,
    leaf: usize,
    dead: usize,
}

pub fn rotate(parsed: &Parsed) -> Result<()> {
    parsed.exact(&ROTATE, [])?;
    let dir = parsed
        .value("identity")
        .ok_or_else(|| ROTATE.usage_error("-i DIR is required".into()))?;
    if parsed.values("next-key").is_empty() {
        return Err(ROTATE.usage_error(
            "--next-key PATH is required: a next key from init or the last rotate".into(),
        ));
    }
    let same_next = parsed.flag("same-next");
    let next_out = match (same_next, parsed.value("next-out")) {
        (true, None) => None,
        (false, Some(p)) => Some(p),
        (true, Some(_)) => {
            return Err(ROTATE.usage_error(
                "--same-next keeps the next keys, so there is nothing to write to --next-out"
                    .into(),
            ));
        }
        (false, None) => {
            return Err(ROTATE.usage_error(
                "--next-out PATH is required: where to write the new next key (or give --same-next)"
                    .into(),
            ));
        }
    };
    if same_next
        && ["next-n", "next-k", "next-pub"]
            .iter()
            .any(|o| !parsed.values(o).is_empty())
    {
        return Err(ROTATE.usage_error(
            "--same-next can't be combined with --next-n, --next-k or --next-pub".into(),
        ));
    }
    if let Some(p) = next_out {
        fs::check_secret_target(p)?;
    }
    // Serialise rotations of this identity: two concurrent rotations would
    // sign two different events with the same number.
    let ident = IdentityDir::open_locked(dir, true)?;
    let revealed = ident.next_authority()?;
    let old_authority = ident.log.head().authority().clone();

    let mut signers: Vec<RootSigner> = Vec::new();
    for path in parsed.values("next-key") {
        for seed in fs::read_seeds(path)? {
            let signer = seed.root();
            if revealed.index_of(&signer.root_key()).is_none() {
                return err(if old_authority.index_of(&signer.root_key()).is_some() {
                    format!(
                        "{path} holds a current key. Rotation needs a next key: the one that \
                         init or the last rotate wrote to --next-out"
                    )
                } else {
                    format!("{path} does not hold a next key of {dir}")
                });
            }
            if !signers.iter().any(|s| s.root_key() == signer.root_key()) {
                signers.push(signer);
            }
        }
    }
    if signers.len() < revealed.k() {
        return err(format!(
            "rotation needs {} of the {} next keys, but {} were given",
            revealed.k(),
            revealed.keys().len(),
            signers.len()
        ));
    }

    // Where the new current key goes: --key-out, or in place of a retired
    // DIR/current.key. A key file that still has a role is never replaced.
    let current_path = ident.dir.join(CURRENT_KEY);
    let current_path_str = current_path.display().to_string();
    let (current_seed, current) = current_keys(parsed)?;
    let next_authority;
    let next_seeds;
    if same_next {
        next_authority = revealed.clone();
        next_seeds = Vec::new();
    } else {
        (next_seeds, next_authority) = new_next(parsed)?;
    }
    let key_out = match parsed.value("key-out") {
        Some(p) => {
            if Some(p) == next_out && p == "-" {
                return err("--next-out and --key-out can't both be standard output");
            }
            fs::check_secret_target(p)?;
            KeyOut::Path(p.to_owned())
        }
        None if current_path.is_file() => {
            let old = fs::read_seeds(&current_path_str)?;
            let retired = old.iter().all(|s| {
                let k = s.root().root_key();
                old_authority.index_of(&k).is_some()
                    && revealed.index_of(&k).is_none()
                    && next_authority.index_of(&k).is_none()
                    && current.index_of(&k).is_none()
            });
            if !retired {
                return err(format!(
                    "{current_path_str} holds a key that is still in use, so writ won't \
                     replace it; give --key-out PATH for the new current key"
                ));
            }
            KeyOut::Replace
        }
        None => {
            return Err(ROTATE.usage_error(format!(
                "--key-out PATH is required: where to write the new current key \
                 ({current_path_str} does not exist)"
            )));
        }
    };

    let max_validity = if parsed.flag("no-max-validity") {
        None
    } else {
        match duration_arg(parsed, "max-validity")? {
            Some(mv) => Some(mv),
            None => ident.log.head().max_validity(),
        }
    };
    let now = wall_clock();
    let (keep, stats) = compute_keep(&ident, now);
    let signer_refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    let event = libwrit::rotate(
        &ident.log,
        libwrit::RotationPlan {
            revealed: revealed.clone(),
            authority: current.clone(),
            next: next_authority.clone(),
            max_validity,
            keep: keep.clone(),
        },
        &signer_refs,
        &mut OsRng,
    )
    .map_err(|e| Error::Msg(e.to_string()))?;
    let n = event.body.n();
    if Item::decode(&Item::Event(event.clone()).encode()).is_err() {
        return err(format!(
            "a rotation keeping {} statements would be too large to read back; \
             revoke some, or let them expire, first",
            keep.len()
        ));
    }

    // Order matters for crash safety: every new secret key and the new next
    // authority must be on disk before the log commits to them. next.writ
    // is append-only, so a crash before the log write leaves the old
    // commitment satisfiable.
    if let Some(p) = next_out
        && !next_seeds.is_empty()
    {
        fs::write_secret(p, &fs::seeds_text(&next_seeds))?;
    }
    let current_text = fs::seeds_text(std::slice::from_ref(&current_seed));
    let key_shown = match &key_out {
        KeyOut::Path(p) => {
            fs::write_secret(p, &current_text)?;
            p.clone()
        }
        KeyOut::Replace => {
            // Write it beside the old key first; the rename below, after the
            // log commits, retires the old one.
            current_path_str.clone()
        }
    };
    let staged = ident.dir.join(format!("{CURRENT_KEY}.new"));
    if matches!(key_out, KeyOut::Replace) {
        fs::write_secret(&staged.display().to_string(), &current_text)?;
    }
    if !same_next {
        fs::append_items(
            &ident.dir.join(NEXT),
            &[Item::Authority(next_authority.clone())],
        )?;
    }
    fs::append_items(&ident.dir.join(LOG), &[Item::Event(event)])?;
    if matches!(key_out, KeyOut::Replace) {
        std::fs::rename(&staged, &current_path)
            .context(|| format!("replacing {current_path_str}"))?;
    }

    let mut lines = vec![format!("rotated {} to event {n}", ident.id())];
    lines.push(format!(
        "  kept {} statement{}{}",
        keep.len(),
        if keep.len() == 1 { "" } else { "s" },
        {
            let mut dropped = Vec::new();
            if stats.expired > 0 {
                dropped.push(format!("{} expired", stats.expired));
            }
            if stats.revoked > 0 {
                dropped.push(format!("{} revoked", stats.revoked));
            }
            if stats.leaf > 0 {
                dropped.push(format!(
                    "{} statement{} for leaf keys (issue new ones)",
                    stats.leaf,
                    if stats.leaf == 1 { "" } else { "s" }
                ));
            }
            if stats.dead > 0 {
                dropped.push(format!("{} that were no longer valid", stats.dead));
            }
            if dropped.is_empty() {
                String::new()
            } else {
                format!("; dropped {}", dropped.join(", "))
            }
        }
    ));
    lines.push(match key_out {
        KeyOut::Replace => {
            format!("  current key  {key_shown}  replaced; the old key no longer signs anything")
        }
        KeyOut::Path(_) => format!("  current key  {key_shown}"),
    });
    if current.keys().len() > 1 {
        lines.push(format!(
            "  current keys any {} of these {} sign statements",
            current.k(),
            current.keys().len()
        ));
    }
    match next_out {
        Some(p) if !next_seeds.is_empty() => {
            lines.push(format!("  next key     {p}  keep it offline"));
        }
        _ => lines.push("  next keys    unchanged".to_owned()),
    }
    if next_out != Some("-") || !parsed.flag("quiet") {
        say(parsed, lines.join("\n"));
    }
    Ok(())
}

enum KeyOut {
    /// Write the new current key here.
    Path(String),
    /// Replace the retired DIR/current.key.
    Replace,
}

/// A fresh current key, plus other people's keys from --key-pub.
fn current_keys(parsed: &Parsed) -> Result<(Seed, Authority)> {
    let pubs = read_root_pubs(parsed.values("key-pub"))?;
    let seed = Seed::generate(&mut OsRng);
    let mut keys = vec![seed.root().root_key()];
    keys.extend(pubs);
    let k = threshold(parsed, "key-k", keys.len())?;
    let authority =
        Authority::new(k, keys).map_err(|e| Error::Msg(format!("current keys: {e}")))?;
    Ok((seed, authority))
}

/// The threshold from --NAME, defaulting to a majority of `total`; must be
/// more than half of `total`.
fn threshold(parsed: &Parsed, name: &str, total: usize) -> Result<usize> {
    let k = count(parsed, name, total / 2 + 1)?;
    if total > 0 && 2 * k <= total {
        return err(format!(
            "--{name} {k} is too low for {total} keys: it must be more than half, so at \
             least {}. Otherwise two separate groups of key holders could each act, and \
             verifiers would refuse the identity",
            total / 2 + 1
        ));
    }
    Ok(k)
}

pub fn export(parsed: &Parsed) -> Result<()> {
    parsed.exact(&EXPORT, [])?;
    let dir = parsed
        .value("identity")
        .ok_or_else(|| EXPORT.usage_error("-i DIR is required".into()))?;
    let ident = IdentityDir::open(dir)?;
    let mut out: String = ident.log.items().map(|i| i.armor()).collect();
    if parsed.flag("all") {
        out.extend(ident.issued.iter().map(Item::armor));
    } else {
        let roots = [ident.id()];
        let material = ident.material();
        let policy = Policy::default();
        let v = Verifier::new(&roots, &material, &policy);
        let now = wall_clock();
        for item in &ident.issued {
            if let Item::Statement(s) = item
                && v.statement_status(&s.body.hash(), now).is_ok()
            {
                out.push_str(&item.armor());
            }
        }
    }
    fs::print(&out)
}

pub fn keygen(parsed: &Parsed) -> Result<()> {
    parsed.exact(&KEYGEN, [])?;
    let out = parsed.value("out").unwrap_or("-");
    let seed = Seed::generate(&mut OsRng);
    let public = seed.root().root_key();
    fs::write_secret(out, &fs::seeds_text(std::slice::from_ref(&seed)))?;
    eprintln!(
        "public key: slh-dsa-shake-128s {}\nTo make a public key file for --next-pub, run 'writ pubkey' on the key file.",
        libwrit::Hash(public.0)
    );
    Ok(())
}

pub fn pubkey(parsed: &Parsed) -> Result<()> {
    let path = match parsed.positional.as_slice() {
        [] => "-",
        [p] => p.as_str(),
        _ => return Err(PUBKEY.usage_error("expected at most one KEYFILE".into())),
    };
    let mut out = String::new();
    for seed in fs::read_seeds(path)? {
        let key = if parsed.flag("leaf") {
            PublicKey::Leaf(seed.leaf().leaf_key().clone())
        } else {
            PublicKey::Root(seed.root().root_key())
        };
        out.push_str(&Item::PublicKey(key).armor());
    }
    fs::print(&out)
}

/// Shared by `grant` and friends: the effective expiry for a new statement.
pub fn expiry(
    parsed: &Parsed,
    issued: libwrit::Time,
    max_validity: Option<u64>,
    default: Option<u64>,
) -> Result<Option<libwrit::Time>> {
    let explicit = match parsed.value("expires") {
        None => None,
        Some(text) => Some(if let Some(d) = parse_duration(text) {
            issued.saturating_add(d)
        } else if let Some(t) = libwrit::time::parse_time(text) {
            t
        } else {
            return err(format!(
                "--expires: expected a duration (30d, 12h) or a date (2027-01-01), got {text:?}"
            ));
        }),
    };
    if let Some(e) = explicit
        && e <= issued
    {
        return err("--expires must be in the future");
    }
    let chosen = explicit.or(default.map(|d| issued.saturating_add(d)));
    match (chosen, max_validity) {
        (Some(e), Some(mv)) if e - issued > mv => err(format!(
            "this identity requires statements to expire within {}; --expires is too late",
            Duration(mv)
        )),
        (None, Some(mv)) => {
            crate::note(format!(
                "this identity requires an expiry; the statement expires in {}",
                Duration(mv)
            ));
            Ok(Some(issued.saturating_add(mv)))
        }
        (e, _) => Ok(e),
    }
}
