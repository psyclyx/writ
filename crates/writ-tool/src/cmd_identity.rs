//! `init`, `id`, `rotate`, `export`, `keygen`, `pubkey`.

use crate::args::{Parsed, Spec, flag, opt, short};
use crate::error::{Context, Error, Result, err};
use crate::ident::{self, CURRENT_KEY, ISSUED, IdentityDir, LOG, NEXT};
use crate::{OsRng, fs, say, wall_clock};
use libwrit::keys::RootSigner;
use libwrit::time::{Duration, parse_duration};
use libwrit::{
    Authority, Body, Claim, Item, Policy, PublicKey, RootKey, Seed, Signer, Subject, Verifier,
};
use std::collections::BTreeSet;

pub static INIT: Spec = Spec {
    name: "init",
    usage: "init DIR --next-out PATH [options]",
    about: "create an identity",
    details: "\
Creates DIR with the identity log, an empty issuance log, and the current
(warm) key in DIR/current.key. The next (cold) key goes to --next-out,
which you must choose explicitly: keep it offline; it is the only way to
rotate. Prints the new id.

Keys are plaintext; compose with age to encrypt them at rest:
  writ init me --next-out - | age -p > me-next.key.age

Next authority: by default one fresh key, which must sign the next rotation.
With --next-n/--next-k/--next-pub it is K of N keys (social recovery: e.g.
2 of {your cold key, a friend's key, a key in a safe}). Prefer K > N/2: if
two disjoint groups could each rotate, a race between them looks exactly
like a compromise, and verifiers will refuse the identity.",
    opts: &[
        opt(
            "next-out",
            "PATH",
            "where to write the next key(s) ('-' for stdout); required",
        ),
        opt("next-n", "N", "fresh next keys to generate (default 1)"),
        opt("next-k", "K", "next keys needed to rotate (default 1)"),
        opt(
            "next-pub",
            "PATH",
            "add someone else's public key (from `writ pubkey`) to the next authority",
        ),
        opt(
            "key-out",
            "PATH",
            "where to write the current key (default DIR/current.key)",
        ),
        opt(
            "max-validity",
            "DUR",
            "require every statement to expire within DUR (e.g. 90d)",
        ),
        short(flag("quiet", "print only the id"), 'q'),
    ],
};

pub static ID: Spec = Spec {
    name: "id",
    usage: "id DIR",
    about: "print an identity's id",
    details: "",
    opts: &[],
};

pub static ROTATE: Spec = Spec {
    name: "rotate",
    usage: "rotate -i DIR --next-key PATH... --next-out PATH [options]",
    about: "reveal the next key(s) and commit to new ones",
    details: "\
Rotation replaces the identity's keys without changing its id. The keys
committed to at the last event (--next-key) sign the rotation and become the
current keys; fresh next keys go to --next-out.

Statements issued before the rotation stay valid only if the rotation keeps
them. writ keeps everything in DIR/issued.writ that is still live: not
revoked, not expired, and not a leaf grant (leaf keys get new grants). A
thief holding the old current key is cut off from every verifier that sees
the rotation.

If DIR/current.key exists, it is replaced by the revealed key(s) and the old,
now useless key is deleted. Otherwise, use the revealed key with --key.

  writ rotate -i me --next-key <(age -d me-next.key.age) --next-out - | age -p > me-next2.key.age",
    opts: &[
        short(opt("identity", "DIR", "the identity"), 'i'),
        opt(
            "next-key",
            "PATH",
            "a next key committed to by the log (repeat for K of N; '-' for stdin)",
        ),
        opt(
            "next-out",
            "PATH",
            "where to write the new next key(s) ('-' for stdout); required",
        ),
        opt("next-n", "N", "fresh next keys to generate (default 1)"),
        opt(
            "next-k",
            "K",
            "next keys needed for the following rotation (default 1)",
        ),
        opt(
            "next-pub",
            "PATH",
            "add someone else's public key to the new next authority",
        ),
        opt("max-validity", "DUR", "set the statement lifetime limit"),
        flag("no-max-validity", "remove the statement lifetime limit"),
        short(flag("quiet", "say nothing on success"), 'q'),
    ],
};

pub static EXPORT: Spec = Spec {
    name: "export",
    usage: "export -i DIR [--all]",
    about: "print an identity's log and live statements as a bundle",
    details: "\
The bundle others need to verify what this identity says: its log, every
statement still valid now, and its revocations (so verifiers learn of them).
Data signatures travel with their data and are left out unless --all.",
    opts: &[
        short(opt("identity", "DIR", "the identity"), 'i'),
        flag(
            "all",
            "everything ever issued, including expired, revoked and signatures",
        ),
    ],
};

pub static KEYGEN: Spec = Spec {
    name: "keygen",
    usage: "keygen [--out PATH]",
    about: "make a secret key (e.g. to be someone's recovery key)",
    details: "\
Prints a new secret key. Give its public key (`writ pubkey`) to whoever adds
you to their next authority with --next-pub.",
    opts: &[opt(
        "out",
        "PATH",
        "where to write the key (default stdout); never overwrites",
    )],
};

pub static PUBKEY: Spec = Spec {
    name: "pubkey",
    usage: "pubkey [--leaf] [KEYFILE]",
    about: "print the public key of a secret key",
    details: "\
Reads secret keys (default: stdin) and prints their public keys as armored
items. Root keys are for --next-pub; leaf keys (--leaf) can be grant subjects.",
    opts: &[flag("leaf", "treat the keys as leaf keys")],
};

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
    let k = count(parsed, "next-k", 1)?;
    let seeds: Vec<Seed> = (0..n).map(|_| Seed::generate(&mut OsRng)).collect();
    let mut keys: Vec<RootKey> = seeds.iter().map(|s| s.root().root_key()).collect();
    keys.extend(pubs);
    let total = keys.len();
    if total == 0 {
        return err("the next authority needs at least one key");
    }
    let authority =
        Authority::new(k, keys).map_err(|e| Error::Msg(format!("next authority: {e}")))?;
    if 2 * k <= total && total > 1 {
        eprintln!(
            "writ: warning: with {k} of {total}, two disjoint groups of key holders could each \
             sign a rotation; verifiers treat that as a compromise. Prefer --next-k {}.",
            total / 2 + 1
        );
    }
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
        if p != "-" && std::path::Path::new(p).is_file() {
            return err(format!("{p} already exists; writ never overwrites a key"));
        }
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
            "  next authority: {} of {} keys",
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

/// What a rotation keeps: everything issued that is still live.
fn compute_keep(ident: &IdentityDir, now: libwrit::Time) -> (Vec<libwrit::Hash>, KeepStats) {
    let roots = [ident.id()];
    let material = ident.material();
    let policy = Policy::default();
    let verifier = Verifier::new(&roots, &material, &policy);
    let mut stats = KeepStats::default();
    let mut keep = BTreeSet::new();
    for item in &ident.issued {
        match item {
            Item::Statement(s) => {
                let h = s.body.hash();
                match &s.body.claim {
                    Claim::Revoke { .. } => continue,
                    Claim::Grant {
                        subject: Subject::Leaf(_),
                        ..
                    } => {
                        stats.leaf += 1;
                        continue;
                    }
                    _ => {}
                }
                match verifier.statement_status(&h, now) {
                    Ok(()) => {
                        keep.insert(h);
                    }
                    Err(libwrit::Reason::Expired(_)) => stats.expired += 1,
                    Err(libwrit::Reason::Revoked(_)) => stats.revoked += 1,
                    // Issued for the future: keep it, it isn't dead.
                    Err(libwrit::Reason::NotYetValid(_)) => {
                        keep.insert(h);
                    }
                    Err(_) => stats.dead += 1,
                }
            }
            Item::Signature(s) => {
                let h = s.body.hash();
                let current = match &s.body.signer {
                    libwrit::Issuer::Identity { id, event } => {
                        *id == ident.id() && (*event == ident.log.head_n() || ident.log.keeps(&h))
                    }
                    libwrit::Issuer::Leaf(_) => false,
                };
                let revoked = ident.issued.iter().any(|i| {
                    matches!(i, Item::Statement(r)
                        if matches!(&r.body.claim, Claim::Revoke { target } if *target == h)
                        && verifier.statement_status(&r.body.hash(), now).is_ok())
                });
                if revoked {
                    stats.revoked += 1;
                } else if current {
                    keep.insert(h);
                } else {
                    stats.dead += 1;
                }
            }
            _ => {}
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
    let next_out = parsed.value("next-out").ok_or_else(|| {
        ROTATE.usage_error("--next-out PATH is required: where should the new next key go?".into())
    })?;
    if parsed.values("next-key").is_empty() {
        return Err(ROTATE.usage_error(
            "--next-key PATH is required: the key(s) committed to at the last event".into(),
        ));
    }
    if next_out != "-" && std::path::Path::new(next_out).is_file() {
        return err(format!(
            "{next_out} already exists; writ never overwrites a key"
        ));
    }
    // Serialise rotations of this identity: two concurrent rotations would
    // sign two different events with the same number.
    let lock = std::fs::OpenOptions::new()
        .append(true)
        .open(std::path::Path::new(dir).join(LOG))
        .context(|| format!("opening {dir}/{LOG}"))?;
    lock.lock().context(|| format!("locking {dir}/{LOG}"))?;
    let ident = IdentityDir::open(dir)?;
    let revealed = ident.next_authority()?;

    let mut revealed_seeds = Vec::new();
    let mut signers: Vec<RootSigner> = Vec::new();
    for path in parsed.values("next-key") {
        for seed in fs::read_seeds(path)? {
            let signer = seed.root();
            if revealed.index_of(&signer.root_key()).is_none() {
                let current = ident
                    .log
                    .head()
                    .authority()
                    .index_of(&signer.root_key())
                    .is_some();
                return err(if current {
                    format!(
                        "the key in {path} is the current key, not the next one; rotation needs the next (cold) key"
                    )
                } else {
                    format!("the key in {path} is not in the next authority {dir} committed to")
                });
            }
            if !signers.iter().any(|s| s.root_key() == signer.root_key()) {
                signers.push(signer);
                revealed_seeds.push(seed);
            }
        }
    }
    if signers.len() < revealed.k() {
        return err(format!(
            "rotation needs {} of the {} next keys; got {}",
            revealed.k(),
            revealed.keys().len(),
            signers.len()
        ));
    }

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
    let (next_seeds, next) = new_next(parsed)?;
    let signer_refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    let event = libwrit::rotate(
        &ident.log,
        revealed.clone(),
        &next,
        max_validity,
        keep.clone(),
        &signer_refs,
        &mut OsRng,
    )
    .map_err(|e| Error::Msg(e.to_string()))?;
    let n = event.body.n();

    // The new next keys must be safe before the log commits to them.
    if !next_seeds.is_empty() {
        fs::write_secret(next_out, &fs::seeds_text(&next_seeds))?;
    }
    fs::replace(
        &ident.dir.join(NEXT),
        Item::Authority(next.clone()).armor().as_bytes(),
    )?;
    fs::append_items(&ident.dir.join(LOG), &[Item::Event(event)])?;
    drop(lock);

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
                dropped.push(format!("{} leaf grants (reissue them)", stats.leaf));
            }
            if stats.dead > 0 {
                dropped.push(format!("{} already invalid", stats.dead));
            }
            if dropped.is_empty() {
                String::new()
            } else {
                format!("; dropped {}", dropped.join(", "))
            }
        }
    ));

    // Install the revealed keys as the current key, if that's how this
    // identity is kept.
    let current_path = ident.dir.join(CURRENT_KEY);
    if current_path.is_file() {
        let path_str = current_path.display().to_string();
        let old = fs::read_seeds(&path_str)?;
        let retired = old
            .iter()
            .all(|s| revealed.index_of(&s.root().root_key()).is_none());
        if retired {
            std::fs::remove_file(&current_path).context(|| format!("removing {path_str}"))?;
            fs::write_secret(&path_str, &fs::seeds_text(&revealed_seeds))?;
            lines.push(format!(
                "  {path_str} now holds the revealed key; the retired key was deleted"
            ));
        }
    } else {
        lines.push("  the key(s) you revealed are now the current key: sign with --key".to_owned());
    }
    if !next_seeds.is_empty() {
        lines.push(format!("  next key  {next_out}  keep it offline"));
    }
    if next_out != "-" || !parsed.flag("quiet") {
        say(parsed, lines.join("\n"));
    }
    Ok(())
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
        "public key: slh-dsa-shake-128s {}\n(`writ pubkey` prints it as a file for --next-pub)",
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
    let chosen = explicit.or(default.map(|d| issued + d));
    match (chosen, max_validity) {
        (Some(e), Some(mv)) if e - issued > mv => err(format!(
            "this identity requires statements to expire within {}; --expires is later",
            Duration(mv)
        )),
        (None, Some(mv)) => {
            eprintln!(
                "writ: this identity requires an expiry; expiring in {}",
                Duration(mv)
            );
            Ok(Some(issued + mv))
        }
        (e, _) => Ok(e),
    }
}
