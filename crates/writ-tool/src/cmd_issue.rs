//! `name`, `grant`, `revoke`, `leaf`, `sign`.

use crate::args::{Parsed, Spec};
use crate::cmd_identity::expiry;
use crate::error::{Error, Result, err};
use crate::ident::IdentityDir;
use crate::specs::{GRANT, LEAF, NAME, REVOKE, SIGN};
use crate::{OsRng, display, fs, say, subject, wall_clock};
use libwrit::model::LEAF_CEILING;
use libwrit::time::Duration;
use libwrit::{Body, Claim, Hash, Issuer, Item, PublicKey, Seed, Signer, Statement, Subject};

fn identity(parsed: &Parsed, spec: &'static Spec) -> Result<IdentityDir> {
    let dir = parsed.value("identity").ok_or_else(|| {
        spec.usage_error("-i DIR is required: which identity is speaking?".into())
    })?;
    IdentityDir::open_locked(dir, false)
}

fn note(parsed: &Parsed) -> Result<Option<String>> {
    match parsed.value("note") {
        Some(n) if n.len() > libwrit::model::MAX_NOTE => err(format!(
            "--note is limited to {} bytes",
            libwrit::model::MAX_NOTE
        )),
        Some(n) => Ok(Some(n.to_owned())),
        None => Ok(None),
    }
}

/// Signs and records a statement as the identity; prints it.
fn issue(
    parsed: &Parsed,
    ident: &mut IdentityDir,
    statement: Statement,
    out: Option<&str>,
) -> Result<libwrit::Signed<Statement>> {
    let signers = ident.signers(parsed.values("key"))?;
    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    let signed = libwrit::issue(statement, &ident.log, &refs, &mut OsRng)
        .map_err(|e| Error::Msg(e.to_string()))?;
    let item = Item::Statement(signed.clone());
    ident.record(std::slice::from_ref(&item))?;
    match out {
        Some(path) => std::fs::write(path, item.armor())
            .map_err(|e| Error::Msg(format!("writing {path}: {e}")))?,
        None => fs::emit(&item, Some(&ident.dir.join(crate::ident::ISSUED)))?,
    }
    Ok(signed)
}

fn base(ident: &IdentityDir, issued: libwrit::Time) -> (Issuer, libwrit::Time) {
    (
        Issuer::Identity {
            id: ident.id(),
            event: ident.log.head_n(),
        },
        issued,
    )
}

/// `--expires` for a name or grant. One for a leaf key must expire within
/// 24 hours (DESIGN.md §7).
fn subject_expiry(
    parsed: &Parsed,
    ident: &IdentityDir,
    subj: &Subject,
    issued: libwrit::Time,
) -> Result<Option<libwrit::Time>> {
    let is_leaf = matches!(subj, Subject::Leaf(_));
    if is_leaf && parsed.value("expires").is_none() {
        return err(
            "a name or grant for a leaf key must expire within 24 hours; add --expires, such as --expires 24h",
        );
    }
    let expires = expiry(parsed, issued, ident.log.head().max_validity(), None)?;
    if is_leaf && expires.is_some_and(|e| e - issued > LEAF_CEILING) {
        return err("a name or grant for a leaf key can last at most 24 hours");
    }
    Ok(expires)
}

pub fn name(parsed: &Parsed) -> Result<()> {
    let [name_text, subject_text] = parsed.exact(&NAME, ["NAME", "SUBJECT"])?;
    let mut ident = identity(parsed, &NAME)?;
    let name = subject::name(name_text)?;
    let subj = subject::subject(subject_text)?;
    let (issuer, issued) = base(&ident, wall_clock());
    let expires = subject_expiry(parsed, &ident, &subj, issued)?;
    let signed = issue(
        parsed,
        &mut ident,
        Statement {
            issuer,
            issued,
            expires,
            note: note(parsed)?,
            claim: Claim::Name {
                name: name.clone(),
                subject: subj.clone(),
            },
        },
        None,
    )?;
    say(
        parsed,
        format!(
            "named {} {} → {} [{}]",
            ident.name(),
            writ_sexp::readable::print_atom(&name),
            display::subject(&subj),
            display::short(&signed.body.hash())
        ),
    );
    Ok(())
}

pub fn grant(parsed: &Parsed) -> Result<()> {
    let [subject_text, tag_text] = parsed.exact(&GRANT, ["SUBJECT", "TAG"])?;
    let mut ident = identity(parsed, &GRANT)?;
    let subj = subject::subject(subject_text)?;
    let tag = subject::tag(tag_text)?;
    let delegate = parsed.flag("delegate");
    if delegate && matches!(subj, Subject::Opaque(_)) {
        return err(
            "--delegate does not work with an application key, because it can't sign statements",
        );
    }
    let (issuer, issued) = base(&ident, wall_clock());
    let expires = subject_expiry(parsed, &ident, &subj, issued)?;
    if let Subject::Name(p) = &subj {
        say(
            parsed,
            format!(
                "note: {} is a name path, so this grant goes to whoever the path names, \
                 now and in the future",
                display::name_path(p)
            ),
        );
    }
    let signed = issue(
        parsed,
        &mut ident,
        Statement {
            issuer,
            issued,
            expires,
            note: note(parsed)?,
            claim: Claim::Grant {
                subject: subj.clone(),
                tag: tag.clone(),
                delegate,
            },
        },
        None,
    )?;
    say(
        parsed,
        format!(
            "granted {tag} to {}{}{} [{}]",
            display::subject(&subj),
            if delegate { ", delegable" } else { "" },
            expires
                .map(|e| format!(", until {}", display::time(e)))
                .unwrap_or_default(),
            display::short(&signed.body.hash())
        ),
    );
    Ok(())
}

/// Finds the hash a revocation should target.
fn revocation_target(ident: &IdentityDir, text: &str) -> Result<(Hash, String)> {
    let path = std::path::Path::new(text);
    if path.is_file() {
        let bytes = fs::read_input(text, "an item to revoke")?;
        let items = Item::decode_bundle(&bytes).map_err(|e| Error::Msg(format!("{text}: {e}")))?;
        let [item] = items.as_slice() else {
            return err(format!(
                "{text}: expected exactly one statement or signature"
            ));
        };
        let (hash, issuer) = match item {
            Item::Statement(s) => (s.body.hash(), s.body.issuer.id()),
            Item::Signature(s) => (s.body.hash(), s.body.signer.id()),
            other => return err(format!("{text}: can't revoke a {}", other.kind())),
        };
        if issuer != Some(ident.id()) {
            return err(format!(
                "{text} was not issued by {}; only the issuer can revoke",
                ident.name()
            ));
        }
        return Ok((hash, describe_item(item)));
    }
    let prefix = text.to_ascii_lowercase();
    if prefix.len() < 6 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return err(format!(
            "{text:?}: expected a statement hash (at least 6 hex digits) or a file"
        ));
    }
    let mut matches: Vec<(Hash, String)> = Vec::new();
    for item in &ident.issued {
        let h = match item {
            Item::Statement(s) => s.body.hash(),
            Item::Signature(s) => s.body.hash(),
            _ => continue,
        };
        if h.to_hex().starts_with(&prefix) && !matches.iter().any(|(m, _)| *m == h) {
            matches.push((h, describe_item(item)));
        }
    }
    match matches.len() {
        1 => matches.pop().ok_or_else(|| Error::Msg("no match".into())),
        0 => match Hash::from_hex(&prefix) {
            Some(h) => {
                crate::warn(format!("{text} is not in {}/issued.writ", ident.name()));
                Ok((h, "not in the issuance log".into()))
            }
            None => err(format!(
                "no statement or signature in {}/issued.writ starts with {text}",
                ident.name()
            )),
        },
        n => err(format!("{text} is ambiguous: {n} items start with it")),
    }
}

fn describe_item(item: &Item) -> String {
    match item {
        Item::Statement(s) => display::describe(&s.body),
        Item::Signature(s) => format!(
            "signature on {} in context {}",
            display::short(&s.body.data),
            writ_sexp::readable::print_atom(&s.body.context)
        ),
        other => other.kind().to_owned(),
    }
}

pub fn revoke(parsed: &Parsed) -> Result<()> {
    let [target_text] = parsed.exact(&REVOKE, ["TARGET"])?;
    let mut ident = identity(parsed, &REVOKE)?;
    let (target, what) = revocation_target(&ident, target_text)?;
    let already = ident.issued.iter().any(|i| {
        matches!(i, Item::Statement(s) if matches!(s.body.claim, Claim::Revoke { target: t } if t == target))
    });
    if already {
        crate::note(format!(
            "{} is already revoked; this adds a second revocation",
            display::short(&target)
        ));
    }
    let (issuer, issued) = base(&ident, wall_clock());
    let signed = issue(
        parsed,
        &mut ident,
        Statement {
            issuer,
            issued,
            expires: None,
            note: note(parsed)?,
            claim: Claim::Revoke { target },
        },
        None,
    )?;
    say(
        parsed,
        format!(
            "revoked {} ({what}) [{}]",
            display::short(&target),
            display::short(&signed.body.hash())
        ),
    );
    Ok(())
}

pub fn leaf(parsed: &Parsed) -> Result<()> {
    let [tag_text] = parsed.exact(&LEAF, ["TAG"])?;
    let out = parsed.value("out").ok_or_else(|| {
        LEAF.usage_error("--out PATH is required: where should the leaf's secret key go?".into())
    })?;
    let mut ident = identity(parsed, &LEAF)?;
    let tag = subject::tag(tag_text)?;
    fs::check_secret_target(out)?;
    let (issuer, issued) = base(&ident, wall_clock());
    let expires = expiry(parsed, issued, None, Some(LEAF_CEILING))?;
    let Some(expires) = expires else {
        return err("a leaf grant must expire");
    };
    if expires - issued > LEAF_CEILING {
        return err(format!(
            "a leaf key can live at most 24 hours, not {}",
            Duration(expires - issued)
        ));
    }
    if let Some(mv) = ident.log.head().max_validity()
        && expires - issued > mv
    {
        return err(format!(
            "this identity requires statements to expire within {}",
            Duration(mv)
        ));
    }
    // Sign the grant before writing the key, so a failure leaves no orphan key.
    let seed = Seed::generate(&mut OsRng);
    let leaf = seed.leaf();
    let signers = ident.signers(parsed.values("key"))?;
    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    let signed = libwrit::issue(
        Statement {
            issuer,
            issued,
            expires: Some(expires),
            note: note(parsed)?,
            claim: Claim::Grant {
                subject: Subject::Leaf(leaf.leaf_key().clone()),
                tag: tag.clone(),
                delegate: parsed.flag("delegate"),
            },
        },
        &ident.log,
        &refs,
        &mut OsRng,
    )
    .map_err(|e| Error::Msg(e.to_string()))?;
    fs::write_secret(out, &fs::seeds_text(std::slice::from_ref(&seed)))?;
    let item = Item::Statement(signed.clone());
    ident.record(std::slice::from_ref(&item))?;
    match parsed.value("grant-out") {
        Some(path) => std::fs::write(path, item.armor())
            .map_err(|e| Error::Msg(format!("writing {path}: {e}")))?,
        None if out == "-" => {
            crate::note(format!(
                "the key went to standard output, so the grant was not printed. It is in {}/issued.writ, and 'writ export -i {}' prints it",
                ident.name(),
                ident.name()
            ));
        }
        None => fs::emit(&item, Some(&ident.dir.join(crate::ident::ISSUED)))?,
    }
    say(
        parsed,
        format!(
            "leaf:{} holds {tag} until {} [{}]",
            leaf.leaf_key().fingerprint(),
            display::time(expires),
            display::short(&signed.body.hash())
        ),
    );
    Ok(())
}

pub fn sign(parsed: &Parsed) -> Result<()> {
    let file = match parsed.positional.as_slice() {
        [] => "-",
        [f] => f.as_str(),
        _ => return Err(SIGN.usage_error("expected at most one FILE".into())),
    };
    let context = parsed.value("context").ok_or_else(|| {
        SIGN.usage_error("--context CONTEXT is required, e.g. --context example/release/v1".into())
    })?;
    let data = fs::read_input(file, "the data to sign")?;
    let hash = Hash::of_data(&data);
    let issued = wall_clock();
    let (item, by, ident) = match (parsed.value("identity"), parsed.value("leaf")) {
        (Some(_), Some(_)) => return err("sign with either -i DIR or --leaf KEY, not both"),
        (None, None) => {
            return Err(SIGN.usage_error("give -i DIR or --leaf KEY to choose who signs".into()));
        }
        (None, Some(key)) => {
            let seeds = fs::read_seeds(key)?;
            let [seed] = seeds.as_slice() else {
                return err(format!("{key}: expected one leaf key"));
            };
            let leaf = seed.leaf();
            let PublicKey::Leaf(pk) = leaf.public_key() else {
                return err("not a leaf key");
            };
            let sig = libwrit::sign_data_leaf(hash, context.as_bytes(), issued, &leaf, &mut OsRng)
                .map_err(|e| Error::Msg(e.to_string()))?;
            (
                Item::Signature(sig),
                format!("leaf:{}", pk.fingerprint()),
                None,
            )
        }
        (Some(_), None) => {
            let ident = identity(parsed, &SIGN)?;
            let signers = ident.signers(parsed.values("key"))?;
            let refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
            let sig = libwrit::sign_data(
                hash,
                context.as_bytes(),
                issued,
                &ident.log,
                &refs,
                &mut OsRng,
            )
            .map_err(|e| Error::Msg(e.to_string()))?;
            let by = ident.id().to_string();
            (Item::Signature(sig), by, Some(ident))
        }
    };
    if let Some(mut ident) = ident {
        ident.record(std::slice::from_ref(&item))?;
    }
    match parsed.value("out") {
        Some(path) => {
            if std::path::Path::new(path).exists() {
                return err(format!("{path} already exists"));
            }
            std::fs::write(path, item.armor())
                .map_err(|e| Error::Msg(format!("writing {path}: {e}")))?;
        }
        None => fs::print(&item.armor())?,
    }
    let Item::Signature(s) = &item else {
        return Ok(());
    };
    say(
        parsed,
        format!(
            "signed {} as {by} in context {} [{}]",
            if file == "-" { "stdin" } else { file },
            context,
            display::short(&s.body.hash())
        ),
    );
    Ok(())
}
