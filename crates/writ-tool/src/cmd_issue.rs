//! `name`, `grant`, `revoke`, `leaf`, `sign`.

use crate::args::{Parsed, Spec, flag, opt, short};
use crate::cmd_identity::expiry;
use crate::error::{Error, Result, err};
use crate::ident::IdentityDir;
use crate::{OsRng, display, fs, say, subject, wall_clock};
use libwrit::model::LEAF_CEILING;
use libwrit::time::Duration;
use libwrit::{Body, Claim, Hash, Issuer, Item, PublicKey, Seed, Signer, Statement, Subject};

pub static NAME: Spec = Spec {
    name: "name",
    usage: "name -i DIR NAME SUBJECT [options]",
    about: "say who NAME refers to, in your namespace",
    details: "\
Names are local: `me alice` is whoever you said alice is. One name may refer
to several subjects (a group). SUBJECT is an id (writ1…), an identity
directory, a name path ('writ1… bob laptops'), a key file, or an OpenSSH
public key.

The statement is printed as an armored item (append it to a bundle with >>)
and recorded in DIR/issued.writ, which `writ export` and `writ rotate` use.",
    opts: &[
        short(opt("identity", "DIR", "the issuing identity"), 'i'),
        opt(
            "key",
            "PATH",
            "secret key (default DIR/current.key; repeat for K of N)",
        ),
        opt(
            "expires",
            "WHEN",
            "duration (30d) or date (2027-01-01); default never",
        ),
        opt(
            "note",
            "TEXT",
            "display-only text, signed with the statement",
        ),
        short(flag("quiet", "print only the statement"), 'q'),
    ],
};

pub static GRANT: Spec = Spec {
    name: "grant",
    usage: "grant -i DIR SUBJECT TAG [options]",
    about: "grant TAG to SUBJECT",
    details: "\
TAG is a path of atoms, general to specific: '(ssh nas)', '(zuko home)', or
'()' for everything. Holders of '(zuko)' hold '(zuko home relay)'. With
--delegate the subject may grant onward, but only within TAG.

Granting to a name path ('me alice devices') delegates naming: whoever alice
names as her devices gets the grant.

Grants to leaf keys must expire within 24 hours.

The statement is printed as an armored item (append it to a bundle with >>)
and recorded in DIR/issued.writ, which `writ export` and `writ rotate` use.",
    opts: &[
        short(opt("identity", "DIR", "the issuing identity"), 'i'),
        opt(
            "key",
            "PATH",
            "secret key (default DIR/current.key; repeat for K of N)",
        ),
        flag("delegate", "let the subject grant onward (within TAG)"),
        opt(
            "expires",
            "WHEN",
            "duration (30d) or date (2027-01-01); default never",
        ),
        opt(
            "note",
            "TEXT",
            "display-only text, signed with the statement",
        ),
        short(flag("quiet", "print only the statement"), 'q'),
    ],
};

pub static REVOKE: Spec = Spec {
    name: "revoke",
    usage: "revoke -i DIR TARGET [options]",
    about: "revoke one of your statements or signatures",
    details: "\
TARGET is a hash (or a unique prefix of one, as `writ show` and the issuing
commands print) from DIR/issued.writ, or a file holding the item. Revocations
are final: to undo one, issue the statement again.",
    opts: &[
        short(opt("identity", "DIR", "the issuing identity"), 'i'),
        opt(
            "key",
            "PATH",
            "secret key (default DIR/current.key; repeat for K of N)",
        ),
        opt(
            "note",
            "TEXT",
            "display-only text, signed with the revocation",
        ),
        short(flag("quiet", "print only the revocation"), 'q'),
    ],
};

pub static LEAF: Spec = Spec {
    name: "leaf",
    usage: "leaf -i DIR TAG --out PATH [options]",
    about: "make a short-lived leaf key and grant it TAG",
    details: "\
Leaf keys are the fast path: ML-DSA-65 + Ed25519, quick to sign and verify,
always time-bounded (at most 24 hours). A leaf can sign data and, with
--delegate, issue non-delegable grants within TAG. Renew a leaf by granting
to its public key again (`writ pubkey --leaf KEY`), or make a new one.

The secret key goes to --out; the grant is printed (or written to
--grant-out) and recorded in DIR/issued.writ.",
    opts: &[
        short(opt("identity", "DIR", "the issuing identity"), 'i'),
        opt(
            "key",
            "PATH",
            "secret key (default DIR/current.key; repeat for K of N)",
        ),
        opt(
            "out",
            "PATH",
            "where to write the leaf's secret key ('-' for stdout); required",
        ),
        opt(
            "grant-out",
            "PATH",
            "where to write the grant (default stdout)",
        ),
        opt("expires", "WHEN", "lifetime, at most 24h (default 24h)"),
        flag(
            "delegate",
            "let the leaf issue (non-delegable) grants within TAG",
        ),
        opt("note", "TEXT", "display-only text, signed with the grant"),
        short(flag("quiet", "print only the grant"), 'q'),
    ],
};

pub static SIGN: Spec = Spec {
    name: "sign",
    usage: "sign (-i DIR | --leaf KEY) --context CONTEXT [FILE]",
    about: "sign a file (or stdin)",
    details: "\
CONTEXT is an application label that keeps signatures for one purpose from
being accepted for another, e.g. 'example/release/v1'. Verifiers must ask for
the same context. Prints the signature as an armored item.

Signatures by an identity are recorded in DIR/issued.writ so that rotation
keeps them; signatures by a leaf key live as long as its grant.",
    opts: &[
        short(opt("identity", "DIR", "sign as this identity"), 'i'),
        opt(
            "key",
            "PATH",
            "identity secret key (default DIR/current.key)",
        ),
        opt("leaf", "KEY", "sign with this leaf secret key instead"),
        short(
            opt("context", "CONTEXT", "application label (required)"),
            'c',
        ),
        opt("out", "PATH", "write the signature here instead of stdout"),
        short(flag("quiet", "print only the signature"), 'q'),
    ],
};

fn identity(parsed: &Parsed, spec: &'static Spec) -> Result<IdentityDir> {
    let dir = parsed.value("identity").ok_or_else(|| {
        spec.usage_error("-i DIR is required: which identity is speaking?".into())
    })?;
    IdentityDir::open(dir)
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

pub fn name(parsed: &Parsed) -> Result<()> {
    let [name_text, subject_text] = parsed.exact(&NAME, ["NAME", "SUBJECT"])?;
    let mut ident = identity(parsed, &NAME)?;
    let name = subject::name(name_text)?;
    let subj = subject::subject(subject_text)?;
    let (issuer, issued) = base(&ident, wall_clock());
    let expires = expiry(parsed, issued, ident.log.head().max_validity(), None)?;
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
            "an application key can't delegate (it can't sign statements); drop --delegate",
        );
    }
    let (issuer, issued) = base(&ident, wall_clock());
    let is_leaf = matches!(subj, Subject::Leaf(_));
    if is_leaf && parsed.value("expires").is_none() {
        return err("grants to leaf keys must expire within 24 hours: add --expires (e.g. 24h)");
    }
    let expires = expiry(parsed, issued, ident.log.head().max_validity(), None)?;
    if is_leaf && expires.is_some_and(|e| e - issued > LEAF_CEILING) {
        return err("grants to leaf keys may last at most 24 hours");
    }
    if let Subject::Name(p) = &subj {
        say(
            parsed,
            format!(
                "note: this delegates naming. Whoever {} refers to now or later — as decided by \
                 the identities along the path — holds {tag}.",
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
                eprintln!(
                    "writ: warning: {text} is not in {}/issued.writ",
                    ident.name()
                );
                Ok((h, "an item not in the issuance log".into()))
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
        eprintln!(
            "writ: note: {} was already revoked; issuing another revocation",
            display::short(&target)
        );
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
    if out != "-" && std::path::Path::new(out).is_file() {
        return err(format!("{out} already exists; writ never overwrites a key"));
    }
    let (issuer, issued) = base(&ident, wall_clock());
    let expires = expiry(parsed, issued, None, Some(LEAF_CEILING))?;
    let Some(expires) = expires else {
        return err("a leaf grant must expire");
    };
    if expires - issued > LEAF_CEILING {
        return err(format!(
            "leaf keys live at most 24 hours (asked for {})",
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
            eprintln!(
                "writ: the grant is in {}/issued.writ (stdout carries the key); `writ export -i {}` includes it",
                ident.name(),
                ident.name()
            );
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
            return Err(SIGN.usage_error("who signs? pass -i DIR or --leaf KEY".into()));
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
