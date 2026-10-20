//! Readable output: `writ show`, proofs, and denials.

use crate::style::{self, Stream};
use libwrit::time::{Duration, Rfc3339};
use libwrit::{
    Authority, Body, Claim, DataSig, Denial, Event, Hash, Holder, Id, Issuer, Item, Material,
    NamePath, OpaqueKey, Proof, PublicKey, Signed, Statement, Subject, Time,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use writ_sexp::readable::print_atom;

thread_local! {
    static LABELS: RefCell<BTreeMap<Id, String>> = const { RefCell::new(BTreeMap::new()) };
    static FULL_IDS: Cell<bool> = const { Cell::new(false) };
}

/// Calls `id` by a local name in explanations: an identity directory's name,
/// or what a root named it. The first label for an id wins, and a label is
/// never given to two ids.
pub fn label(id: Id, name: &str) {
    let trimmed = name.trim_end_matches('/');
    let name = std::path::Path::new(trimmed)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(trimmed);
    if name.is_empty()
        || name.starts_with('.')
        || name.starts_with("writ1")
        || !name.bytes().all(writ_sexp::readable::is_token_byte)
    {
        return;
    }
    LABELS.with_borrow_mut(|l| {
        if !l.values().any(|v| v == name) {
            l.entry(id).or_insert_with(|| name.to_owned());
        }
    });
}

/// Print ids in full everywhere (for `writ show`).
pub fn full_ids() {
    FULL_IDS.set(true);
}

/// An id for explanations: its label, or an abbreviation.
pub fn id(id: &Id) -> String {
    let text = id.to_string();
    if FULL_IDS.get() {
        return text;
    }
    if let Some(l) = LABELS.with_borrow(|l| l.get(id).cloned()) {
        return l;
    }
    match (text.get(..13), text.get(text.len().saturating_sub(6)..)) {
        (Some(head), Some(tail)) => format!("{head}…{tail}"),
        _ => text,
    }
}

/// An id with both its label and its full form.
pub fn id_full(id: &Id) -> String {
    match LABELS.with_borrow(|l| l.get(id).cloned()) {
        Some(l) => format!("{l} ({id})"),
        None => id.to_string(),
    }
}

/// A rough duration for humans: 45s, 20m, 5h, 12d, 3y.
pub fn approx(secs: u64) -> String {
    match secs {
        0..120 => format!("{secs}s"),
        120..7200 => format!("{}m", secs / 60),
        7200..172_800 => format!("{}h", secs / 3600),
        172_800..34_560_000 => format!("{}d", secs / 86_400),
        _ => format!("{}y", secs / 31_536_000),
    }
}

/// Abbreviated hash: enough to be unique in practice, and accepted by `writ revoke`.
pub fn short(h: &Hash) -> String {
    h.to_hex().get(..16).unwrap_or_default().to_owned()
}

pub fn time(t: Time) -> String {
    Rfc3339(t).to_string()
}

pub fn names(names: &[Vec<u8>]) -> String {
    names
        .iter()
        .map(|n| print_atom(n))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn name_path(p: &NamePath) -> String {
    format!("({} {})", id(&p.base), names(&p.names))
}

pub fn opaque(k: &OpaqueKey) -> String {
    let kind = String::from_utf8_lossy(&k.kind);
    let b64 = writ_sexp::base64::encode(&k.bytes);
    if b64.len() > 40 {
        let tail = b64.get(b64.len() - 12..).unwrap_or_default();
        format!("{kind} {}…{tail}", b64.get(..20).unwrap_or_default())
    } else {
        format!("{kind} {b64}")
    }
}

pub fn subject(s: &Subject) -> String {
    match s {
        Subject::Id(i) => id(i),
        Subject::Leaf(k) => format!("leaf:{}", k.fingerprint()),
        Subject::Opaque(k) => opaque(k),
        Subject::Name(p) => name_path(p),
    }
}

pub fn holder(h: &Holder) -> String {
    subject(&h.to_subject())
}

pub fn issuer(i: &Issuer) -> String {
    match i {
        Issuer::Identity { id: i, event } => format!("{} (event {event})", id(i)),
        Issuer::Leaf(k) => format!("leaf:{}", k.fingerprint()),
    }
}

fn authority(a: &Authority) -> String {
    let keys: Vec<String> = a
        .keys()
        .iter()
        .map(|k| format!("slh-dsa-shake-128s {}", libwrit::Hash(k.0).to_hex()))
        .collect();
    format!(
        "{} of {}:\n{}",
        a.k(),
        keys.len(),
        keys.iter()
            .map(|k| format!("               {k}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn row(out: &mut String, label: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "  {label:<12} {value}");
}

fn sig_count(n: usize) -> String {
    if n == 1 {
        "1 signature".into()
    } else {
        format!("{n} signatures")
    }
}

/// One item, readably.
pub fn item(item: &Item) -> String {
    let mut out = String::new();
    match item {
        Item::Event(e) => event(&mut out, e),
        Item::Statement(s) => statement(&mut out, s),
        Item::Signature(s) => data_sig(&mut out, s),
        Item::Record(r) => {
            let b = &r.body;
            let _ = writeln!(
                out,
                "{} by {} (event {})",
                style::paint(Stream::Out, style::BOLD, "record"),
                id_full(&b.id),
                b.event
            );
            row(&mut out, "issued", time(b.issued));
            row(&mut out, "head", b.head);
            row(
                &mut out,
                "revokes",
                match b.revoked.len() {
                    0 => "nothing".to_owned(),
                    1 => "1 statement or signature".to_owned(),
                    n => format!("{n} statements or signatures"),
                },
            );
            for h in &b.revoked {
                row(&mut out, "", short(h));
            }
            row(&mut out, "hash", b.hash());
        }
        Item::PublicKey(PublicKey::Root(k)) => {
            let _ = writeln!(out, "key slh-dsa-shake-128s");
            row(&mut out, "public", libwrit::Hash(k.0).to_hex());
        }
        Item::PublicKey(PublicKey::Leaf(k)) => {
            let _ = writeln!(out, "key mldsa65-ed25519");
            row(&mut out, "fingerprint", format!("leaf:{}", k.fingerprint()));
        }
        Item::Authority(a) => {
            let _ = writeln!(out, "authority");
            row(&mut out, "keys", authority(a));
            row(&mut out, "hash", a.hash());
        }
    }
    out
}

fn event(out: &mut String, e: &Signed<Event>) {
    let body = &e.body;
    match body {
        Event::Inception(_) => {
            let _ = writeln!(
                out,
                "{} {}",
                style::paint(Stream::Out, style::BOLD, "inception"),
                id_full(&body.id())
            );
        }
        Event::Rotation(r) => {
            let _ = writeln!(out, "rotation {} of {}", r.n, id_full(&r.id));
            row(out, "prev", r.prev);
        }
    }
    row(out, "authority", authority(body.authority()));
    row(out, "next", body.next());
    if let Some(mv) = body.max_validity() {
        row(out, "max-validity", Duration(mv));
    }
    if let Some(p) = body.publish() {
        row(
            out,
            "publish",
            format!("records at least every {}", Duration(p.max_age())),
        );
        for u in p.urls() {
            row(out, "", u);
        }
    }
    if let Event::Rotation(r) = body {
        row(
            out,
            "keep",
            match r.keep.len() {
                0 => "nothing".to_owned(),
                1 => "1 statement".to_owned(),
                n => format!("{n} statements"),
            },
        );
        for h in &r.keep {
            let _ = writeln!(out, "               {h}");
        }
    }
    row(out, "hash", body.hash());
    row(out, "signed", sig_count(e.sigs.len()));
}

fn statement(out: &mut String, s: &Signed<Statement>) {
    let b = &s.body;
    let _ = writeln!(
        out,
        "{} {}",
        style::paint(Stream::Out, style::BOLD, b.kind()),
        dim(&b.hash().to_hex())
    );
    row(out, "issuer", issuer(&b.issuer));
    row(out, "issued", time(b.issued));
    if let Some(e) = b.expires {
        row(
            out,
            "expires",
            format!(
                "{} ({} after issue)",
                time(e),
                Duration(e.saturating_sub(b.issued))
            ),
        );
    }
    match &b.claim {
        Claim::Name { name, subject: s } => {
            row(out, "name", print_atom(name));
            row(out, "refers to", subject(s));
        }
        Claim::Grant {
            subject: s,
            tags,
            delegate,
        } => {
            row(out, "subject", subject(s));
            row(
                out,
                if tags.as_slice().len() == 1 {
                    "tag"
                } else {
                    "tags"
                },
                tags,
            );
            row(out, "delegate", if *delegate { "yes" } else { "no" });
        }
        Claim::Revoke { target } => row(out, "revokes", target),
    }
    if let Some(n) = &b.note {
        row(out, "note", format!("{n:?}"));
    }
    row(out, "signed", sig_count(s.sigs.len()));
}

fn data_sig(out: &mut String, s: &Signed<DataSig>) {
    let b = &s.body;
    let _ = writeln!(
        out,
        "{} {}",
        style::paint(Stream::Out, style::BOLD, "signature"),
        dim(&b.hash().to_hex())
    );
    row(out, "signer", issuer(&b.signer));
    row(out, "issued", time(b.issued));
    row(out, "context", print_atom(&b.context));
    row(out, "data", b.data);
    row(out, "signed", sig_count(s.sigs.len()));
}

/// The chain behind a positive answer.
/// A proof-line label, padded and colored for stdout.
fn line_label(text: &str) -> String {
    style::paint(Stream::Out, style::ACCENT, &format!("{text:<8}"))
}

/// A hash or other secondary detail, dimmed for stdout.
fn dim(text: &str) -> String {
    style::paint(Stream::Out, style::DIM, text)
}

pub fn proof(p: &Proof, material: &Material, now: Time) -> String {
    let mut out = String::new();
    let start = if p.steps.is_empty() && !p.names.is_empty() {
        "from"
    } else {
        "root"
    };
    let _ = writeln!(out, "  {} {}", line_label(start), id_full(&p.root));
    let mut from = id(&p.root);
    for step in &p.steps {
        for h in &step.names {
            if let Some(st) = material.statement(h)
                && let Claim::Name { name, subject: s } = &st.body.claim
            {
                let who = issuer_short(&st.body.issuer);
                let _ = writeln!(
                    out,
                    "  {} {}  {who}'s {} is {}",
                    line_label("name"),
                    dim(&short(h)),
                    print_atom(name),
                    subject(s)
                );
            }
        }
        if let Some(st) = material.statement(&step.grant)
            && let Claim::Grant { tags, delegate, .. } = &st.body.claim
        {
            // The one of the grant's tags this chain used (§18.2).
            let tag = tags
                .iter()
                .find(|t| step.tag.is_within(t))
                .map(ToString::to_string)
                .unwrap_or_else(|| tags.to_string());
            let _ = writeln!(
                out,
                "  {} {}  {from} → {} {tag}{}",
                line_label("grant"),
                dim(&short(&step.grant)),
                holder(&step.holder),
                if *delegate { " (delegable)" } else { "" }
            );
        }
        from = holder(&step.holder);
    }
    for h in &p.names {
        if let Some(st) = material.statement(h)
            && let Claim::Name { name, subject: s } = &st.body.claim
        {
            let who = issuer_short(&st.body.issuer);
            let _ = writeln!(
                out,
                "  {} {}  {who}'s {} is {}",
                line_label("name"),
                dim(&short(h)),
                print_atom(name),
                subject(s)
            );
        }
    }
    if p.signature.is_none() && p.steps.is_empty() && p.names.is_empty() {
        let _ = writeln!(out, "  (the subject is an --as identity)");
    }
    match p.expires {
        Some(e) => {
            let _ = writeln!(
                out,
                "  {} {} (in {})",
                line_label("until"),
                time(e),
                approx(e.saturating_sub(now))
            );
        }
        None => {
            let _ = writeln!(out, "  {} no expiry", line_label("until"));
        }
    }
    out
}

fn issuer_short(i: &Issuer) -> String {
    match i {
        Issuer::Identity { id: i, .. } => id(i),
        Issuer::Leaf(k) => format!("leaf:{}", k.fingerprint()),
    }
}

/// Why the answer is no.
pub fn denial(d: &Denial, material: &Material) -> String {
    let mut out = format!("{d}\n");
    match d {
        Denial::NotFound { rejected } => {
            if rejected.is_empty() {
                out.push_str("  no statement in the input applies\n");
            } else {
                out.push_str("  statements that did not apply:\n");
            }
            for r in rejected {
                let what = material
                    .statement(&r.statement)
                    .map(|s| describe(&s.body))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "    {} {what}: {}",
                    style::paint(Stream::Err, style::DIM, &short(&r.statement)),
                    r.reason
                );
                if matches!(r.reason, libwrit::Reason::NoFreshRecord { .. }) {
                    out.push_str(&record_hint(material, &r.statement));
                }
            }
        }
        Denial::Signature(libwrit::Reason::NoFreshRecord { .. }) => {
            out.push_str("  get a fresh record from the signer, or run again with --fetch\n");
        }
        Denial::Compromised(e) => {
            let _ = writeln!(
                out,
                "  its next keys signed two different versions of event {}. writ refuses \
                 this identity; with --state it keeps refusing it until you delete \
                 its file from the state directory",
                e.n()
            );
        }
        Denial::Root { .. } => {
            out.push_str("  the input has no valid log for this identity; give its directory with --as, or its log with --in\n");
        }
        _ => {}
    }
    out
}

/// Where a statement's issuer publishes its records.
fn record_hint(material: &Material, statement: &libwrit::Hash) -> String {
    let urls = material
        .statement(statement)
        .and_then(|s| s.body.issuer.id())
        .and_then(|id| {
            let log = material.log(&id);
            let urls = log
                .as_ref()
                .as_ref()
                .ok()?
                .head()
                .publish()?
                .urls()
                .to_vec();
            Some(urls)
        })
        .unwrap_or_default();
    if urls.is_empty() {
        "      get a fresh record from its issuer\n".to_owned()
    } else {
        format!(
            "      a fresh record is published at {}; run again with --fetch\n",
            urls.join(", ")
        )
    }
}

/// One-line summary of a statement.
pub fn describe(s: &Statement) -> String {
    match &s.claim {
        Claim::Grant {
            subject: sj, tags, ..
        } => {
            format!("grant {tags} to {}", subject(sj))
        }
        Claim::Name { name, subject: sj } => {
            format!("name {} → {}", print_atom(name), subject(sj))
        }
        Claim::Revoke { target } => format!("revoke {}", short(target)),
    }
}
