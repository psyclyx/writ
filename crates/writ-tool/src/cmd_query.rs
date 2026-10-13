//! `check`, `resolve`, `prove`, `verify`, `show`.

use crate::args::{Parsed, Spec};
use crate::error::{Error, Result, err};
use crate::ident::{self, IdentityDir};
use crate::specs::{CHECK, PROVE, RESOLVE, VERIFY};
use crate::state::State;
use crate::style::{self, Stream};
use crate::{display, fs, subject, wall_clock};
use libwrit::time::parse_duration;
use libwrit::{Body, Denial, Floor, Id, Item, Material, Policy, Time, Verifier};
use std::collections::BTreeSet;
use std::path::Path;

/// Everything a question needs.
struct Query {
    roots: Vec<Id>,
    material: Material,
    policy: Policy,
    now: Time,
    wall: Time,
    pinned: bool,
    state: Option<State>,
}

impl Query {
    fn setup(parsed: &Parsed, spec: &'static Spec, stdin_free: bool) -> Result<Query> {
        if parsed.values("as").is_empty() {
            return Err(spec
                .usage_error("--as is required: the identity whose point of view to use".into()));
        }
        let mut material = Material::new();
        let mut roots = Vec::new();
        for who in parsed.values("as") {
            if ident::is_identity_dir(Path::new(who)) {
                let dir = IdentityDir::open(who)?;
                roots.push(dir.id());
                for item in dir.log.items().chain(dir.issued.iter().cloned()) {
                    material.add(item);
                }
            } else {
                roots.push(subject::id(who)?);
            }
        }
        let inputs = parsed.values("in");
        let mut sources: Vec<String> = inputs.to_vec();
        if inputs.is_empty() && stdin_free && fs::stdin_is_piped() {
            sources.push("-".into());
        }
        for src in &sources {
            let bytes = fs::read_input(src, "the bundle")?;
            let name = if src == "-" { "stdin" } else { src.as_str() };
            material
                .add_bundle(&bytes)
                .map_err(|e| Error::Msg(format!("{name}: {e}")))?;
        }
        let state = parsed.value("state").map(State::open).transpose()?;
        if let Some(s) = &state {
            for item in &s.logs {
                material.add(item.clone());
            }
        }
        label_roots_names(&roots, &material);
        let mut policy = Policy::default();
        if let Some(c) = parsed.value("leaf-ceiling") {
            policy.leaf_ceiling = parse_duration(c)
                .ok_or_else(|| Error::Msg(format!("--leaf-ceiling: not a duration: {c:?}")))?;
        }
        let wall = wall_clock();
        let (now, pinned) = match parsed.value("at") {
            Some(t) => (
                libwrit::time::parse_time(t).ok_or_else(|| {
                    Error::Msg(format!(
                        "--at: expected a date like 2027-01-01 or 2027-01-01T12:00Z, got {t:?}"
                    ))
                })?,
                true,
            ),
            None => (
                Floor::new(state.as_ref().and_then(|s| s.floor)).now(wall, 0),
                false,
            ),
        };
        Ok(Query {
            roots,
            material,
            policy,
            now,
            wall,
            pinned,
            state,
        })
    }

    fn verifier(&self) -> Verifier<'_> {
        Verifier::new(&self.roots, &self.material, &self.policy)
    }

    /// Updates `--state`: raise the floor, remember the logs involved.
    fn persist(&self, ids: impl IntoIterator<Item = Id>) -> Result<()> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let floor = if self.pinned {
            None
        } else {
            let mut floor = Floor::new(state.floor);
            if let Some(w) = self.verifier().time_witness() {
                floor.observe(w, self.wall, self.policy.skew);
            }
            Some(floor.value())
        };
        // Remember the logs of every identity this question involved (not every
        // identity in the input: that would let anyone grow the state without
        // bound). DESIGN.md §4.4.
        let mut all: BTreeSet<Id> = ids.into_iter().collect();
        all.extend(self.roots.iter().copied());
        state.save(floor, &self.material, all)
    }

    fn deny(&self, parsed: &Parsed, headline: String, d: &Denial) -> Error {
        if !parsed.flag("quiet") {
            eprint!(
                "{} {headline}: {}",
                style::paint(Stream::Err, style::BAD, "denied:"),
                display::denial(d, &self.material)
            );
        }
        Error::Denied
    }
}

/// Identities a denial involved: the compromised one, or the issuers of the
/// candidates that failed.
fn denial_ids(d: &Denial, material: &Material) -> Vec<Id> {
    match d {
        Denial::Compromised(e) => vec![e.id()],
        Denial::NotFound { rejected } => rejected
            .iter()
            .filter_map(|r| material.statement(&r.statement)?.body.issuer.id())
            .collect(),
        _ => Vec::new(),
    }
}

fn subject_id(h: &libwrit::Holder) -> Option<Id> {
    match h {
        libwrit::Holder::Id(id) => Some(*id),
        _ => None,
    }
}

pub fn check(parsed: &Parsed) -> Result<()> {
    let [subject_text, tag_text] = parsed.exact(&CHECK, ["SUBJECT", "TAG"])?;
    require_as(parsed, &CHECK)?;
    let holder = subject::holder(subject_text)?;
    let tag = subject::tag(tag_text)?;
    let q = Query::setup(parsed, &CHECK, true)?;
    let result = q.verifier().check(&holder, &tag, q.now);
    match result {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied().chain(subject_id(&holder)))?;
            if !parsed.flag("quiet") {
                fs::print(&format!(
                    "{} {} holds {tag}\n{}",
                    style::paint(Stream::Out, style::OK, "allowed:"),
                    display::holder(&holder),
                    display::proof(&proof, &q.material, q.now)
                ))?;
            }
            Ok(())
        }
        Err(d) => {
            q.persist(
                denial_ids(&d, &q.material)
                    .into_iter()
                    .chain(subject_id(&holder)),
            )?;
            Err(q.deny(
                parsed,
                format!("{} does not hold {tag}", display::holder(&holder)),
                &d,
            ))
        }
    }
}

pub fn prove(parsed: &Parsed) -> Result<()> {
    let [subject_text, tag_text] = parsed.exact(&PROVE, ["SUBJECT", "TAG"])?;
    require_as(parsed, &PROVE)?;
    let holder = subject::holder(subject_text)?;
    let tag = subject::tag(tag_text)?;
    let q = Query::setup(parsed, &PROVE, true)?;
    match q.verifier().check(&holder, &tag, q.now) {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied().chain(subject_id(&holder)))?;
            let items = proof.items(&q.material);
            fs::print(&items.iter().map(Item::armor).collect::<String>())?;
            if !parsed.flag("quiet") {
                eprintln!(
                    "proof: {} log event{} and {} statement{}",
                    items.iter().filter(|i| matches!(i, Item::Event(_))).count(),
                    plural(items.iter().filter(|i| matches!(i, Item::Event(_))).count()),
                    proof.statements().len(),
                    plural(proof.statements().len())
                );
            }
            Ok(())
        }
        Err(d) => {
            q.persist(
                denial_ids(&d, &q.material)
                    .into_iter()
                    .chain(subject_id(&holder)),
            )?;
            Err(q.deny(
                parsed,
                format!("{} does not hold {tag}", display::holder(&holder)),
                &d,
            ))
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn resolve(parsed: &Parsed) -> Result<()> {
    let [path_text] = parsed.exact(&RESOLVE, ["NAMEPATH"])?;
    require_as(parsed, &RESOLVE)?;
    // The output is for scripts: full ids.
    display::full_ids();
    let q = Query::setup(parsed, &RESOLVE, true)?;
    let path = subject::name_path(path_text, q.roots.first().copied())?;
    match q.verifier().resolve(&path, q.now) {
        Ok(members) => {
            let mut ids = BTreeSet::new();
            let mut out = String::new();
            for (holder, proof) in &members {
                ids.extend(proof.ids.iter().copied());
                out.push_str(&display::holder(holder));
                out.push('\n');
                if parsed.flag("verbose") {
                    out.push_str(&display::proof(proof, &q.material, q.now));
                }
            }
            q.persist(ids.into_iter().chain([path.base]))?;
            fs::print(&out)
        }
        Err(d) => {
            q.persist(denial_ids(&d, &q.material).into_iter().chain([path.base]))?;
            Err(q.deny(
                parsed,
                format!("{} refers to no one", display::name_path(&path)),
                &d,
            ))
        }
    }
}

pub fn verify(parsed: &Parsed) -> Result<()> {
    let [file, sig_path] = parsed.exact(&VERIFY, ["FILE", "SIGNATURE"])?;
    require_as(parsed, &VERIFY)?;
    let tag = subject::tag(parsed.value("tag").ok_or_else(|| {
        VERIFY.usage_error("--tag is required: what the signer must hold".into())
    })?)?;
    let context = parsed
        .value("context")
        .ok_or_else(|| VERIFY.usage_error("--context CONTEXT is required".into()))?;
    let sig_bytes = fs::read_input(sig_path, "the signature")?;
    let items =
        Item::decode_bundle(&sig_bytes).map_err(|e| Error::Msg(format!("{sig_path}: {e}")))?;
    let sig = match items.as_slice() {
        [Item::Signature(s)] => s.clone(),
        _ => {
            return err(format!(
                "{sig_path}: expected one signature (from `writ sign`)"
            ));
        }
    };
    let hash = fs::hash_input(file, "the signed data")?;
    let q = Query::setup(parsed, &VERIFY, file != "-" && sig_path != "-")?;
    let signer = match &sig.body.signer {
        libwrit::Issuer::Identity { id, .. } => display::id(id),
        libwrit::Issuer::Leaf(k) => format!("leaf:{}", k.fingerprint()),
    };
    match q
        .verifier()
        .verify(&sig, &hash, context.as_bytes(), &tag, q.now)
    {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied())?;
            if !parsed.flag("quiet") {
                fs::print(&format!(
                    "{} by {signer}, signed {}, holding {tag}\n{}",
                    style::paint(Stream::Out, style::OK, "good signature"),
                    display::time(sig.body.issued),
                    display::proof(&proof, &q.material, q.now)
                ))?;
            }
            Ok(())
        }
        Err(d) => {
            q.persist(
                denial_ids(&d, &q.material)
                    .into_iter()
                    .chain(sig.body.signer.id()),
            )?;
            let headline = match &d {
                Denial::NotFound { .. }
                | Denial::Compromised(_)
                | Denial::Root { .. }
                | Denial::Limit(_) => {
                    format!("{signer} does not hold {tag}")
                }
                _ => format!("signature {}", display::short(&sig.body.hash())),
            };
            Err(q.deny(parsed, headline, &d))
        }
    }
}

pub fn show(parsed: &Parsed) -> Result<()> {
    display::full_ids();
    let files: Vec<String> = if parsed.positional.is_empty() {
        vec!["-".into()]
    } else {
        parsed.positional.clone()
    };
    let mut out = String::new();
    for f in &files {
        let bytes = fs::read_input(f, "a bundle")?;
        let name = if f == "-" { "stdin" } else { f.as_str() };
        let items = Item::decode_bundle(&bytes).map_err(|e| Error::Msg(format!("{name}: {e}")))?;
        for item in &items {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&display::item(item));
        }
    }
    fs::print(&out)
}

/// Labels the identities the roots name directly ("me alice" → alice), for
/// readable explanations. Only valid name statements count.
fn label_roots_names(roots: &[Id], material: &Material) {
    let policy = Policy::default();
    let v = Verifier::new(roots, material, &policy);
    let now = wall_clock();
    for root in roots {
        for h in material.issued_by(root) {
            if let Some(st) = material.statement(h)
                && let libwrit::Claim::Name {
                    name,
                    subject: libwrit::Subject::Id(id),
                } = &st.body.claim
                && let Ok(name) = std::str::from_utf8(name)
                && v.statement_status(h, now).is_ok()
            {
                display::label(*id, name);
            }
        }
    }
}

fn require_as(parsed: &Parsed, spec: &'static Spec) -> Result<()> {
    if parsed.values("as").is_empty() {
        return Err(
            spec.usage_error("--as is required: the identity whose point of view to use".into())
        );
    }
    Ok(())
}
