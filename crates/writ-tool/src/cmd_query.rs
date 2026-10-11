//! `check`, `resolve`, `prove`, `verify`, `show`.

use crate::args::{Opt, Parsed, Spec, flag, opt, short};
use crate::error::{Error, Result, err};
use crate::ident::{self, IdentityDir};
use crate::state::State;
use crate::{display, fs, subject, wall_clock};
use libwrit::time::parse_duration;
use libwrit::{Body, Denial, Floor, Id, Item, Material, Policy, Time, Verifier};
use std::collections::BTreeSet;
use std::path::Path;

macro_rules! query_opts {
    ($($extra:expr),* $(,)?) => {
        &[
            opt("as", "ID", "whose point of view: an id or identity directory (repeatable)"),
            opt("in", "PATH", "read material from PATH (repeatable; '-' for stdin)"),
            opt("at", "TIME", "answer as of TIME (2027-01-01, 2027-01-01T12:00Z, @UNIX)"),
            opt("state", "DIR", "verifier state: clock floor and remembered logs"),
            opt("leaf-ceiling", "DUR", "accept leaf grants of at most DUR (≤ 24h)"),
            $($extra,)*
            short(flag("quiet", "no explanation; just the exit status"), 'q'),
        ]
    };
}

const CHECK_OPTS: &[Opt] = query_opts!();
const RESOLVE_OPTS: &[Opt] =
    query_opts!(short(flag("verbose", "show each answer's derivation"), 'v'));
const PROVE_OPTS: &[Opt] = query_opts!();
const VERIFY_OPTS: &[Opt] = query_opts!(
    short(
        opt("tag", "TAG", "what the signer must hold (required)"),
        't'
    ),
    short(
        opt(
            "context",
            "CONTEXT",
            "the application label it was signed for (required)"
        ),
        'c'
    ),
);

pub static CHECK: Spec = Spec {
    name: "check",
    usage: "check --as ID SUBJECT TAG [options] [< bundle]",
    about: "does SUBJECT hold TAG?",
    details: "\
Exit status 0 means yes, and the chain of grants is printed; 1 means no, and
the reasons are printed to stderr.

SUBJECT is an id, an identity directory, a key file, or an OpenSSH public
key. TAG is what's being asked for: holding '(ssh)' covers '(ssh nas)'.

The material (identity logs, statements, revocations) comes from --in files,
from stdin when it is piped, and from each --as directory's own log and
issuance log. Order doesn't matter.

Time: the wall clock, never earlier than writ's build date or the --state
floor (the newest statement from your roots seen so far). --at overrides it.",
    opts: CHECK_OPTS,
};

pub static RESOLVE: Spec = Spec {
    name: "resolve",
    usage: "resolve --as ID NAMEPATH [options] [< bundle]",
    about: "who does NAMEPATH refer to?",
    details: "\
NAMEPATH is names in someone's namespace: 'writ1… alice', 'me alice
laptops', or just 'alice' to start from the (first) --as identity. Prints one
subject per line.

The material comes from --in, piped stdin, and --as directories.",
    opts: RESOLVE_OPTS,
};

pub static PROVE: Spec = Spec {
    name: "prove",
    usage: "prove --as ID SUBJECT TAG [options] [< bundle] [> proof.writ]",
    about: "print just the material that shows SUBJECT holds TAG",
    details: "\
The proof is a bundle: the logs and statements on one chain, nothing else.
Hand verifiers the proof rather than everything you know — statements reveal
who knows whom.",
    opts: PROVE_OPTS,
};

pub static VERIFY: Spec = Spec {
    name: "verify",
    usage: "verify --as ID --tag TAG --context CONTEXT FILE SIGNATURE [options] [< bundle]",
    about: "is SIGNATURE on FILE by someone who holds TAG?",
    details: "\
Checks the signature over FILE ('-' for stdin) in CONTEXT, then that its
signer holds TAG from the --as point of view. Exit status 0 means good.

The material comes from --in, piped stdin, and --as directories.",
    opts: VERIFY_OPTS,
};

pub static SHOW: Spec = Spec {
    name: "show",
    usage: "show [FILE...]",
    about: "print bundles readably",
    details: "Reads armored or binary bundles from FILEs or stdin.",
    opts: &[],
};

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
            return Err(spec.usage_error("--as ID is required: from whose point of view?".into()));
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
        // Remember every log seen, not just those this answer used: the
        // ratchet protects future questions too (DESIGN.md §4.4).
        let mut all: BTreeSet<Id> = ids.into_iter().collect();
        all.extend(self.roots.iter().copied());
        all.extend(self.material.ids().copied());
        state.save(floor, &self.material, all)
    }

    fn deny(&self, parsed: &Parsed, headline: String, d: &Denial) -> Error {
        if !parsed.flag("quiet") {
            eprint!("denied: {headline}: {}", display::denial(d, &self.material));
        }
        Error::Denied
    }
}

fn denial_ids(d: &Denial) -> Vec<Id> {
    match d {
        Denial::Compromised(e) => vec![e.id()],
        _ => Vec::new(),
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
            q.persist(proof.ids.iter().copied())?;
            if !parsed.flag("quiet") {
                fs::print(&format!(
                    "allowed: {} holds {tag}\n{}",
                    display::holder(&holder),
                    display::proof(&proof, &q.material, q.now)
                ))?;
            }
            Ok(())
        }
        Err(d) => {
            q.persist(denial_ids(&d))?;
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
            q.persist(proof.ids.iter().copied())?;
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
            q.persist(denial_ids(&d))?;
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
            q.persist(ids)?;
            fs::print(&out)
        }
        Err(d) => {
            q.persist(denial_ids(&d))?;
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
        VERIFY.usage_error("--tag TAG is required: what must the signer hold?".into())
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
    let data = fs::read_input(file, "the signed data")?;
    let hash = libwrit::Hash::of_data(&data);
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
                    "good signature by {signer}, signed {}, holding {tag}\n{}",
                    display::time(sig.body.issued),
                    display::proof(&proof, &q.material, q.now)
                ))?;
            }
            Ok(())
        }
        Err(d) => {
            q.persist(denial_ids(&d))?;
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
        return Err(spec.usage_error("--as ID is required: from whose point of view?".into()));
    }
    Ok(())
}
