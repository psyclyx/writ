//! `check`, `resolve`, `prove`, `verify`, `show`.

use crate::args::{Parsed, Spec};
use crate::error::{Error, Result, err};
use crate::ident::{self, IdentityDir};
use crate::specs::{CHECK, PROVE, RESOLVE, VERIFY};
use crate::state::State;
use crate::style::{self, Stream};
use crate::{display, fs, subject, wall_clock};
use libwrit::time::{Duration, parse_duration};
use libwrit::{
    Body, Denial, Floor, Holder, Id, Item, LogError, Material, Policy, Reason, Tag, Time, Verifier,
};

/// Most identities `--fetch` gets records for in one command.
const MAX_FETCHES: usize = 16;
/// Most records `--state` keeps per identity: the newest, and older ones
/// that list revocations the kept ones do not. A rotation clears them all.
const MAX_RECORDS_KEPT: usize = 16;
use std::collections::BTreeSet;
use std::path::Path;

/// Everything a question needs.
struct Query {
    roots: Vec<Id>,
    /// --fetch: get missing revocation records and ask again.
    fetch: bool,
    /// Roots given as directories: their whole issuance log is in the
    /// material, so they need no records (DESIGN.md §18.6).
    local: Vec<Id>,
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
        let mut local = Vec::new();
        for who in parsed.values("as") {
            // An id is taken as written, before any directory of that name:
            // otherwise whoever can write to the working directory could
            // answer for `--as writ1…`.
            if let Some(id) = Id::parse(who) {
                roots.push(id);
            } else if ident::is_identity_dir(Path::new(who)) {
                let dir = IdentityDir::open(who)?;
                roots.push(dir.id());
                local.push(dir.id());
                for item in dir.log.items().chain(dir.issued.iter().cloned()) {
                    material.add(item);
                }
                // Its own record, so proofs can carry it (DESIGN.md §18.7).
                let record = dir.dir.join(crate::ident::RECORD);
                if record.is_file() {
                    for item in fs::read_bundle_file(&record)? {
                        material.add(item);
                    }
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
            let name = if fs::is_stdin(src) {
                "stdin"
            } else {
                src.as_str()
            };
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
        let mut policy = Policy {
            require_records: parsed.flag("require-records"),
            ..Policy::default()
        };
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
            fetch: parsed.flag("fetch"),
            local,
            material,
            policy,
            now,
            wall,
            pinned,
            state,
        })
    }

    fn verifier(&self) -> Verifier<'_> {
        Verifier::new(&self.roots, &self.material, &self.policy).with_local(&self.local)
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
        // Remember the identities this question relied on (not every identity
        // in the input, nor subjects it was asked about: that would let
        // anyone grow the state without bound). DESIGN.md §4.4.
        let mut all: BTreeSet<Id> = ids.into_iter().collect();
        all.extend(self.roots.iter().copied());
        let verifier = self.verifier();
        // What to keep is judged as of the latest time known, not an --at
        // in the past: else a record or revocation issued after it would be
        // dropped from the state, and a later bundle could leave it out.
        let latest = self.now.max(self.wall);
        let remembered = all.into_iter().filter_map(|id| {
            let mut items = match &*self.material.log(&id) {
                Ok(log) => log.items().collect::<Vec<_>>(),
                Err(LogError::Equivocation(e)) => e.items(),
                Err(_) => return None,
            };
            // And its revocations, so that one seen once stays seen even
            // when a later bundle (or a proof) leaves it out. Judged without
            // the signature budget: a revocation left undecided would be
            // dropped from the state, the permissive direction, and a bundle
            // merging junk signatures onto a remembered one could arrange
            // that. Only the signatures that verify are written.
            items.extend(self.material.issued_by(&id).iter().filter_map(|h| {
                let st = self.material.statement(h)?;
                let revoke = matches!(st.body.claim, libwrit::Claim::Revoke { .. });
                (revoke && verifier.statement_status_unbudgeted(h, latest).is_ok())
                    .then(|| self.material.shippable(h))?
            }));
            // And its records (DESIGN.md §18.7): the newest, which keeps
            // statements fresh, and any older one that lists a revocation
            // the kept ones don't, since records are combined.
            let mut records: Vec<(libwrit::Hash, &libwrit::Signed<libwrit::Record>)> = self
                .material
                .records_by(&id)
                .iter()
                .filter(|h| verifier.record_status_unbudgeted(h, latest).is_ok())
                .filter_map(|h| Some((*h, self.material.record(h)?)))
                .collect();
            records.sort_by_key(|(_, r)| std::cmp::Reverse(r.body.issued));
            let mut listed = BTreeSet::new();
            let mut kept = 0;
            for (i, (h, r)) in records.into_iter().enumerate() {
                let adds = r.body.revoked.iter().any(|x| !listed.contains(x));
                if (i == 0 || adds) && kept < MAX_RECORDS_KEPT {
                    listed.extend(r.body.revoked.iter().copied());
                    // Only verified signatures: junk merged in must not
                    // make the state file unreadable.
                    items.extend(self.material.shippable_record(&h));
                    kept += 1;
                }
            }
            Some((id, items))
        });
        state.save(floor, remembered)
    }

    /// Asks `question`. With --fetch, a denial that names identities whose
    /// fresh record is missing gets those records from the URLs in their
    /// logs, and the question is asked again (DESIGN.md §18.7). Only
    /// identities the search reached from the roots through valid
    /// statements are fetched for, each once and at most MAX_FETCHES, so a
    /// bundle can't make writ fetch URLs of its choosing. `signer` is a
    /// data signature's signer and the tag it must hold.
    fn ask<T>(
        &mut self,
        signer: Option<(Holder, Tag)>,
        question: impl Fn(&Verifier<'_>) -> std::result::Result<T, Denial>,
    ) -> std::result::Result<T, Denial> {
        let mut tried = BTreeSet::new();
        loop {
            let answer = question(&self.verifier());
            let Err(d) = &answer else { return answer };
            if !self.fetch {
                return answer;
            }
            let mut wanted: Vec<Id> = self
                .stale_issuers(d, signer.as_ref())
                .into_iter()
                .filter(|id| !tried.contains(id))
                .collect();
            if wanted.is_empty() {
                return answer;
            }
            // Fetch up to the budget; what is left over is reported, not
            // silently skipped.
            let room = MAX_FETCHES.saturating_sub(tried.len());
            if wanted.len() > room {
                wanted.truncate(room);
                crate::warn(format!(
                    "stopped fetching after records for {MAX_FETCHES} identities"
                ));
                if wanted.is_empty() {
                    return answer;
                }
            }
            for id in wanted {
                tried.insert(id);
                self.fetch_record(id);
            }
        }
    }

    /// Identities a denial says lack a fresh record, and that are worth
    /// fetching for: issuers of rejected statements the search reached
    /// through valid statements (grants from reached principals, names
    /// under valid grants), and a data signature's signer once it is known
    /// to hold the tag.
    fn stale_issuers(&self, d: &Denial, signer: Option<&(Holder, Tag)>) -> Vec<Id> {
        match d {
            Denial::NotFound { rejected } => rejected
                .iter()
                .filter(|r| matches!(r.reason, Reason::NoFreshRecord { .. }))
                .filter_map(|r| self.material.statement(&r.statement)?.body.issuer.id())
                .collect(),
            Denial::Signature(Reason::NoFreshRecord { .. }) => {
                let Some((holder, tag)) = signer else {
                    return Vec::new();
                };
                match self.verifier().check(holder, tag, self.now) {
                    Ok(_) => match holder {
                        Holder::Id(id) => vec![*id],
                        _ => Vec::new(),
                    },
                    Err(d) => self.stale_issuers(&d, None),
                }
            }
            _ => Vec::new(),
        }
    }

    /// Tries `id`'s publish URLs in turn until one gives a fresh record: a
    /// host that serves nothing useful (an old file, an empty one) must not
    /// stop the others from being tried (DESIGN.md §18.8).
    fn fetch_record(&mut self, id: Id) {
        let urls = match &*self.material.log(&id) {
            Ok(log) => log
                .head()
                .publish()
                .map(|p| p.urls().to_vec())
                .unwrap_or_default(),
            Err(_) => return,
        };
        if urls.is_empty() {
            crate::warn(format!(
                "{} publishes records at no URL; get one from its owner",
                display::id(&id)
            ));
        }
        for url in urls {
            let fetched = crate::fetch::get(&url).and_then(|bytes| {
                Item::decode_bundle(&bytes).map_err(|e| format!("not a bundle: {e}"))
            });
            // Only this identity's own log and records are taken: a host, or
            // whoever can impersonate one (TLS is not relied on), must not be
            // able to put anything else into the material.
            let added = fetched.map(|items| {
                let total = items.len();
                let mut taken = 0;
                for item in items {
                    let ours = match &item {
                        Item::Record(r) => r.body.id == id,
                        Item::Event(e) => e.body.id() == id,
                        _ => false,
                    };
                    if ours {
                        self.material.add(item);
                        taken += 1;
                    }
                }
                if taken < total {
                    crate::note(format!(
                        "{url}: ignored {} item{} that are not the log or records of {}",
                        total - taken,
                        plural(total - taken),
                        display::id(&id)
                    ));
                }
            });
            match added {
                Ok(()) if self.verifier().has_fresh_record(&id, self.now) => {
                    crate::note(format!("fetched {url}"));
                    return;
                }
                Ok(()) => crate::warn(format!("{url}: no fresh record there")),
                Err(e) => crate::warn(format!("{url}: {e}")),
            }
        }
    }

    /// The newest valid record of each local root the proof relies on.
    /// Local roots need no record here, but whoever receives the proof does.
    fn local_records(&self, proof: &libwrit::Proof) -> Vec<Item> {
        let verifier = self.verifier();
        self.local
            .iter()
            .filter(|id| proof.ids.contains(id))
            .filter_map(|id| {
                self.material
                    .records_by(id)
                    .iter()
                    .filter(|h| verifier.record_status(h, self.now).is_ok())
                    .filter_map(|h| Some((*h, self.material.record(h)?.body.issued)))
                    .max_by_key(|(_, issued)| *issued)
                    .filter(|(h, _)| !proof.records.contains(h))
                    .and_then(|(h, _)| self.material.shippable_record(&h))
            })
            .collect()
    }

    /// Warns about records an answer relied on that will soon be too old,
    /// so a stopped publishing job is noticed before it causes refusals.
    fn warn_stale(&self, proof: &libwrit::Proof) {
        for h in &proof.records {
            let Some(r) = self.material.record(h) else {
                continue;
            };
            let id = r.body.id;
            let Some(max_age) = self
                .material
                .log(&id)
                .as_ref()
                .as_ref()
                .ok()
                .and_then(|log| log.head().publish().map(libwrit::Publish::max_age))
            else {
                continue;
            };
            let age = self.now.saturating_sub(r.body.issued);
            if age.saturating_mul(5) >= max_age.saturating_mul(4) {
                crate::warn(format!(
                    "the newest revocation record from {} is {} old; statements that \
                     need it stop counting in {}",
                    display::id(&id),
                    Duration(age),
                    Duration(max_age.saturating_sub(age))
                ));
            }
        }
    }

    fn deny(&self, parsed: &Parsed, headline: String, d: &Denial) -> Error {
        if !parsed.flag("quiet") {
            crate::stderr(format!(
                "{} {headline}: {}",
                style::paint(Stream::Err, style::BAD, "denied:"),
                display::denial(d, &self.material, self.fetch)
            ));
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

pub fn check(parsed: &Parsed) -> Result<()> {
    let [subject_text, tag_text] = parsed.exact(&CHECK, ["SUBJECT", "TAG"])?;
    require_as(parsed, &CHECK)?;
    let holder = subject::holder(subject_text)?;
    let tag = subject::tag(tag_text)?;
    let mut q = Query::setup(parsed, &CHECK, true)?;
    let now = q.now;
    let result = q.ask(None, |v| v.check(&holder, &tag, now));
    match result {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied())?;
            if !parsed.flag("quiet") {
                q.warn_stale(&proof);
            }
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
            q.persist(denial_ids(&d, &q.material))?;
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
    let mut q = Query::setup(parsed, &PROVE, true)?;
    let now = q.now;
    match q.ask(None, |v| v.check(&holder, &tag, now)) {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied())?;
            if !parsed.flag("quiet") {
                q.warn_stale(&proof);
            }
            let mut items = proof.items(&q.material);
            items.extend(q.local_records(&proof));
            fs::print(&items.iter().map(Item::armor).collect::<String>())?;
            if !parsed.flag("quiet") {
                crate::stderr_line(format!(
                    "proof: {} log event{} and {} statement{}",
                    items.iter().filter(|i| matches!(i, Item::Event(_))).count(),
                    plural(items.iter().filter(|i| matches!(i, Item::Event(_))).count()),
                    proof.statements().len(),
                    plural(proof.statements().len())
                ));
            }
            Ok(())
        }
        Err(d) => {
            q.persist(denial_ids(&d, &q.material))?;
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
    let mut q = Query::setup(parsed, &RESOLVE, true)?;
    let path = subject::name_path(path_text, q.roots.first().copied())?;
    let now = q.now;
    match q.ask(None, |v| v.resolve(&path, now)) {
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
            q.persist(denial_ids(&d, &q.material))?;
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
    let mut q = Query::setup(
        parsed,
        &VERIFY,
        !fs::is_stdin(file) && !fs::is_stdin(sig_path),
    )?;
    let signer = match &sig.body.signer {
        libwrit::Issuer::Identity { id, .. } => display::id(id),
        libwrit::Issuer::Leaf(k) => format!("leaf:{}", k.fingerprint()),
    };
    let now = q.now;
    let signer_holds = sig.body.signer.id().map(|id| (Holder::Id(id), tag.clone()));
    match q.ask(signer_holds, |v| {
        v.verify(&sig, &hash, context.as_bytes(), &tag, now)
    }) {
        Ok(proof) => {
            q.persist(proof.ids.iter().copied())?;
            if !parsed.flag("quiet") {
                q.warn_stale(&proof);
            }
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
            q.persist(denial_ids(&d, &q.material))?;
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
        let name = if fs::is_stdin(f) { "stdin" } else { f.as_str() };
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
