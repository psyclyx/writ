//! An identity directory: public state plus (usually) the warm key.
//!
//! ```text
//! DIR/log.writ       the identity log (inception, rotations)
//! DIR/issued.writ    everything this identity issued: statements, revocations, signatures
//! DIR/next.writ      every next authority the log has committed to (public, append-only)
//! DIR/current.key    the warm secret key (mode 0600), unless kept elsewhere
//! ```

use crate::error::{Context, Error, Result, err};
use crate::fs;
use libwrit::keys::RootSigner;
use libwrit::{Authority, Event, Id, Item, Log, Material};
use std::path::{Path, PathBuf};

pub const LOG: &str = "log.writ";
pub const ISSUED: &str = "issued.writ";
pub const NEXT: &str = "next.writ";
pub const CURRENT_KEY: &str = "current.key";
/// The log and the newest revocation record: the file to publish (DESIGN.md §18.7).
pub const RECORD: &str = "record.writ";

pub struct IdentityDir {
    pub dir: PathBuf,
    pub log: Log,
    pub issued: Vec<Item>,
    /// Held while issuing (shared) or rotating (exclusive), so a statement
    /// is never signed under an event that a concurrent rotation is retiring.
    _lock: Option<std::fs::File>,
}

/// Whether `path` is an identity directory.
pub fn is_identity_dir(path: &Path) -> bool {
    path.join(LOG).is_file()
}

impl IdentityDir {
    /// Opens an identity for reading.
    pub fn open(dir: &str) -> Result<IdentityDir> {
        IdentityDir::open_with(dir, None)
    }

    /// Opens an identity for issuing (`exclusive = false`) or rotating.
    pub fn open_locked(dir: &str, exclusive: bool) -> Result<IdentityDir> {
        IdentityDir::open_with(dir, Some(exclusive))
    }

    fn open_with(dir: &str, lock: Option<bool>) -> Result<IdentityDir> {
        let path = PathBuf::from(dir);
        if !is_identity_dir(&path) {
            return err(format!(
                "{dir} is not a writ identity: it has no {LOG}. Create one with 'writ init {dir}'"
            ));
        }
        let lock = lock
            .map(|exclusive| fs::lock_dir(&path, exclusive))
            .transpose()?;
        let events = fs::read_bundle_file(&path.join(LOG))?;
        let mut material = Material::new();
        let mut inception = None;
        for item in events {
            match &item {
                Item::Event(e) if matches!(e.body, Event::Inception(_)) => {
                    inception = Some(e.body.id());
                }
                Item::Event(_) => {}
                _ => return err(format!("{dir}/{LOG}: contains a {}", item.kind())),
            }
            material.add(item);
        }
        let id = inception.ok_or_else(|| Error::Msg(format!("{dir}/{LOG}: no inception")))?;
        let log = match &*material.log(&id) {
            Ok(log) => log.clone(),
            Err(e) => return err(format!("{dir}/{LOG}: {e}")),
        };
        if lock.is_some() {
            finish_key_install(&path, &log)?;
        }
        // issued.writ holds what this identity issued, and is not trusted:
        // anything else in it is left out of every use (keep, records,
        // export, revocation lookup), and reported.
        let (issued, foreign): (Vec<Item>, Vec<Item>) = fs::read_bundle_file(&path.join(ISSUED))?
            .into_iter()
            .partition(|item| match item {
                Item::Statement(s) => s.body.issuer.id() == Some(id),
                Item::Signature(s) => s.body.signer.id() == Some(id),
                _ => false,
            });
        if !foreign.is_empty() {
            crate::warn(format!(
                "{dir}/{ISSUED} holds {} item{} that {dir} did not issue; they are ignored. \
                 Read the file: someone else may have written to it",
                foreign.len(),
                if foreign.len() == 1 { "" } else { "s" }
            ));
        }
        crate::display::label(id, dir);
        Ok(IdentityDir {
            dir: path,
            log,
            issued,
            _lock: lock,
        })
    }

    pub fn id(&self) -> Id {
        self.log.id()
    }

    pub fn name(&self) -> String {
        self.dir.display().to_string()
    }

    /// The log and everything issued, as material.
    pub fn material(&self) -> Material {
        Material::from_items(self.log.items().chain(self.issued.iter().cloned()))
    }

    /// Signers for the current authority, from `--key` paths or
    /// `DIR/current.key`.
    pub fn signers(&self, key_paths: &[String]) -> Result<Vec<RootSigner>> {
        let default = self.dir.join(CURRENT_KEY);
        let paths: Vec<String> = if key_paths.is_empty() {
            if !default.exists() {
                return err(format!(
                    "no key given, and {} does not exist; give the key with --key PATH",
                    default.display()
                ));
            }
            vec![default.display().to_string()]
        } else {
            key_paths.to_vec()
        };
        let authority = self.log.head().authority();
        let mut signers = Vec::new();
        let mut strangers = Vec::new();
        for path in &paths {
            for seed in fs::read_seeds(path)? {
                let signer = seed.root();
                if authority.index_of(&signer.root_key()).is_some() {
                    if !signers
                        .iter()
                        .any(|s: &RootSigner| s.root_key() == signer.root_key())
                    {
                        signers.push(signer);
                    }
                } else {
                    strangers.push((path.clone(), signer.root_key()));
                }
            }
        }
        if signers.is_empty() {
            let (path, key) = strangers
                .first()
                .cloned()
                .unwrap_or_else(|| (paths.join(", "), libwrit::RootKey([0; 32])));
            let retired = (0..self.log.head_n()).find(|n| {
                self.log
                    .event(*n)
                    .is_some_and(|e| e.authority().index_of(&key).is_some())
            });
            return match retired {
                Some(n) => err(format!(
                    "the key in {path} is no longer a current key: rotation {} replaced it \
                     with the key 'writ rotate' wrote to --key-out (or to {}/{CURRENT_KEY}). \
                     Sign with that one; the next key only rotates",
                    n + 1,
                    self.name()
                )),
                None => err(format!(
                    "the key in {path} is not a current key of {}",
                    self.name()
                )),
            };
        }
        let k = authority.k();
        if signers.len() < k {
            return err(format!(
                "{} needs {k} of its {} keys to sign, but {} were given",
                self.name(),
                authority.keys().len(),
                signers.len()
            ));
        }
        Ok(signers)
    }

    /// The pending next authority, checked against the log's commitment.
    pub fn next_authority(&self) -> Result<Authority> {
        let path = self.dir.join(NEXT);
        let items = fs::read_bundle_file(&path)?;
        if items.is_empty() {
            return err(format!(
                "{} is missing; rotation needs the public next keys it holds",
                path.display()
            ));
        }
        // Append-only: every authority this identity ever committed to. The
        // pending one is whichever the log's head commits to.
        let committed = *self.log.head().next();
        items
            .into_iter()
            .find_map(|i| match i {
                Item::Authority(a) if a.hash() == committed => Some(a),
                _ => None,
            })
            .ok_or_else(|| {
                Error::Msg(format!(
                    "{}: none of these next keys match the identity log",
                    path.display()
                ))
            })
    }

    /// Appends items to the issuance log.
    pub fn record(&mut self, items: &[Item]) -> Result<()> {
        // Issuers share DIR/.lock, so several can get here at once; the
        // read, append and rename of issued.writ needs a lock of its own.
        let _recording = fs::lock_file(&self.dir.join(".issued.lock"), true)?;
        fs::append_items(&self.dir.join(ISSUED), items)?;
        self.issued.extend(items.iter().cloned());
        Ok(())
    }
}

/// The directory of an identity that `writ init` is making: it did not
/// exist or was empty, and it stays locked, so a concurrent init of the
/// same directory waits and then finds it taken.
pub struct NewDir {
    pub path: PathBuf,
    /// Whether this process created the directory.
    created: bool,
    _lock: std::fs::File,
}

impl NewDir {
    pub fn create(dir: &str) -> Result<NewDir> {
        let path = PathBuf::from(dir);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).context(|| format!("creating {dir}"))?;
        }
        let created = match std::fs::create_dir(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return err(format!("creating {dir}: {e}")),
        };
        let is_empty = || {
            std::fs::read_dir(&path).map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .all(|e| e.file_name() == ".lock")
            })
        };
        // A directory that is plainly taken is refused before the lock file
        // is created in it; the lock then guards the final check.
        if !created && let Ok(false) = is_empty() {
            return err(format!("{dir} already exists and is not empty"));
        }
        let lock = fs::lock_dir(&path, true);
        let empty = is_empty();
        match (lock, empty) {
            (Ok(lock), Ok(true)) => Ok(NewDir {
                path,
                created,
                _lock: lock,
            }),
            (Err(e), _) => Err(e),
            (_, Ok(false)) => err(format!("{dir} already exists and is not empty")),
            (_, Err(e)) => err(format!("{dir}: {e}")),
        }
    }

    /// Removes what init wrote, after a failure. Key files stay: writ never
    /// deletes a key.
    pub fn abandon(self) {
        for f in [LOG, ISSUED, NEXT] {
            let _ = std::fs::remove_file(self.path.join(f));
        }
        if self.created {
            let _ = std::fs::remove_file(self.path.join(".lock"));
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

/// Refuses a path for a secret key inside identity directory `dir`, where
/// writ keeps its own files, except `DIR/current.key` if `current`. Checked
/// before anything is written: a key written there could be replaced by,
/// or replace, the identity's state.
pub fn check_key_path(dir: &Path, path: &str, current: bool) -> Result<()> {
    if fs::is_stdout(path) || fs::is_descriptor(path) {
        return Ok(());
    }
    let p = Path::new(path);
    let parent = real_parent(path)?;
    if let Ok(dir_real) = dir.canonicalize()
        && parent == dir_real
    {
        if current && p.file_name() == Some(CURRENT_KEY.as_ref()) {
            return Ok(());
        }
        return err(format!(
            "{path} is inside {}, where writ keeps the identity's own files; \
             choose a path outside it",
            dir.display()
        ));
    }
    check_output_path(path)
}

/// Refuses an output path inside any identity directory, for commands that
/// have no identity of their own (`keygen`, `sign --leaf`): a file there
/// could be taken for one of the identity's, or replaced by one. `init`
/// checks its own directory separately, since it has no log yet.
pub fn check_output_path(path: &str) -> Result<()> {
    if fs::is_stdout(path) || fs::is_descriptor(path) {
        return Ok(());
    }
    let parent = real_parent(path)?;
    if is_identity_dir(&parent) {
        return err(format!(
            "{path} is inside {}, a writ identity directory; choose a path outside it",
            parent.display()
        ));
    }
    Ok(())
}

/// The canonical directory `path` would be created in.
fn real_parent(path: &str) -> Result<PathBuf> {
    let parent = Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    parent
        .canonicalize()
        .context(|| format!("{path}: directory {}", parent.display()))
}

/// `writ rotate` writes the new current key to `DIR/current.key.new` before
/// the log commits to it, and renames it over `DIR/current.key` after. If a
/// run stopped in between, finish its work: install the staged key if the
/// log uses it, or remove it if the rotation never happened.
fn finish_key_install(dir: &Path, log: &Log) -> Result<()> {
    let staged = dir.join(format!("{CURRENT_KEY}.new"));
    let Ok(meta) = std::fs::symlink_metadata(&staged) else {
        return Ok(());
    };
    let staged_str = staged.display().to_string();
    // Only a key file rotate staged is finished or removed: anything else
    // there is left alone and named, so a key or file put there by other
    // means is never deleted or installed.
    if !meta.is_file() {
        return err(format!(
            "{staged_str} is not a regular file. writ rotate stages the new current key \
             there; move this out of the way"
        ));
    }
    let seeds = fs::read_seeds(&staged_str).map_err(|e| {
        e.with_note(format!(
            "{staged_str} is where writ rotate stages the new current key, and it does not \
             hold one; move this file out of the way"
        ))
    })?;
    let committed = seeds.iter().all(|s| {
        log.head()
            .authority()
            .index_of(&s.root().root_key())
            .is_some()
    });
    if committed {
        let target = dir.join(CURRENT_KEY);
        if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
            return err(format!(
                "{} is a symbolic link; writ does not replace links. Move it away, then \
                 run the command again to install the staged key {staged_str}",
                target.display()
            ));
        }
        std::fs::rename(&staged, &target).context(|| format!("installing {staged_str}"))?;
        fs::sync_parent(&staged)?;
        crate::note(format!(
            "finished an interrupted rotation: {} now holds the current key",
            dir.join(CURRENT_KEY).display()
        ));
    } else {
        std::fs::remove_file(&staged).context(|| format!("removing {staged_str}"))?;
    }
    Ok(())
}
