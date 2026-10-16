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
        let issued = fs::read_bundle_file(&path.join(ISSUED))?;
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
                    "the key in {path} is no longer a current key: rotation {} replaced it. \
                     After a rotation, sign with the next key you gave to 'writ rotate'",
                    n + 1
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
        let lock = fs::lock_dir(&path, true);
        let empty = std::fs::read_dir(&path).map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .all(|e| e.file_name() == ".lock")
        });
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
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context(|| format!("{path}: directory {}", parent.display()))?;
    let Ok(dir_real) = dir.canonicalize() else {
        return Ok(());
    };
    if parent == dir_real && !(current && p.file_name() == Some(CURRENT_KEY.as_ref())) {
        return err(format!(
            "{path} is inside {}, where writ keeps the identity's own files; \
             choose a path outside it",
            dir.display()
        ));
    }
    Ok(())
}

/// `writ rotate` writes the new current key to `DIR/current.key.new` before
/// the log commits to it, and renames it over `DIR/current.key` after. If a
/// run stopped in between, finish its work: install the staged key if the
/// log uses it, or remove it if the rotation never happened.
fn finish_key_install(dir: &Path, log: &Log) -> Result<()> {
    let staged = dir.join(format!("{CURRENT_KEY}.new"));
    if !staged.is_file() {
        return Ok(());
    }
    let staged_str = staged.display().to_string();
    let seeds = fs::read_seeds(&staged_str)?;
    let committed = seeds.iter().all(|s| {
        log.head()
            .authority()
            .index_of(&s.root().root_key())
            .is_some()
    });
    if committed {
        std::fs::rename(&staged, dir.join(CURRENT_KEY))
            .context(|| format!("installing {staged_str}"))?;
        crate::note(format!(
            "finished an interrupted rotation: {} now holds the current key",
            dir.join(CURRENT_KEY).display()
        ));
    } else {
        std::fs::remove_file(&staged).context(|| format!("removing {staged_str}"))?;
    }
    Ok(())
}
