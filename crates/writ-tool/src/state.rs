//! Verifier state (`--state DIR`): the clock floor, and the identity logs,
//! revocations and revocation records this verifier has accepted (DESIGN.md
//! §4.4, §9.4, §18.7).
//!
//! ```text
//! DIR/floor             the clock floor, decimal seconds since the epoch
//! DIR/logs/<id>.writ    the log, revocations and records (the newest, and
//!                       up to 15 older ones that list revocations the rest
//!                       don't) of each identity a question relied on
//! ```
//!
//! Persisted items are added to every query's material, so a verifier never
//! goes back to an older log head (a stale bundle can't undo a rotation), a
//! revocation or fresh record once seen stays seen, and two conflicting events, once seen,
//! stay seen: the identity remains refused until you delete its file.

use crate::error::{Context, Result, err};
use crate::fs;
use libwrit::{Id, Item, Time};
use std::path::PathBuf;

pub struct State {
    dir: PathBuf,
    pub floor: Option<Time>,
    pub logs: Vec<Item>,
    /// Held from open to save, so concurrent verifiers can't roll each
    /// other's floor or logs back.
    _lock: std::fs::File,
}

impl State {
    pub fn open(dir: &str) -> Result<State> {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(dir.join("logs"))
            .context(|| format!("creating {}", dir.display()))?;
        let lock = fs::lock_dir(&dir, true)?;
        let floor = match std::fs::read_to_string(dir.join("floor")) {
            Ok(text) => Some(text.trim().parse().map_err(|_| {
                crate::error::Error::Msg(format!("{}/floor: not a number", dir.display()))
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return err(format!("{}/floor: {e}", dir.display())),
        };
        let mut logs = Vec::new();
        let entries = std::fs::read_dir(dir.join("logs"))
            .context(|| format!("reading {}/logs", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "writ") {
                logs.extend(fs::read_bundle_file(&path)?);
            }
        }
        Ok(State {
            dir,
            floor,
            logs,
            _lock: lock,
        })
    }

    /// Persists the floor, and for each id what to remember about it: its
    /// log (or equivocation evidence) and its revocations.
    pub fn save(
        &self,
        floor: Option<Time>,
        remembered: impl IntoIterator<Item = (Id, Vec<Item>)>,
    ) -> Result<()> {
        if let Some(floor) = floor
            && Some(floor) != self.floor
        {
            fs::replace(&self.dir.join("floor"), format!("{floor}\n").as_bytes())?;
        }
        for (id, items) in remembered {
            let text: String = items.iter().map(Item::armor).collect();
            let path = self.dir.join("logs").join(format!("{id}.writ"));
            let unchanged = std::fs::read(&path).is_ok_and(|old| old == text.as_bytes());
            if !unchanged {
                fs::replace(&path, text.as_bytes())?;
            }
        }
        Ok(())
    }
}
