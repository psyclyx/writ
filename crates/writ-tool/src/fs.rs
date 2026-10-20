//! Files: secret keys (never overwritten, mode 0600, `-` for stdio, any
//! readable path including `/dev/fd/N`), public state (atomic replace or
//! append), and bundles.

use crate::error::{Context, Result, err};
use libwrit::Zeroizing;
use libwrit::{Item, Seed};
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

thread_local! {
    static STDIN_USED: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Claims stdin for one purpose; a second claim is an error.
pub fn claim_stdin(purpose: &'static str) -> Result<()> {
    match STDIN_USED.get() {
        Some(prev) => err(format!(
            "standard input can be read only once: it is already used for {prev}, so it can't also give {purpose}"
        )),
        None => {
            STDIN_USED.set(Some(purpose));
            Ok(())
        }
    }
}

/// Whether stdin is still unclaimed and is a file (`< bundle`) or a pipe.
/// Terminals, sockets and devices are never read implicitly, so a command
/// run under ssh or a supervisor doesn't wait on an inherited stdin.
pub fn stdin_is_piped() -> bool {
    if STDIN_USED.get().is_some() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        use std::os::unix::fs::FileTypeExt;
        let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() else {
            return false;
        };
        File::from(fd)
            .metadata()
            .is_ok_and(|m| m.is_file() || m.file_type().is_fifo())
    }
    #[cfg(not(unix))]
    {
        use std::io::IsTerminal;
        !std::io::stdin().is_terminal()
    }
}

/// Hashes an input as signed data, in constant memory: `-` is stdin.
pub fn hash_input(path: &str, purpose: &'static str) -> Result<libwrit::Hash> {
    let mut hasher = libwrit::DataHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut feed = |r: &mut dyn Read| -> std::io::Result<()> {
        loop {
            match r.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => hasher.update(buf.get(..n).unwrap_or_default()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    };
    if is_stdin(path) {
        claim_stdin(purpose)?;
        feed(&mut std::io::stdin().lock()).context(|| "reading stdin".into())?;
    } else {
        File::open(path)
            .and_then(|mut f| feed(&mut f))
            .context(|| format!("reading {path}"))?;
    }
    Ok(hasher.finish())
}

/// The most read from a key file: one short line per key, plus comments.
const MAX_KEY_FILE: usize = 64 << 10;

/// Reads a whole input, at most a bundle's limit (SPEC §3.1): `-` is stdin.
pub fn read_input(path: &str, purpose: &'static str) -> Result<Vec<u8>> {
    read_limited(path, purpose, libwrit::model::MAX_BUNDLE)
}

fn read_limited(path: &str, purpose: &'static str, limit: usize) -> Result<Vec<u8>> {
    // Room for a whole key file up front, so reading one never reallocates
    // and leaves copies of the key behind.
    let mut buf = Vec::with_capacity(MAX_KEY_FILE + 1);
    let take = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    if is_stdin(path) {
        claim_stdin(purpose)?;
        std::io::stdin()
            .lock()
            .take(take)
            .read_to_end(&mut buf)
            .context(|| "reading stdin".into())?;
    } else {
        File::open(path)
            .and_then(|f| f.take(take).read_to_end(&mut buf))
            .context(|| format!("reading {path}"))?;
    }
    if buf.len() > limit {
        let name = if is_stdin(path) {
            "standard input"
        } else {
            path
        };
        let size = if limit >= 1 << 20 {
            format!("{} MiB", limit >> 20)
        } else {
            format!("{} KiB", limit >> 10)
        };
        return err(format!(
            "{name} is too large for {purpose}: the limit is {size}"
        ));
    }
    Ok(buf)
}

/// Reads secret seeds: one `WRIT-SECRET-KEY-1…` per line; blank lines and
/// `#` comments are ignored.
pub fn read_seeds(path: &str) -> Result<Vec<Seed>> {
    let bytes = Zeroizing::new(read_limited(path, "a key", MAX_KEY_FILE)?);
    let text = std::str::from_utf8(&bytes)
        .ok()
        .map(|s| Zeroizing::new(s.to_owned()))
        .ok_or_else(|| crate::error::Error::Msg(format!("{path}: not a writ secret key file")))?;
    let mut seeds = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match Seed::parse(line) {
            Some(s) => seeds.push(s),
            None => {
                return err(format!(
                    "{path}:{}: not a writ secret key (expected WRIT-SECRET-KEY-1…)",
                    i + 1
                ));
            }
        }
    }
    if seeds.is_empty() {
        return err(format!("{path}: no secret keys in file"));
    }
    Ok(seeds)
}

/// The descriptor number `path` names, if it is exactly `/dev/fd/N` or
/// `/proc/self/fd/N`: decimal digits, no leading zero, nothing after.
/// Anything else under those directories, such as `/dev/fd/../x`, is an
/// ordinary path and gets the ordinary rules (never overwrite, mode 0600,
/// not inside an identity directory).
fn descriptor_number(path: &str) -> Option<u32> {
    let n = path
        .strip_prefix("/dev/fd/")
        .or_else(|| path.strip_prefix("/proc/self/fd/"))?;
    let canonical = n == "0" || (!n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()));
    if !canonical || n.len() > 9 {
        return None;
    }
    n.parse().ok()
}

/// Whether `path` names standard input.
pub fn is_stdin(path: &str) -> bool {
    path == "-" || path == "/dev/stdin" || descriptor_number(path) == Some(0)
}

/// Whether `path` names standard output.
pub fn is_stdout(path: &str) -> bool {
    path == "-" || path == "/dev/stdout" || descriptor_number(path) == Some(1)
}

/// Whether two output paths name the same destination.
pub fn same_output(a: &str, b: &str) -> bool {
    a == b || (is_stdout(a) && is_stdout(b))
}

/// Whether `path` names a descriptor the caller handed us, other than
/// stdout (`/dev/fd/N`, e.g. from process substitution).
pub fn is_descriptor(path: &str) -> bool {
    path == "/dev/stderr" || descriptor_number(path).is_some_and(|n| n >= 2)
}

/// Fails early, before any signing, if `write_secret(path, …)` would refuse.
pub fn check_secret_target(path: &str) -> Result<()> {
    if is_stdout(path) || is_descriptor(path) {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => exists_error(path, true),
        Err(_) => Ok(()),
    }
}

fn exists_error<T>(path: &str, secret: bool) -> Result<T> {
    let what = if secret { "a key file" } else { "a file" };
    err(format!(
        "{path} already exists, and writ never overwrites {what}; choose another path, or '-' for standard output"
    ))
}

/// Writes secret key text to a new [`Output`] with mode 0600.
pub fn write_secret(path: &str, text: &str) -> Result<()> {
    Output::open(path, true)?.write(text)
}

/// A destination for one write. `-` and `/dev/stdout` are standard output.
/// `/dev/fd/N` is a descriptor the caller opened; writ opens it again for
/// appending, so output given to `>>` or a pipe lands after what is already
/// there. Anything else must not exist yet and is created: existing files,
/// FIFOs and symlinks are refused, so output can't be steered into
/// something an attacker prepared.
///
/// Open outputs before doing anything that can't be undone: a file that was
/// created but never written is removed again.
pub struct Output {
    path: String,
    dest: Dest,
}

enum Dest {
    Stdout,
    Descriptor(File),
    /// A file this command created; `None` once written.
    Created(Option<File>),
}

impl Output {
    /// Opens `path`; a created file gets mode 0600 if `secret`.
    pub fn open(path: &str, secret: bool) -> Result<Output> {
        let dest = if is_stdout(path) {
            Dest::Stdout
        } else if is_descriptor(path) {
            let f = OpenOptions::new()
                .append(true)
                .open(path)
                .context(|| format!("opening {path}"))?;
            Dest::Descriptor(f)
        } else {
            let mut options = OpenOptions::new();
            // O_CREAT|O_EXCL: this also refuses a symlink, even a dangling
            // one, as the last component.
            options.write(true).create_new(true);
            #[cfg(unix)]
            if secret {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(f) => Dest::Created(Some(f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return exists_error(path, secret);
                }
                Err(e) => return err(format!("creating {path}: {e}")),
            }
        };
        Ok(Output {
            path: path.to_owned(),
            dest,
        })
    }

    /// Writes all of `text` and closes the output.
    pub fn write(mut self, text: &str) -> Result<()> {
        let path = &self.path;
        match &mut self.dest {
            Dest::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(text.as_bytes())
                    .and_then(|()| out.flush())
                    .context(|| "writing to stdout".into())
            }
            Dest::Descriptor(f) => f
                .write_all(text.as_bytes())
                .context(|| format!("writing {path}")),
            Dest::Created(slot) => {
                if let Some(f) = slot {
                    f.write_all(text.as_bytes())
                        .and_then(|()| f.sync_all())
                        .context(|| format!("writing {path}"))?;
                }
                *slot = None;
                sync_parent(Path::new(path))
            }
        }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if let Dest::Created(Some(_)) = self.dest {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Seeds as key-file text: a `# writ …` line saying what they are, then one
/// seed per line.
pub fn seeds_text(comment: &str, seeds: &[Seed]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(format!("# writ {comment}\n"));
    for seed in seeds {
        s.push_str(&seed.to_text());
        s.push('\n');
    }
    s
}

/// Replaces a public file atomically and durably: write a new temporary
/// file beside it, rename it into place, then sync the directory.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let (tmp, mut f) = create_tmp(path)?;
    let replaced = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = replaced {
        let _ = std::fs::remove_file(&tmp);
        return err(format!("replacing {}: {e}", path.display()));
    }
    sync_parent(path)
}

/// Creates a temporary file beside `path`, named after it, the process id
/// and a counter. Never opens an existing file or follows a symlink.
fn create_tmp(path: &Path) -> Result<(PathBuf, File)> {
    let name = path.file_name().unwrap_or_default();
    for n in 0..1000 {
        let mut tmp = name.to_os_string();
        tmp.push(format!(".tmp{}.{n}", std::process::id()));
        let tmp = path.with_file_name(tmp);
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return err(format!("creating {}: {e}", tmp.display())),
        }
    }
    err(format!(
        "creating a temporary file beside {}: too many already exist",
        path.display()
    ))
}

/// Syncs the directory holding `path`, so that a file created or renamed
/// there survives a crash.
pub fn sync_parent(path: &Path) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .context(|| format!("syncing {}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Appends armored items to a public file. Atomic: the file is rewritten
/// and renamed into place, so a crash leaves either the old or the new
/// contents, never a torn block.
pub fn append_items(path: &Path, items: &[Item]) -> Result<()> {
    let mut bytes = match read_file_bounded(path) {
        Ok(Some(b)) => b,
        Ok(None) => Vec::new(),
        Err(e) => return Err(e),
    };
    for item in items {
        bytes.extend_from_slice(item.armor().as_bytes());
    }
    replace(path, &bytes)
}

/// Reads one of writ's own files whole, up to a bundle's limit (SPEC §3.1):
/// `None` if it does not exist. Even a local file is read with a bound.
fn read_file_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    let limit = libwrit::model::MAX_BUNDLE;
    let mut buf = Vec::new();
    let read = File::open(path).and_then(|f| {
        f.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut buf)
    });
    match read {
        Ok(_) if buf.len() > limit => err(format!(
            "{} is larger than {} MiB, the most writ reads",
            path.display(),
            limit >> 20
        )),
        Ok(_) => Ok(Some(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => err(format!("reading {}: {e}", path.display())),
    }
}

/// Takes the lock file `DIR/.lock`, shared or exclusive, for as long as the
/// returned handle lives.
pub fn lock_dir(dir: &Path, exclusive: bool) -> Result<File> {
    lock_file(&dir.join(".lock"), exclusive)
}

/// Takes a lock file, creating it if needed, for as long as the returned
/// handle lives.
pub fn lock_file(path: &Path, exclusive: bool) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .context(|| format!("opening {}", path.display()))?;
    if exclusive { f.lock() } else { f.lock_shared() }
        .context(|| format!("locking {}", path.display()))?;
    Ok(f)
}

/// Reads a bundle file; a missing file is an empty bundle.
pub fn read_bundle_file(path: &Path) -> Result<Vec<Item>> {
    match read_file_bounded(path)? {
        Some(bytes) => Item::decode_bundle(&bytes).context(|| path.display().to_string()),
        None => Ok(Vec::new()),
    }
}

/// Writes to stdout.
pub fn print(text: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        // A closed pipe (`writ show | head`) is not an error worth reporting.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => err(format!("writing to stdout: {e}")),
    }
}

/// Prints an armored item to stdout — unless stdout is a terminal and the
/// item is recorded elsewhere: then armor would only be noise.
pub fn emit(item: &Item, recorded_in: Option<&Path>) -> Result<()> {
    use std::io::IsTerminal;
    if let Some(path) = recorded_in
        && std::io::stdout().is_terminal()
    {
        eprintln!(
            "recorded in {}; standard output is a terminal, so the item was not printed",
            path.display()
        );
        return Ok(());
    }
    print(&item.armor())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_paths_are_exact() {
        for p in ["/dev/fd/3", "/proc/self/fd/3", "/dev/fd/10", "/dev/stderr"] {
            assert!(is_descriptor(p), "{p}");
        }
        for p in [
            "/dev/fd/../../../etc/passwd",
            "/proc/self/fd/../x",
            "/dev/fd/",
            "/dev/fd/03",
            "/dev/fd/3x",
            "/dev/fd/-1",
            "/dev/fd/3/",
            "/dev/fd/1234567890",
            "/dev/fd/0",
            "/dev/fd/1",
            "/dev/fdx/3",
        ] {
            assert!(!is_descriptor(p), "{p}");
        }
        for p in ["-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"] {
            assert!(is_stdin(p), "{p}");
            assert!(!is_stdout(p) || p == "-", "{p}");
        }
        for p in ["-", "/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"] {
            assert!(is_stdout(p), "{p}");
        }
        assert!(!is_stdin("/dev/fd/00"));
        assert!(!is_stdout("/dev/fd/01"));
    }

    #[test]
    fn replace_never_reuses_a_planted_temporary_file() {
        let dir = std::env::temp_dir().join(format!("writ-fs-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("issued.writ");
        let pid = std::process::id();
        // Where earlier versions put the temporary file, and the first two
        // names this one tries.
        let elsewhere = dir.join("elsewhere");
        for name in [
            format!("issued.writ.tmp{pid}"),
            format!("issued.writ.tmp{pid}.0"),
        ] {
            std::os::unix::fs::symlink(&elsewhere, dir.join(name)).unwrap();
        }
        std::fs::write(dir.join(format!("issued.writ.tmp{pid}.1")), "planted").unwrap();
        replace(&file, b"new").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        assert!(!elsewhere.exists());
        let planted = std::fs::read(dir.join(format!("issued.writ.tmp{pid}.1"))).unwrap();
        assert_eq!(planted, b"planted");
        assert!(!dir.join(format!("issued.writ.tmp{pid}.2")).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
