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
            "stdin can only be read once (already used for {prev}, now wanted for {purpose})"
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

/// Reads a whole input: `-` is stdin.
pub fn read_input(path: &str, purpose: &'static str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if path == "-" {
        claim_stdin(purpose)?;
        std::io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .context(|| "reading stdin".into())?;
    } else {
        File::open(path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .context(|| format!("reading {path}"))?;
    }
    Ok(buf)
}

/// Reads secret seeds: one `WRIT-SECRET-KEY-1…` per line; blank lines and
/// `#` comments are ignored.
pub fn read_seeds(path: &str) -> Result<Vec<Seed>> {
    let bytes = Zeroizing::new(read_input(path, "a key")?);
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

/// Whether `path` names a descriptor the caller handed us (`/dev/fd/N`,
/// e.g. from process substitution, or `/dev/stdout`).
fn is_descriptor(path: &str) -> bool {
    path.starts_with("/dev/fd/")
        || path.starts_with("/proc/self/fd/")
        || matches!(path, "/dev/stdout" | "/dev/stderr")
}

/// Fails early, before any signing, if `write_secret(path, …)` would refuse.
pub fn check_secret_target(path: &str) -> Result<()> {
    if path == "-" || is_descriptor(path) {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => err(format!(
            "{path} already exists; writ never overwrites a key (use '-' or /dev/fd/N for a stream)"
        )),
        Err(_) => Ok(()),
    }
}

/// Writes secret key text. `-` is stdout and `/dev/fd/N` is a descriptor
/// the caller opened; anything else must not exist yet, and is created
/// with mode 0600. Existing files, FIFOs and symlinks are refused, so a key
/// can't be steered into something an attacker prepared.
pub fn write_secret(path: &str, text: &str) -> Result<()> {
    if path == "-" {
        let mut out = std::io::stdout().lock();
        return out
            .write_all(text.as_bytes())
            .and_then(|()| out.flush())
            .context(|| "writing to stdout".into());
    }
    let mut file = if is_descriptor(path) {
        OpenOptions::new()
            .write(true)
            .open(path)
            .context(|| format!("opening {path}"))?
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return check_secret_target(path);
            }
            Err(e) => return err(format!("creating {path}: {e}")),
        }
    };
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all().or(Ok(())))
        .context(|| format!("writing {path}"))
}

/// Replaces a secret key file atomically with new contents (mode 0600):
/// used only to install a rotation's revealed key over the retired one.
pub fn replace_secret(path: &Path, text: &str) -> Result<()> {
    let tmp = tmp_path(path);
    write_secret(&tmp.display().to_string(), text)?;
    std::fs::rename(&tmp, path).context(|| format!("replacing {}", path.display()))
}

/// Seeds as key-file text, one per line.
pub fn seeds_text(seeds: &[Seed]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::new());
    for seed in seeds {
        s.push_str(&seed.to_text());
        s.push('\n');
    }
    s
}

/// Replaces a public file atomically (write a temporary file, then rename).
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let mut f = File::create(&tmp).context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).context(|| format!("replacing {}", path.display()))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp{}", std::process::id()));
    path.with_file_name(name)
}

/// Appends armored items to a public file. Atomic: the file is rewritten
/// and renamed into place, so a crash leaves either the old or the new
/// contents, never a torn block.
pub fn append_items(path: &Path, items: &[Item]) -> Result<()> {
    let mut bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return err(format!("reading {}: {e}", path.display())),
    };
    for item in items {
        bytes.extend_from_slice(item.armor().as_bytes());
    }
    replace(path, &bytes)
}

/// Takes the lock file `DIR/.lock`, shared or exclusive, for as long as the
/// returned handle lives.
pub fn lock_dir(dir: &Path, exclusive: bool) -> Result<File> {
    let path = dir.join(".lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .context(|| format!("opening {}", path.display()))?;
    if exclusive { f.lock() } else { f.lock_shared() }
        .context(|| format!("locking {}", path.display()))?;
    Ok(f)
}

/// Reads a bundle file; a missing file is an empty bundle.
pub fn read_bundle_file(path: &Path) -> Result<Vec<Item>> {
    match std::fs::read(path) {
        Ok(bytes) => Item::decode_bundle(&bytes).context(|| path.display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => err(format!("reading {}: {e}", path.display())),
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
            "(recorded in {}; redirect stdout to also get the armored item)",
            path.display()
        );
        return Ok(());
    }
    print(&item.armor())
}
