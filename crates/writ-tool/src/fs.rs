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

/// Whether stdin is still available and not a terminal.
pub fn stdin_is_piped() -> bool {
    use std::io::IsTerminal;
    STDIN_USED.get().is_none() && !std::io::stdin().is_terminal()
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

/// Writes secret key text. `-` is stdout. An existing regular file is never
/// overwritten; an existing non-file (a pipe, `/dev/fd/N`) is written to;
/// a new file is created with mode 0600.
pub fn write_secret(path: &str, text: &str) -> Result<()> {
    if path == "-" {
        let mut out = std::io::stdout().lock();
        return out
            .write_all(text.as_bytes())
            .and_then(|()| out.flush())
            .context(|| "writing to stdout".into());
    }
    let p = Path::new(path);
    let mut file = match std::fs::metadata(p) {
        Ok(m) if m.is_file() => {
            return err(format!(
                "{path} already exists; writ never overwrites a key"
            ));
        }
        Ok(_) => OpenOptions::new()
            .write(true)
            .open(p)
            .context(|| format!("opening {path}"))?,
        Err(_) => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(p).context(|| format!("creating {path}"))?
        }
    };
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all().or(Ok(())))
        .context(|| format!("writing {path}"))
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

/// Appends armored items to a public file in one write.
pub fn append_items(path: &Path, items: &[Item]) -> Result<()> {
    let text: String = items.iter().map(Item::armor).collect();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context(|| format!("opening {}", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .context(|| format!("writing {}", path.display()))
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
