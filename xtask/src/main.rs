//! Development tasks, run as `cargo xtask TASK` (the alias is in
//! `.cargo/config.toml`):
//!
//! - `vectors`: write the published test vectors under `vectors/`.
//! - `man`: write the man pages under `doc/man/`.
//!
//! The tests below check that the committed files are what these tasks
//! write, so `cargo nextest run --workspace` catches a stale file.

mod vectors;

use std::path::PathBuf;
use std::process::ExitCode;

/// Generated files: (path from the repository root, contents).
type Files = Vec<(String, String)>;

const USAGE: &str = "usage: cargo xtask TASK

tasks:
  vectors  write the test vectors under vectors/
  man      write the man pages under doc/man/
";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn man_pages() -> Files {
    writ_tool::man::pages()
        .into_iter()
        .map(|(name, page)| (format!("doc/man/{name}"), page))
        .collect()
}

/// Man pages in `doc/man/` that no command generates any more.
fn stale_man_pages(files: &Files) -> std::io::Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(root().join("doc/man"))? {
        let path = entry?.path();
        let rel = path
            .file_name()
            .map(|n| format!("doc/man/{}", n.to_string_lossy()));
        if path.extension().is_some_and(|e| e == "1")
            && !files.iter().any(|(f, _)| Some(f) == rel.as_ref())
        {
            stale.push(path);
        }
    }
    Ok(stale)
}

fn write(files: &Files) -> std::io::Result<()> {
    for (rel, text) in files {
        let path = root().join(rel);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, text)?;
        println!("wrote {rel}");
    }
    Ok(())
}

fn run(task: &str) -> std::io::Result<bool> {
    match task {
        "vectors" => write(&vectors::generate())?,
        "man" => {
            let pages = man_pages();
            write(&pages)?;
            for path in stale_man_pages(&pages)? {
                std::fs::remove_file(&path)?;
                println!("removed {}", path.display());
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [task] = args.as_slice() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(task) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprint!("xtask: unknown task '{task}'\n{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("xtask {task}: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn check(task: &str, files: &Files) {
        for (rel, text) in files {
            let on_disk = std::fs::read_to_string(root().join(rel)).unwrap_or_default();
            assert!(
                on_disk == *text,
                "{rel} is not what `cargo xtask {task}` writes; run it and commit the result"
            );
        }
    }

    #[test]
    fn vectors_are_current() {
        check("vectors", &vectors::generate());
    }

    #[test]
    fn man_pages_are_current() {
        let pages = man_pages();
        check("man", &pages);
        let stale = stale_man_pages(&pages).unwrap();
        assert!(
            stale.is_empty(),
            "{stale:?}: no command makes these; run `cargo xtask man`"
        );
    }
}
