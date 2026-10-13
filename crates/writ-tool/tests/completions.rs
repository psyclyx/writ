//! The completion scripts, exercised in real shells when they are installed
//! (the dev shell has them). Each check is skipped, with a note, otherwise.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn script(shell: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_writ"))
        .args(["completions", shell])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

fn sandbox(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("writ-compl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("me")).unwrap();
    std::fs::create_dir_all(dir.join("other")).unwrap();
    for f in ["bundle.writ", "alice.pub", "me/log.writ"] {
        std::fs::write(dir.join(f), "").unwrap();
    }
    dir
}

fn has(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// (command line, sorted expected completions).
const CASES: &[(&str, &str)] = &[
    ("writ gr", "grant"),
    ("writ --color ", "always auto never"),
    ("writ completions ", "bash fish zsh"),
    ("writ help ch", "check"),
    ("writ grant -i ", "me/ other/"),
    ("writ grant -i me alice.pub ", ""),
    ("writ check --as me a", "alice.pub"),
    ("writ init ", "me/ other/"),
];

fn normalize(words: &str) -> String {
    let mut v: Vec<&str> = words.split_whitespace().collect();
    v.sort_unstable();
    v.join(" ")
}

fn bash_cases(dir: &Path, preamble: &str) {
    let file = dir.join("writ.bash");
    std::fs::write(&file, script("bash")).unwrap();
    let mut prog = format!("{preamble}\nsource {}\n", file.display());
    prog.push_str(
        r#"try() {
    read -ra COMP_WORDS <<< "$1"
    [[ $1 == *' ' ]] && COMP_WORDS+=('')
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); COMP_LINE=$1; COMP_POINT=${#1}
    COMPREPLY=(); _writ
    local w out=()
    for w in "${COMPREPLY[@]}"; do [[ -d $w ]] && w=$w/; out+=("$w"); done
    echo "${out[*]}"
}
"#,
    );
    for (line, _) in CASES {
        prog.push_str(&format!("try '{line}'\n"));
    }
    let out = Command::new("bash")
        .args(["--norc", "-c", &prog])
        .current_dir(dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let got: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        got.len(),
        CASES.len(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for ((line, want), got) in CASES.iter().zip(got) {
        assert_eq!(normalize(got), *want, "bash: {line}");
    }
}

#[test]
fn bash() {
    if !Command::new("bash")
        .args(["-c", "type -t compgen"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "builtin")
    {
        eprintln!("skipping: no interactive bash (with compgen) on PATH");
        return;
    }
    let dir = sandbox("bash");
    bash_cases(&dir, "");
    if let Some(bc) = std::env::var_os("WRIT_TEST_BASH_COMPLETION") {
        bash_cases(&dir, &format!("source {}", Path::new(&bc).display()));
    } else {
        eprintln!("skipping the bash-completion variant: WRIT_TEST_BASH_COMPLETION is not set");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fish() {
    if !has("fish", &["--version"]) {
        eprintln!("skipping: fish not installed");
        return;
    }
    let dir = sandbox("fish");
    let file = dir.join("writ.fish");
    std::fs::write(&file, script("fish")).unwrap();
    let check = Command::new("fish")
        .args(["--no-execute"])
        .arg(&file)
        .status()
        .unwrap();
    assert!(check.success());
    for (line, want) in CASES {
        let out = Command::new("fish")
            .args([
                "--no-config",
                "-c",
                &format!("source {}; complete -C '{line}'", file.display()),
            ])
            .current_dir(&dir)
            .output()
            .unwrap();
        let words: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.split('\t').next().unwrap_or("").to_owned())
            .collect();
        assert_eq!(normalize(&words.join(" ")), *want, "fish: {line}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn zsh() {
    if !has("zsh", &["--version"]) {
        eprintln!("skipping: zsh not installed");
        return;
    }
    let dir = sandbox("zsh");
    let file = dir.join("_writ");
    std::fs::write(&file, script("zsh")).unwrap();
    let out = Command::new("zsh").arg("-n").arg(&file).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Load it the way zsh does, and check the function defines cleanly.
    let out = Command::new("zsh")
        .args([
            "-f",
            "-c",
            &format!(
                "fpath=({} $fpath); autoload -Uz compinit; compinit -u -D; \
                 autoload -Uz _writ; whence -w _writ",
                dir.display()
            ),
        ])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("function"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Loads the zsh script the way users do, in a real interactive zsh, and
/// presses Tab after `writ gr`. Returns whether the line became `writ grant`.
fn zsh_completes(dir: &Path, setup: &str) -> bool {
    let driver = dir.join("drive.zsh");
    std::fs::write(
        &driver,
        format!(
            r#"zmodload zsh/zpty
zpty -b z 'zsh -f -i'
zpty -w z 'PS1="%% "; unsetopt beep; PATH={bin}:$PATH; cd {dir}'
zpty -w z '{setup}'
zpty -w -n z $'writ gr\t'
zpty -r -m z out '*writ grant*' && print COMPLETED
"#,
            bin = Path::new(env!("CARGO_BIN_EXE_writ"))
                .parent()
                .unwrap()
                .display(),
            dir = dir.display(),
        ),
    )
    .unwrap();
    let mut child = Command::new("zsh")
        .arg("-f")
        .arg(&driver)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).contains("COMPLETED")
}

#[test]
fn zsh_loads_every_documented_way() {
    if !has("zsh", &["--version"]) || !has("zsh", &["-fc", "zmodload zsh/zpty"]) {
        eprintln!("skipping: zsh with zpty not installed");
        return;
    }
    let dir = sandbox("zshload");
    let fpath = dir.join("zfunc");
    std::fs::create_dir_all(&fpath).unwrap();
    std::fs::write(fpath.join("_writ"), script("zsh")).unwrap();
    let compinit = "autoload -Uz compinit; compinit -u -D";
    for setup in [
        format!("{compinit}; source <(writ completions zsh)"),
        format!("{compinit}; eval \"$(writ completions zsh)\""),
        format!("fpath=({} $fpath); {compinit}", fpath.display()),
    ] {
        assert!(zsh_completes(&dir, &setup), "zsh: {setup}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bash_and_fish_load_from_a_pipe() {
    let bin = Path::new(env!("CARGO_BIN_EXE_writ"))
        .parent()
        .unwrap()
        .display()
        .to_string();
    let path = format!("{bin}:{}", std::env::var("PATH").unwrap_or_default());
    if Command::new("bash")
        .args(["-c", "type -t compgen"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "builtin")
    {
        for load in [
            "source <(writ completions bash)",
            "eval \"$(writ completions bash)\"",
        ] {
            let out = Command::new("bash")
                .args(["--norc", "-c", &format!("{load}; complete -p writ")])
                .env("PATH", &path)
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("-F _writ writ"),
                "bash: {load}"
            );
        }
    } else {
        eprintln!("skipping bash: no interactive bash on PATH");
    }
    if has("fish", &["--version"]) {
        let out = Command::new("fish")
            .args([
                "--no-config",
                "-c",
                "writ completions fish | source; complete -C 'writ gr'",
            ])
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("grant"));
    } else {
        eprintln!("skipping fish: not installed");
    }
}
