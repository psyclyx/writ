//! End-to-end tests driving the `writ` binary.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("writ-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox { dir }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.join(p)
    }

    fn run_with(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_writ"))
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs writ with empty stdin; returns (status, stdout, stderr).
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = self.run_with(args, b"");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Runs writ and expects success; returns stdout.
    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "writ {args:?} failed:\n{err}");
        out
    }

    /// Runs writ and expects `code`; returns stderr.
    fn fails(&self, args: &[&str], code: i32) -> String {
        let (got, out, err) = self.run(args);
        assert_eq!(
            got, code,
            "writ {args:?}: expected exit {code}\nstdout: {out}\nstderr: {err}"
        );
        err
    }

    fn append(&self, file: &str, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(file))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.path(file)).unwrap()
    }

    fn init(&self, name: &str) -> String {
        self.ok(&[
            "init",
            name,
            "--next-out",
            &format!("{name}-next.key"),
            "-q",
        ])
        .trim()
        .to_owned()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_and_key_files() {
    let s = Sandbox::new("init");
    let (code, out, err) = s.run(&["init", "me", "--next-out", "me-next.key"]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim();
    assert!(id.starts_with("writ1") && id.len() == 63, "{id}");
    assert!(err.contains("created identity"));
    assert_eq!(s.ok(&["id", "me"]).trim(), id);
    for f in ["log.writ", "issued.writ", "next.writ", "current.key"] {
        assert!(s.path("me").join(f).exists(), "{f}");
    }
    #[cfg(unix)]
    {
        assert_eq!(mode(&s.path("me/current.key")), 0o600);
        assert_eq!(mode(&s.path("me-next.key")), 0o600);
    }
    assert!(s.read("me/current.key").starts_with("WRIT-SECRET-KEY-1"));

    // Never overwrite a key; never reuse a directory.
    let err = s.fails(&["init", "other", "--next-out", "me-next.key"], 2);
    assert!(err.contains("never overwrites"), "{err}");
    assert!(!s.path("other").exists());
    s.fails(&["init", "me", "--next-out", "x.key"], 2);
    // --next-out is required.
    let err = s.fails(&["init", "third"], 2);
    assert!(err.contains("--next-out"), "{err}");

    // Secrets to stdout: the id goes to stderr instead.
    let (code, out, err) = s.run(&["init", "piped", "--next-out", "-"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("WRIT-SECRET-KEY-1") && out.lines().count() == 1);
    assert!(err.contains("created identity writ1"));
}

#[test]
fn names_grants_revocation() {
    let s = Sandbox::new("grants");
    s.init("me");
    let alice = s.init("alice");
    s.append("b.writ", &s.ok(&["name", "-i", "me", "alice", &alice]));
    s.append(
        "b.writ",
        &s.ok(&["grant", "-i", "me", "me alice", "(ssh nas)"]),
    );
    let out = s.ok(&[
        "check",
        "--as",
        "me",
        &alice,
        "(ssh nas disk)",
        "--in",
        "b.writ",
    ]);
    assert!(out.starts_with("allowed:"), "{out}");
    assert!(out.contains("me's alice is"), "{out}");
    // Too broad a question.
    let err = s.fails(
        &["check", "--as", "me", &alice, "(ssh)", "--in", "b.writ"],
        1,
    );
    assert!(err.contains("only conveys (ssh nas)"), "{err}");
    // Quiet mode: status only.
    let (code, out, err) = s.run(&[
        "check", "-q", "--as", "me", "alice", "(ssh)", "--in", "b.writ",
    ]);
    assert_eq!((code, out.as_str(), err.as_str()), (1, "", ""));

    // Revoke by hash prefix.
    let grant = s.read("me/issued.writ");
    let issued_items = s.ok(&["show", "me/issued.writ"]);
    let hash = issued_items
        .lines()
        .find_map(|l| l.strip_prefix("grant "))
        .unwrap()
        .to_owned();
    assert!(!grant.is_empty());
    s.append("b.writ", &s.ok(&["revoke", "-i", "me", &hash[..10]]));
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            "alice",
            "(ssh nas)",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("revoked by"), "{err}");
    // --as DIR brings the identity's own issuance log, revocation included.
    s.fails(&["check", "--as", "me", "alice", "(ssh nas)"], 1);
    // Ambiguous or unknown targets are refused.
    s.fails(&["revoke", "-i", "me", "zz"], 2);
}

#[test]
fn delegation_through_names() {
    let s = Sandbox::new("names");
    s.init("me");
    let alice = s.init("alice");
    let bob = s.init("bob");
    s.append("b.writ", &s.ok(&["name", "-i", "me", "alice", "alice"]));
    s.append("b.writ", &s.ok(&["name", "-i", "alice", "laptop", "bob"]));
    s.append(
        "b.writ",
        &s.ok(&[
            "grant",
            "-i",
            "me",
            "me alice laptop",
            "(zuko)",
            "--delegate",
        ]),
    );
    s.append("b.writ", &s.ok(&["export", "-i", "alice"]));
    s.ok(&["check", "--as", "me", &bob, "(zuko home)", "--in", "b.writ"]);
    let out = s.ok(&["resolve", "--as", "me", "alice laptop", "--in", "b.writ"]);
    assert_eq!(out.trim(), bob);
    let out = s.ok(&[
        "resolve",
        "--as",
        "me",
        &format!("{alice} laptop"),
        "--in",
        "b.writ",
    ]);
    assert_eq!(out.trim(), bob);
    s.fails(&["resolve", "--as", "me", "nobody", "--in", "b.writ"], 1);
    // A name path is not a concrete subject.
    let err = s.fails(
        &[
            "check", "--as", "me", "me alice", "(zuko)", "--in", "b.writ",
        ],
        2,
    );
    assert!(err.contains("writ resolve"), "{err}");

    // The proof alone convinces, and is smaller than everything.
    let proof = s.ok(&["prove", "--as", "me", "bob", "(zuko x)", "--in", "b.writ"]);
    std::fs::write(s.path("proof.writ"), &proof).unwrap();
    let id_me = s.ok(&["id", "me"]);
    s.ok(&[
        "check",
        "--as",
        id_me.trim(),
        &bob,
        "(zuko x)",
        "--in",
        "proof.writ",
    ]);
    let shown = s.ok(&["show", "proof.writ"]);
    assert_eq!(
        shown.matches("\ninception").count() + usize::from(shown.starts_with("inception")),
        2
    );
}

#[test]
fn leaf_sign_verify() {
    let s = Sandbox::new("leaf");
    s.init("me");
    s.append(
        "b.writ",
        &s.ok(&[
            "leaf",
            "-i",
            "me",
            "(release)",
            "--out",
            "leaf.key",
            "--expires",
            "2h",
        ]),
    );
    #[cfg(unix)]
    assert_eq!(mode(&s.path("leaf.key")), 0o600);
    std::fs::write(s.path("data"), b"hello").unwrap();
    let sig = s.ok(&["sign", "--leaf", "leaf.key", "-c", "app/v1", "data"]);
    std::fs::write(s.path("data.sig"), &sig).unwrap();
    let out = s.ok(&[
        "verify",
        "--as",
        "me",
        "-t",
        "(release)",
        "-c",
        "app/v1",
        "data",
        "data.sig",
        "--in",
        "b.writ",
    ]);
    assert!(out.starts_with("good signature by leaf:"), "{out}");
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v2",
            "data",
            "data.sig",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("different context"), "{err}");
    std::fs::write(s.path("other"), b"hellO").unwrap();
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v1",
            "other",
            "data.sig",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("does not match the data"), "{err}");
    // After the grant expires.
    let later = s.ok(&["show", "b.writ"]);
    assert!(later.contains("expires"));
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v1",
            "data",
            "data.sig",
            "--in",
            "b.writ",
            "--at",
            "2099-01-01",
        ],
        1,
    );
    assert!(err.contains("expired"), "{err}");
    // Leaf limits.
    let err = s.fails(
        &[
            "leaf",
            "-i",
            "me",
            "()",
            "--out",
            "l2.key",
            "--expires",
            "25h",
        ],
        2,
    );
    assert!(err.contains("24 hours"), "{err}");
    let err = s.fails(&["leaf", "-i", "me", "()", "--out", "leaf.key"], 2);
    assert!(err.contains("never overwrites"), "{err}");
    // Renewal: grant to the leaf's public key again.
    let pubkey = s.ok(&["pubkey", "--leaf", "leaf.key"]);
    std::fs::write(s.path("leaf.pub"), pubkey).unwrap();
    let err = s.fails(&["grant", "-i", "me", "leaf.pub", "(release)"], 2);
    assert!(err.contains("--expires"), "{err}");
    s.ok(&[
        "grant",
        "-i",
        "me",
        "leaf.pub",
        "(release)",
        "--expires",
        "24h",
    ]);
    // Secret keys are not subjects.
    let err = s.fails(
        &[
            "grant",
            "-i",
            "me",
            "leaf.key",
            "(release)",
            "--expires",
            "1h",
        ],
        2,
    );
    assert!(err.contains("secret key"), "{err}");

    // Identity signatures, from stdin.
    let out = s.run_with(&["sign", "-i", "me", "-c", "app/v1"], b"hello");
    assert!(out.status.success());
    std::fs::write(s.path("me.sig"), &out.stdout).unwrap();
    s.ok(&[
        "verify", "--as", "me", "-t", "()", "-c", "app/v1", "data", "me.sig",
    ]);
}

#[test]
fn rotation_keeps_and_drops() {
    let s = Sandbox::new("rotate");
    s.init("me");
    let alice = s.init("alice");
    s.ok(&["grant", "-i", "me", &alice, "(kept)"]);
    s.ok(&["grant", "-i", "me", &alice, "(short)", "--expires", "1s"]);
    s.ok(&["leaf", "-i", "me", "(svc)", "--out", "leaf.key"]);
    std::fs::write(s.path("d"), b"x").unwrap();
    std::fs::write(s.path("d.sig"), s.ok(&["sign", "-i", "me", "-c", "c", "d"])).unwrap();
    std::fs::write(s.path("old.key"), s.read("me/current.key")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));

    // The current key can't rotate.
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me/current.key",
            "--next-out",
            "n2.key",
        ],
        2,
    );
    assert!(err.contains("current key, not the next"), "{err}");
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n2.key",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("kept 2 statements"), "{err}");
    assert!(
        err.contains("1 expired") && err.contains("1 leaf grants"),
        "{err}"
    );
    assert_eq!(s.read("me/current.key"), s.read("me-next.key"));
    // The old key is retired and refused.
    let err = s.fails(&["grant", "-i", "me", "--key", "old.key", &alice, "(x)"], 2);
    assert!(err.contains("retired"), "{err}");
    s.ok(&["grant", "-i", "me", &alice, "(fresh)"]);
    // Rotating again needs the new next key.
    s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me-next.key",
            "--next-out",
            "n3.key",
        ],
        2,
    );

    for (tag, code) in [("(kept)", 0), ("(fresh)", 0), ("(short)", 1)] {
        s.fails(&["check", "--as", "me", &alice, tag], code);
    }
    // The kept signature still verifies.
    s.ok(&["verify", "--as", "me", "-t", "()", "-c", "c", "d", "d.sig"]);
}

#[test]
fn age_style_composition() {
    let s = Sandbox::new("stdio");
    // Next key on stdout; current key elsewhere.
    let out = s.run_with(
        &["init", "me", "--next-out", "-", "--key-out", "cur.key"],
        b"",
    );
    assert!(out.status.success());
    let next_key = out.stdout.clone();
    assert!(!s.path("me/current.key").exists());
    // Keys from stdin and from /dev/stdin.
    let cur = std::fs::read(s.path("cur.key")).unwrap();
    let alice = s.init("alice");
    let out = s.run_with(&["grant", "-i", "me", "--key", "-", &alice, "(a)"], &cur);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = s.run_with(
        &["grant", "-i", "me", "--key", "/dev/stdin", &alice, "(b)"],
        &cur,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Without a key: a clear error.
    let err = s.fails(&["grant", "-i", "me", &alice, "(c)"], 2);
    assert!(err.contains("--key"), "{err}");
    // Rotate with the next key on stdin, new next key on stdout.
    let out = s.run_with(
        &["rotate", "-i", "me", "--next-key", "-", "--next-out", "-"],
        &next_key,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("WRIT-SECRET-KEY-1"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("now the current key"), "{err}");
    // The revealed key now signs.
    let out = s.run_with(
        &["grant", "-i", "me", "--key", "-", &alice, "(d)"],
        &next_key,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn k_of_n_and_friends() {
    let s = Sandbox::new("kofn");
    s.ok(&["keygen", "--out", "friend.key"]);
    std::fs::write(s.path("friend.pub"), s.ok(&["pubkey", "friend.key"])).unwrap();
    let (code, _, err) = s.run(&[
        "init",
        "me",
        "--next-out",
        "cold.keys",
        "--next-n",
        "2",
        "--next-k",
        "2",
        "--next-pub",
        "friend.pub",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("2 of 3"), "{err}");
    let cold = s.read("cold.keys");
    let mut lines = cold.lines();
    std::fs::write(s.path("cold1.key"), lines.next().unwrap()).unwrap();
    // One key is not enough.
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "cold1.key",
            "--next-out",
            "n.key",
        ],
        2,
    );
    assert!(err.contains("needs 2 of the 3"), "{err}");
    // One of mine plus the friend's.
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "cold1.key",
        "--next-key",
        "friend.key",
        "--next-out",
        "n.key",
    ]);
    assert_eq!(code, 0, "{err}");
    // A weak threshold is warned about.
    let (_, _, err) = s.run(&["init", "weak", "--next-out", "w.keys", "--next-n", "2"]);
    assert!(err.contains("warning"), "{err}");
}

#[test]
fn state_ratchet_and_equivocation() {
    let s = Sandbox::new("state");
    s.init("me");
    let alice = s.init("alice");
    std::fs::write(
        s.path("trust.writ"),
        s.ok(&["grant", "-i", "me", &alice, "()", "--delegate"]),
    )
    .unwrap();
    let bob = s.init("bob");
    // A thief copies alice, warm key included; then alice rotates.
    copy_dir(&s.path("alice"), &s.path("alice-twin"));
    s.ok(&[
        "rotate",
        "-i",
        "alice",
        "--next-key",
        "alice-next.key",
        "--next-out",
        "a2.key",
        "-q",
    ]);
    std::fs::write(s.path("fresh.writ"), s.ok(&["export", "-i", "alice"])).unwrap();
    // The thief signs with the old key, and withholds the rotation.
    s.ok(&["grant", "-i", "alice-twin", &bob, "(y)"]);
    std::fs::write(s.path("stale.writ"), s.ok(&["export", "-i", "alice-twin"])).unwrap();

    // Without state, a stale bundle is believed.
    s.ok(&[
        "check",
        "--as",
        "me",
        &bob,
        "(y)",
        "--in",
        "trust.writ",
        "--in",
        "stale.writ",
    ]);
    // A verifier that has seen the rotation remembers it.
    s.ok(&[
        "check",
        "--as",
        "me",
        &alice,
        "()",
        "--in",
        "trust.writ",
        "--in",
        "fresh.writ",
        "--state",
        "st",
    ]);
    assert!(s.path("st/floor").exists());
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &bob,
            "(y)",
            "--in",
            "trust.writ",
            "--in",
            "stale.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("not kept"), "{err}");

    // The twin rotates differently with the same next key: equivocation.
    s.ok(&[
        "rotate",
        "-i",
        "alice-twin",
        "--next-key",
        "alice-next.key",
        "--next-out",
        "t2.key",
        "-q",
    ]);
    std::fs::write(s.path("twin.writ"), s.ok(&["export", "-i", "alice-twin"])).unwrap();
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &bob,
            "(y)",
            "--in",
            "trust.writ",
            "--in",
            "twin.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("equivocated"), "{err}");
    // Once seen, it stays seen.
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &alice,
            "()",
            "--in",
            "trust.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("equivocated"), "{err}");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

#[test]
fn ssh_keys_and_max_validity() {
    let s = Sandbox::new("ssh");
    let (code, _, err) = s.run(&["init", "me", "--next-out", "n.key", "--max-validity", "30d"]);
    assert_eq!(code, 0, "{err}");
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[7u8; 32]);
    let line = format!("ssh-ed25519 {} laptop", base64(&blob));
    let (code, _, err) = s.run(&["grant", "-i", "me", &line, "(ssh nas)"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("requires an expiry"), "{err}");
    let err = s.fails(
        &["grant", "-i", "me", &line, "(ssh nas)", "--expires", "60d"],
        2,
    );
    assert!(err.contains("within 30d"), "{err}");
    let err = s.fails(
        &[
            "grant",
            "-i",
            "me",
            &line,
            "(ssh)",
            "--delegate",
            "--expires",
            "1d",
        ],
        2,
    );
    assert!(err.contains("can't delegate"), "{err}");
    std::fs::write(s.path("id_ed25519.pub"), format!("{line}\n")).unwrap();
    let out = s.ok(&["check", "--as", "me", "id_ed25519.pub", "(ssh nas)"]);
    assert!(out.contains("ssh-ed25519"), "{out}");
    s.fails(&["check", "--as", "me", &line, "(ssh other)"], 1);
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            s.push(if i <= c.len() {
                A[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    s
}

#[test]
fn usage_and_help() {
    let s = Sandbox::new("usage");
    let (code, out, _) = s.run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Questions"));
    let (code, out, _) = s.run(&["grant", "--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("--delegate") && out.contains("Usage: writ grant"));
    let err = s.fails(&["gran"], 2);
    assert!(err.contains("did you mean `grant`"), "{err}");
    let err = s.fails(&["grant", "-i", "me"], 2);
    assert!(err.contains("missing SUBJECT TAG"), "{err}");
    let err = s.fails(&["check", "x", "()"], 2);
    assert!(err.contains("--as"), "{err}");
    let err = s.fails(&["grant", "--bogus"], 2);
    assert!(err.contains("unknown option --bogus"), "{err}");
    let (code, out, _) = s.run(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("writ "));
    let err = s.fails(&["show", "nonexistent"], 2);
    assert!(err.contains("nonexistent"), "{err}");
    std::fs::write(
        s.path("junk"),
        "-----BEGIN WRIT-----\nnope\n-----END WRIT-----\n",
    )
    .unwrap();
    let err = s.fails(&["show", "junk"], 2);
    assert!(err.contains("junk"), "{err}");
}
